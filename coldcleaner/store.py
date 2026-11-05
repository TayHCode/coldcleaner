import csv
import fcntl
import os
import re
import shlex
import subprocess
import tarfile
import tempfile
import uuid
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field, fields, replace
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from . import hosts


@dataclass(frozen=True)
class Record:
    id: str
    archived_at: str
    host: str
    source_path: str
    archive_path: str
    original_bytes: int
    archive_bytes: int
    file_count: int
    status: str
    matches: tuple[str, ...] = field(default=(), compare=False)


_COLUMNS = [item.name for item in fields(Record) if item.name != "matches"]


def _configured(name):
    if name not in hosts.HOSTS:
        raise LookupError(f"archive host {name!r} is not configured; add [hosts.{name}] with its kind and ssh "
                          "to the rules file to restore it, or recover a legacy archive with --to-host HOST --to PATH")
    return hosts.HOSTS[name]


def _host(host):
    host = _configured(host) if isinstance(host, str) else host
    if host.kind == "powershell":
        raise ValueError("cold storage requires a posix or WSL host; PowerShell is unsupported")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", host.name):
        raise ValueError("host name must be filesystem-safe")
    return host


def _source(path):
    path = PurePosixPath(path)
    if not path.is_absolute() or path == PurePosixPath("/") or ".." in path.parts:
        raise ValueError("source must be an absolute non-root path without '..'")
    return path


@contextmanager
def _index_lock(root):
    root.mkdir(parents=True, exist_ok=True)
    with (root / ".index.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def _read_index(root):
    index = root / "INDEX.csv"
    if not index.exists():
        return []
    with index.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != _COLUMNS:
            raise ValueError("unexpected INDEX.csv columns")
        records = []
        for row in reader:
            for key in ("original_bytes", "archive_bytes", "file_count"):
                row[key] = int(row[key])
            if row["status"] not in {"stored", "expired", "restored"}:
                raise ValueError("unexpected archive status")
            records.append(Record(**row))
        return records


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_index(root, records):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", newline="", encoding="utf-8",
                                         dir=root, prefix=".index-", delete=False) as stream:
            temporary = Path(stream.name)
            writer = csv.writer(stream)
            writer.writerow(_COLUMNS)
            writer.writerows([getattr(record, key) for key in _COLUMNS] for record in records)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, root / "INDEX.csv")
        _sync_directory(root)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _pipe(producer, consumer):
    processes = []
    with tempfile.TemporaryFile() as errors:
        try:
            first = producer(errors)
            processes.append(first)
            second = consumer(first.stdout, errors)
            processes.append(second)
            first.stdout.close()
            codes = [process.wait() for process in reversed(processes)]
            if any(codes):
                errors.seek(0)
                raise RuntimeError("archive stream failed: " + errors.read().decode(errors="replace"))
        finally:
            for process in processes:
                if process.stdout is not None:
                    process.stdout.close()
                if process.poll() is None:
                    process.terminate()
                process.wait()


def _measure(host, path):
    quoted = shlex.quote(str(path))
    script = (f"set -euo pipefail; {{ test -d {quoted} || test -f {quoted}; }}; test ! -L {quoted}; "
              f"du -sk {quoted}; "
              f"find {quoted} -exec sh -c 'for p do printf x; done' sh {{}} + | wc -c")
    lines = hosts.run(host, script).stdout.decode().splitlines()
    return int(lines[0].split()[0]) * 1024, int(lines[-1].strip())


def compression_level(host, path, extensions):
    host = _host(host)
    path = _source(path)
    extensions = {extension.lower().lstrip(".") for extension in extensions}
    script = (f"find {shlex.quote(str(path))} -type f -exec sh -c "
              + shlex.quote('for p do n=$(wc -c < "$p") || exit; printf "%s\\t%s\\0" "$n" "$p"; done')
              + " sh {} +")
    entries = hosts.run(host, script).stdout.split(b"\0")
    total = compressed = 0
    for entry in filter(None, entries):
        size, name = entry.split(b"\t", 1)
        size = int(size)
        total += size
        filename = os.fsdecode(name).lower()
        if any(filename.endswith("." + extension) for extension in extensions):
            compressed += size
            if filename == str(path).lower():
                return 1
    return 1 if total and compressed > total / 2 else 10


def _listing(archive_path, manifest):
    with manifest.open("xb") as output:
        _pipe(lambda errors: subprocess.Popen(["zstd", "-dc", "--", str(archive_path)],
                                              stdout=subprocess.PIPE, stderr=errors),
              lambda source, errors: subprocess.Popen(["tar", "-tf", "-"], stdin=source,
                                                      stdout=output, stderr=errors))
        output.flush()
        os.fsync(output.fileno())
    return manifest.read_text(encoding="utf-8").splitlines()


def _reserve(root, host, path, date):
    directory = root / host.name / date
    directory.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(path).strip("/"))[:160].strip(".-") or "archive"
    suffix = 1
    while True:
        name = slug if suffix == 1 else f"{slug}-{suffix}"
        final = directory / (name + ".tar.zst")
        partial = directory / (name + ".tar.zst.partial")
        manifest = directory / (name + ".files.txt")
        if not final.exists() and not manifest.exists():
            try:
                fd = os.open(partial, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                return final, partial, manifest, fd
            except FileExistsError:
                pass
        suffix += 1


def archive(host, path, *, apply=False, nas_root, level=None):
    host = _host(host)
    path = _source(path)
    level = 10 if level is None else level
    if type(level) is not int or not 1 <= level <= 19:
        raise ValueError("compression level must be an integer from 1 to 19")
    original_bytes, file_count = _measure(host, path)
    now = datetime.now(timezone.utc)
    root = Path(nas_root).absolute()
    record = Record(uuid.uuid4().hex[:12], now.isoformat(), host.name, str(path), "",
                    original_bytes, 0, file_count, "stored")
    if not apply:
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(path).strip("/"))[:160].strip(".-") or "archive"
        destination = root / host.name / now.date().isoformat() / (slug + ".tar.zst")
        return replace(record, archive_path=str(destination))
    with _index_lock(root):
        final, partial, manifest, fd = _reserve(root, host, path, now.date().isoformat())
    indexed = False
    marker = None
    try:
        with os.fdopen(fd, "wb") as output:
            marker = hosts.run(host, "mktemp " + shlex.quote(str(path.parent / ".coldcleaner-archive.XXXXXXXX"))).stdout.decode().strip()
            if not marker:
                raise RuntimeError("archive marker creation failed")
            script = f"tar -C {shlex.quote(str(path.parent))} -cf - -- {shlex.quote(path.name)}"
            _pipe(lambda errors: hosts.popen(host, script, stdout=subprocess.PIPE, stderr=errors),
                  lambda source, errors: subprocess.Popen(["zstd", "-T0", f"-{level}"],
                                                          stdin=source, stdout=output, stderr=errors))
            output.flush()
            os.fsync(output.fileno())
        members = _listing(partial, manifest)
        if len(members) != file_count or _measure(host, path) != (original_bytes, file_count):
            raise RuntimeError("archive verification failed: source size or file count changed")
        record = replace(record, archive_path=str(final), archive_bytes=partial.stat().st_size)
        with _index_lock(root):
            records = _read_index(root)
            while any(item.id == record.id for item in records):
                record = replace(record, id=uuid.uuid4().hex[:12])
            os.replace(partial, final)
            _sync_directory(final.parent)
            _write_index(root, records + [record])
            indexed = True
            quoted = shlex.quote(str(path))
            script = (f"set -eu; test -f {shlex.quote(marker)} || exit 75; "
                      f"changed=$(find {quoted} -cnewer {shlex.quote(marker)} -print) || exit 75; "
                      f'test -z "$changed" || exit 75; '
                      f"rm -rf -- {quoted}; test ! -e {quoted}; test ! -L {quoted}")
            try:
                hosts.run(host, script)
            except subprocess.CalledProcessError as error:
                if error.returncode == 75:
                    _write_index(root, records)
                    indexed = False
                    raise RuntimeError("archive verification failed: source changed or marker check failed") from error
                raise
        return record
    finally:
        if marker:
            hosts.run(host, "rm -f -- " + shlex.quote(marker), check=False)
        partial.unlink(missing_ok=True)
        if not indexed and not any(item.id == record.id for item in _read_index(root)):
            final.unlink(missing_ok=True)
            manifest.unlink(missing_ok=True)


def _archive_path(root, record):
    path = Path(record.archive_path)
    if not path.is_absolute():
        path = root / path
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("archive path escapes NAS root")
    return path


def _manifest_path(path):
    return path.with_name(path.name.removesuffix(".tar.zst") + ".files.txt")


def find(term, nas_root):
    root = Path(nas_root)
    if not root.exists():
        return []
    term = term.casefold()
    with _index_lock(root):
        found = []
        for record in _read_index(root):
            manifest = _manifest_path(_archive_path(root, record))
            members = manifest.read_text(encoding="utf-8").splitlines() if manifest.exists() else []
            matches = tuple(member for member in members if term in member.casefold())
            if matches or term in record.source_path.casefold() or term in record.archive_path.casefold():
                found.append(replace(record, matches=matches))
        return found


def restore(id, nas_root, *, to=None, member=None, to_host=None):
    root = Path(nas_root)
    if not root.exists():
        raise LookupError(f"no archive with id {id!r}")
    with _index_lock(root):
        records = _read_index(root)
        record = next((item for item in records if item.id == id), None)
        if record is None:
            raise LookupError(f"no archive with id {id!r}")
        if record.status == "expired":
            raise ValueError("archive has expired")
        archive_path = _archive_path(root, record)
        if to_host is not None and to is None:
            raise ValueError('cross-host recovery requires an explicit destination path')
        if archive_path.with_suffix('.sha256.json').exists():
            if to_host is not None:
                raise ValueError('cross-host recovery is only supported for legacy archives')
            from . import reclaim
            host = _configured(record.host)
            reclaim.restore_archive(host, record, archive_path, to=to, member=member)
            records = [replace(item, status='restored') if item.id == id else item for item in records]
            _write_index(root, records)
            return replace(record, status='restored')
        host = _host(to_host if to_host is not None else record.host)
        if to_host is not None and host.kind != 'posix':
            raise ValueError('recovery host must be POSIX')
        original = _source(record.source_path)
        target = _source(to if to is not None else record.source_path)
        archive_path = _archive_path(root, record)
        dependencies = set()
        if member is not None:
            member_path = PurePosixPath(member)
            if member_path.is_absolute() or ".." in member_path.parts or member_path.parts[:1] != (original.name,):
                raise ValueError("member must be a path within the archived folder")
            members = _manifest_path(archive_path).read_text(encoding="utf-8").splitlines()
            if member.rstrip("/") not in {name.rstrip("/") for name in members}:
                raise ValueError("member is not in the archive")
            selected = member.rstrip("/")
            with tarfile.open(archive_path, "r:zst") as archive:
                entries = {item.name.rstrip("/"): item for item in archive}
            pending = [item for name, item in entries.items()
                       if name == selected or name.startswith(selected + "/")]
            while pending:
                item = pending.pop()
                if item.islnk():
                    linked = item.linkname.rstrip("/")
                    link_path = PurePosixPath(linked)
                    if link_path.is_absolute() or ".." in link_path.parts or link_path.parts[:1] != (original.name,):
                        raise ValueError("hardlink target must be within the archived folder")
                    if linked != selected and not linked.startswith(selected + "/") and linked not in dependencies:
                        dependencies.add(linked)
                        pending.append(entries[linked])
        quoted = shlex.quote(str(target))
        parent = shlex.quote(str(target.parent))
        setup = (f"set -eu; if test -e {quoted} || test -L {quoted}; then exit 73; fi; "
                 f"mkdir -p {parent}; mktemp -d {shlex.quote(str(target.parent / '.coldcleaner-restore.XXXXXXXX'))}")
        try:
            staging = hosts.run(host, setup).stdout.decode().strip()
        except subprocess.CalledProcessError as error:
            if error.returncode == 73:
                raise FileExistsError(f"restore destination already exists: {target}") from error
            raise
        try:
            extraction = PurePosixPath(staging) / "archive" if dependencies else PurePosixPath(staging)
            command = f"tar -C {shlex.quote(str(extraction))} -xpf -"
            if dependencies:
                command = f"mkdir -p {shlex.quote(str(extraction))} && " + command
            if member is not None:
                command += " -- " + " ".join(shlex.quote(name) for name in [member, *sorted(dependencies)])
            _pipe(lambda errors: subprocess.Popen(["zstd", "-dc", "--", str(archive_path)],
                                                  stdout=subprocess.PIPE, stderr=errors),
                  lambda source, errors: hosts.popen(host, command, stdin=source, stderr=errors))
            published = PurePosixPath(staging)
            if dependencies:
                published /= "selected"
                destination = published / member_path
                hosts.run(host, f"set -e; mkdir -p {shlex.quote(str(destination.parent))}; "
                          f"mv -- {shlex.quote(str(extraction / member_path))} {shlex.quote(str(destination))}")
            staged = shlex.quote(str(published / original.name))
            if target.name != original.name:
                renamed = shlex.quote(str(published / target.name))
                hosts.run(host, f"mv -- {staged} {renamed}")
                staged = renamed
            publish = (f"set -euo pipefail; test ! -e {quoted}; test ! -L {quoted}; "
                       f"mv -n -- {staged} {parent}/; test ! -e {staged}; test ! -L {staged}")
            hosts.run(host, publish)
            records = [replace(item, status="restored") if item.id == id else item for item in records]
            _write_index(root, records)
        finally:
            hosts.run(host, f"rm -rf -- {shlex.quote(staging)}")
    return replace(record, host=host.name, status="restored")


def enforce_cap(nas_root, cap_bytes, *, apply=False):
    if type(cap_bytes) is not int or cap_bytes < 0:
        raise ValueError("cap_bytes must be a nonnegative integer")
    root = Path(nas_root)
    if not root.exists():
        return []
    with _index_lock(root) if apply else nullcontext():
        records = _read_index(root)
        candidates = [item for item in records if item.status != "expired"]
        total = sum(item.archive_bytes for item in candidates)
        expired = []
        for record in sorted(candidates, key=lambda item: item.archived_at):
            if total <= cap_bytes:
                break
            if _archive_path(root, record).with_suffix('.sha256.json').exists():
                continue
            _archive_path(root, record)
            expired.append(replace(record, status="expired"))
            total -= record.archive_bytes
        if apply:
            if expired:
                ids = {item.id for item in expired}
                records = [replace(item, status="expired") if item.id in ids else item for item in records]
                _write_index(root, records)
            for record in records:
                if record.status == "expired":
                    archive_path = _archive_path(root, record)
                    if archive_path.with_suffix('.sha256.json').exists():
                        continue
                    archive_path.unlink(missing_ok=True)
                    _manifest_path(archive_path).unlink(missing_ok=True)
        return expired
