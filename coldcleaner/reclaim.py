"""Reclaim configured agent data; package caches are out of scope."""
import contextlib
import fcntl
import gzip
import hashlib
import json
import ntpath
import os
from pathlib import Path, PurePosixPath
import random
import re
import shlex
import subprocess
import tarfile
import tempfile
import time
import shutil
from datetime import datetime, timezone
from urllib.parse import urlsplit
import uuid

from . import hosts, protect, reclaim_probe, rules, store, version


SOURCE = Path(reclaim_probe.__file__).read_text() + '''
try:
    request = json.loads(sys.stdin.buffer.readline())
    response = main(request)
    if request['operation'] not in ('tar', 'bundle'):
        print(json.dumps(response))
except Exception as error:
    print(str(error), file=sys.stderr)
    raise SystemExit(3 if isinstance(error, ValueError) else 1)
'''


def probe(host, operation, timeout=900, **request):
    try:
        result = hosts.python_run(host, SOURCE, dict(operation=operation, **request), timeout=timeout)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as exc:
        reason = exc.stderr.decode(errors='replace').strip() or 'host probe failed'
        raise (ValueError if exc.returncode == 3 else RuntimeError)(reason) from None


BATCH = 50
WORKTREE_MERGED_DAYS = 1
LIMIT_REACHED = 'deletion limit reached'
RUN_SECONDS = 5 * 3600
DEADLINE = 'run deadline reached'
APPROVALS = 'approvals.json'
APPROVAL_NEEDED = 'APPROVAL NEEDED: approve it from a reclaim dry-run plan with coldcleaner approve'
APPROVAL_STALE = reclaim_probe.APPROVAL_STALE
APPROVAL_WINDOWS = 'APPROVAL UNAVAILABLE: Windows reports no file change time, so an approved item cannot be proven unchanged'
ITEM_ID = re.compile(r'[0-9a-f]{16}')
PLAN_KEYS = {'id', 'host', 'tier', 'path', 'bytes', 'approval', 'rule', 'reason'}
SIZE_SECONDS = 30
UNLISTED_SECONDS = 120
UNLISTED_ROWS = 20
HINTS = (
    ('agent transcripts', re.compile(r'^\.?(claude|codex|t3|cursor|gemini|aider|opencode)$|transcript|session')),
    ('benchmark output', re.compile(r'bench|perf|profil|results?$|runs$|outputs?$')),
    ('looks like scratch', re.compile(r'scratch|^\.?te?mp\b|tmp$|spike|playground|sandbox|^\.?trash')),
)


class DeadlineReached(Exception):
    pass


def describe(exc):
    if isinstance(exc, subprocess.CalledProcessError):
        detail = (exc.stderr or b'').decode(errors='replace').strip()
        return '\n'.join(detail.splitlines()[:3])[:1000] or f'command exited with status {exc.returncode}'
    return str(exc)


def hint(path):
    name = re.split(r'[\\/]', path.rstrip('\\/'))[-1].casefold()
    return next((label for label, pattern in HINTS if pattern.search(name)), '')


def github_url(url):
    if re.fullmatch(r'git@github\.com:[^\s]+', url):
        return True
    parsed = urlsplit(url)
    return parsed.scheme in {'https', 'ssh', 'git'} and parsed.hostname == 'github.com'


def repository(url):
    if not github_url(url):
        raise ValueError('origin must be GitHub')
    value = url.split(':', 1)[1] if url.startswith('git@github.com:') else urlsplit(url).path.lstrip('/')
    value = value.removesuffix('.git')
    if not re.fullmatch(r'[\w.-]+/[\w.-]+', value):
        raise ValueError('invalid GitHub repository')
    return value


def pull_requests(repo, branch, head=None, head_repository=None):
    head_repository = head_repository or repo
    owner, name = repo.split('/')
    query = '''query($owner:String!,$name:String!,$branch:String!,$cursor:String){
      repository(owner:$owner,name:$name){parent{nameWithOwner} pullRequests(headRefName:$branch,first:100,after:$cursor){
        nodes{state headRefOid url headRepository{nameWithOwner}} pageInfo{hasNextPage endCursor}}}}'''
    if not branch:
        query = '''query($owner:String!,$name:String!,$branch:String!,$cursor:String){
          repository(owner:$owner,name:$name){parent{nameWithOwner} object(expression:$branch){... on Commit{
            associatedPullRequests(first:100,after:$cursor){nodes{state headRefOid url headRepository{nameWithOwner}}
              pageInfo{hasNextPage endCursor}}}}}}'''
    rows = []; cursor = None
    while True:
        args = ['gh', 'api', 'graphql', '-f', 'query=' + query, '-f', 'owner=' + owner,
                '-f', 'name=' + name, '-f', 'branch=' + (branch or head)]
        if cursor:
            args += ['-f', 'cursor=' + cursor]
        try:
            result = hosts.run(hosts.LOCAL, shlex.join(args), timeout=180)
        except subprocess.CalledProcessError as exc:
            if missing_repository(exc.stdout):
                raise ValueError('UNIQUE: GitHub repository not found: ' + repo) from None
            raise
        response = json.loads(result.stdout)
        if response.get('errors'):
            raise RuntimeError('GitHub PR inventory incomplete')
        root = response['data']['repository']
        parent = (root['parent'] or {}).get('nameWithOwner')
        if not branch and root['object'] is None:
            break
        page = root['pullRequests'] if branch else root['object']['associatedPullRequests']
        rows.extend(row for row in page['nodes'] if
                    (row['headRepository'] or {}).get('nameWithOwner', '').casefold() == head_repository.casefold())
        if not page['pageInfo']['hasNextPage']:
            break
        cursor = page['pageInfo']['endCursor']
    return rows + pull_requests(parent, branch, head, head_repository) if parent else rows


def missing_repository(stdout):
    try:
        errors = json.loads(stdout or b'{}').get('errors') or []
    except ValueError:
        return False
    return bool(errors) and all(error.get('type') == 'NOT_FOUND' and error.get('path') == ['repository'] for error in errors)


def completion(state, prs):
    if state['dirty'] or state['stashes']:
        return 'IN USE: uncommitted work or stashes'
    if any(row['state'] == 'OPEN' for row in prs):
        return 'IN USE: open pull request'
    if not state['published']:
        return 'UNIQUE: unpushed commits or incomplete origin proof'
    if not state['merged'] and not any(row['state'] in ('CLOSED', 'MERGED') and
                                      row['headRefOid'] == state['head'] for row in prs):
        return 'IN USE: work is neither merged nor closed at this head'
    return ''


def git_state(host, path):
    context = probe(host, 'context', path=path)
    module = ntpath if host.kind == 'powershell' else os.path
    if context is None or module.normcase(module.normpath(context)) != module.normcase(module.normpath(path)):
        return None
    state = probe(host, 'repo', path=path)
    return state if state['worktree'] else None


def check_bundle(destination, head, reflog=()):
    with tempfile.TemporaryDirectory(prefix='coldcleaner-verify-') as verifier:
        subprocess.run(['git', 'init', '--bare', '--object-format=' + reclaim_probe.object_format(head), verifier], check=True, capture_output=True)
        subprocess.run(['git', '-C', verifier, 'bundle', 'verify', str(destination)], check=True, capture_output=True)
    heads = subprocess.run(['git', 'bundle', 'list-heads', str(destination)], check=True, capture_output=True, text=True).stdout.strip()
    if heads.splitlines() != [head + ' HEAD', *(c + ' ' + reclaim_probe.reflog_ref(c) for c in reflog)]:
        raise ValueError('Git recovery bundle head differs')


def preserve_git(host, path, directory, state):
    destination = directory / 'head.bundle'
    with tempfile.TemporaryFile() as errors:
        process = hosts.python_stream(host, SOURCE, dict(operation='bundle', path=path, reflog=state['reflog']), stderr=errors)
        try:
            metadata = json.loads(process.stdout.readline())
            digest = hashlib.sha256()
            with destination.open('xb') as output:
                for chunk in iter(lambda: process.stdout.read(1024 * 1024), b''):
                    output.write(chunk); digest.update(chunk)
                output.flush(); os.fsync(output.fileno())
            if process.wait() or digest.hexdigest() != metadata['sha256']:
                raise RuntimeError('Git recovery bundle transfer failed')
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate(); process.wait()
    destination.chmod(0o600)
    check_bundle(destination, state['head'], state['reflog'])
    return dict(head=state['head'], branch=state['branch'], remote=state['remote'], reflog=state['reflog'], **metadata)


def read_archive(archive_path):
    found = {}
    with tempfile.TemporaryFile() as errors:
        decompressor = subprocess.Popen(['zstd', '-dc', '--', str(archive_path)], stdout=subprocess.PIPE, stderr=errors)
        try:
            with tarfile.open(fileobj=decompressor.stdout, mode='r|') as archive:
                for member in archive:
                    if member.name in found or not (member.isdir() or member.isfile()):
                        raise ValueError('unexpected archive member')
                    found[member.name.rstrip('/')] = (reclaim_probe.sha256_hex(archive.extractfile(member))
                                                      if member.isfile() else None)
            if decompressor.wait():
                raise RuntimeError('NAS archive test-read failed')
        except tarfile.TarError as exc:
            raise RuntimeError('NAS archive test-read failed') from exc
        finally:
            decompressor.stdout.close()
            if decompressor.poll() is None:
                decompressor.terminate(); decompressor.wait()
    return found


ATTEMPT = 'attempt.creating'
PENDING = '.attempts'


def retire_attempts(root, records):
    pending = root / PENDING
    entries = list(pending.iterdir()) if pending.is_dir() else []
    if not entries:
        return
    indexed = {store._archive_path(root, record).parent.resolve() for record in records}
    for entry in entries:
        parts = entry.name.split('+')
        if (len(parts) != 3 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', parts[0])
                or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', parts[1]) or not re.fullmatch(r'[0-9a-f]{32}', parts[2])):
            raise RuntimeError(f'unexpected NAS attempt entry {entry}')
        directory = root.joinpath(*parts)
        marker = directory / ATTEMPT
        if directory.resolve() not in indexed and marker.is_file():
            for item in directory.iterdir():
                if item != marker:
                    item.unlink()
            marker.unlink()
            directory.rmdir()
        entry.unlink()


def git_identity(git):
    return git and (git['head'], git['branch'], git['remote'], tuple(git.get('reflog') or ()))


def stored_copy(host, path, root, records, initial, git):
    for record in reversed(records):
        if record.status != 'stored' or record.host != host.name or record.source_path != path:
            continue
        final = store._archive_path(root, record)
        receipt = final.with_suffix('.sha256.json')
        if not receipt.is_file() or not final.is_file() or final.stat().st_size != record.archive_bytes:
            continue
        try:
            saved = json.loads(receipt.read_text())
            same = (saved.get('host'), saved.get('source'), saved.get('distro'), saved['manifest'], saved.get('security'),
                    git_identity(saved.get('git'))) == \
                (host.name, path, host.distro, initial['manifest'], initial['security'], git_identity(git))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise RuntimeError(f'unreadable archive receipt {receipt}') from exc
        if not same:
            continue
        if git:
            bundle = final.parent / 'head.bundle'
            with bundle.open('rb') as stream:
                if reclaim_probe.sha256_hex(stream) != saved['git'].get('sha256'):
                    raise RuntimeError('Git recovery bundle SHA-256 mismatch')
            check_bundle(bundle, git['head'], git['reflog'])
        found = read_archive(final)
        if found != initial['manifest']:
            raise RuntimeError('NAS contents differ from source SHA-256 manifest')
        listing = store._manifest_path(final)
        names = ''.join(name + '\n' for name in found)
        if not listing.is_file() or listing.read_text() != names:
            listing.write_text(names)
            listing.chmod(0o600)
        return record
    return None


def copy(host, path, root, records, initial, git):
    if shutil.disk_usage(root).free < 2 * initial['logical_bytes'] + len(initial['manifest']) * 1024:
        raise ValueError('NAS has insufficient free space for a complete verified copy')
    ident = uuid.uuid4().hex
    day = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    directory = root / host.name / day / ident
    pending = root / PENDING / '+'.join((host.name, day, ident))
    pending.parent.mkdir(parents=True, exist_ok=True)
    store._sync_directory(root)
    pending.touch()
    store._sync_directory(pending.parent)
    directory.mkdir(parents=True, mode=0o700)
    (directory / ATTEMPT).touch()
    store._sync_directory(directory)
    git_recovery = git and preserve_git(host, path, directory, git)
    final = directory / (ident + '.tar.zst')
    partial = final.with_suffix('.partial')
    receipt = final.with_suffix('.sha256.json')
    manifest_path = store._manifest_path(final)
    store._pipe(lambda errors: hosts.python_stream(host, SOURCE, dict(operation='tar', path=path), stderr=errors),
                lambda source, errors: subprocess.Popen(['zstd', '-T2', '-3', '-o', str(partial)], stdin=source, stderr=errors))
    found = read_archive(partial)
    if found != initial['manifest']:
        raise RuntimeError('NAS contents differ from source SHA-256 manifest')
    with partial.open('rb') as stream:
        os.fsync(stream.fileno())
    os.rename(partial, final)
    final.chmod(0o600)
    receipt.write_text(json.dumps(dict(host=host.name, distro=host.distro, source=path,
                                      manifest=found, security=initial['security'], git=git_recovery), sort_keys=True))
    manifest_path.write_text(''.join(name + '\n' for name in found))
    for path_to_sync in (receipt, manifest_path):
        path_to_sync.chmod(0o600)
        with path_to_sync.open('rb') as stream:
            os.fsync(stream.fileno())
    store._sync_directory(directory)
    record = store.Record(ident, datetime.now(timezone.utc).isoformat(), host.name, path,
                          str(final), initial['bytes'], final.stat().st_size,
                          len(found), 'stored')
    store._write_index(root, [*records, record])
    (directory / ATTEMPT).unlink()
    pending.unlink()
    return record


def preserve(host, path, root, before_remove, reflog=()):
    initial = probe(host, 'manifest', path=path)
    root = Path(root)
    with store._index_lock(root):
        records = store._read_index(root)
        retire_attempts(root, records)
        git = git_state(host, path)
        if reflog and not git:
            raise ValueError('reflog history needs a Git worktree to bundle')
        if git:
            git['reflog'] = list(reflog)
        record = stored_copy(host, path, root, records, initial, git) or copy(host, path, root, records, initial, git)
    before_remove()
    final = store._archive_path(root, record)
    if not final.is_file() or final.stat().st_size != record.archive_bytes:
        raise ValueError('verified archive is no longer present')
    current = probe(host, 'manifest', path=path)
    if current['manifest'] != initial['manifest'] or current['security'] != initial['security']:
        raise ValueError('source changed after verified NAS copy')
    return record, initial['manifest'], initial['security']


def send_restore(host, request, path, compressed, workdir):
    with tempfile.NamedTemporaryFile(dir=workdir, prefix='.restore-', mode='wb') as header:
        header.write(hosts.python_payload(SOURCE, request)); header.flush()
        source = 'import os,sys;from pathlib import Path;sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes());sys.stdout.buffer.flush();args=["zstd","-dc","--",sys.argv[2]] if sys.argv[3]=="True" else ["cat","--",sys.argv[2]];os.execvp(args[0],args)'
        store._pipe(lambda errors: subprocess.Popen(['python3', '-c', source, header.name, str(path), str(compressed)],
                                                   stdout=subprocess.PIPE, stderr=errors),
                    lambda source, errors: hosts.python_sink(host, stdin=source, stderr=errors))


def restore_archive(host, record, archive_path, *, to=None, member=None):
    saved = json.loads(archive_path.with_suffix('.sha256.json').read_text())
    if saved['host'] != host.name or saved['source'] != record.source_path:
        raise ValueError('archive receipt identity mismatch')
    if saved.get('distro'):
        host = hosts.Host(host.name, 'wsl-maintenance', host.ssh, saved['distro'])
    request = dict(operation='restore', path=to if to is not None else record.source_path,
                   manifest=saved['manifest'], security=saved.get('security', {}), member=member)
    def transfer(request, path, compressed):
        send_restore(host, request, path, compressed, archive_path.parent)
    recovery = saved.get('git') if member is None else None
    if recovery and not (archive_path.parent / 'head.bundle').is_file():
        raise ValueError('Git recovery bundle is missing')
    if recovery:
        destination = request['path']
        staging = probe(host, 'restore-stage', path=destination)
        module = ntpath if host.kind == 'powershell' else os.path
        request['path'] = module.join(staging, 'tree')
        try:
            transfer(request, archive_path, True)
            transfer(dict(operation='restore-git', path=request['path'], **recovery), archive_path.parent / 'head.bundle', False)
            probe(host, 'restore-publish', path=request['path'], to=destination)
        finally:
            probe(host, 'restore-cleanup', path=staging)
    else:
        transfer(request, archive_path, True)


DRILL_LOG = 'restore-drill.jsonl'


def extracted_bytes(archive_path):
    with tempfile.TemporaryFile() as errors:
        decompressor = subprocess.Popen(['zstd', '-dc', '--', str(archive_path)], stdout=subprocess.PIPE, stderr=errors)
        try:
            with tarfile.open(fileobj=decompressor.stdout, mode='r|') as archive:
                total = sum(member.size for member in archive)
            while decompressor.stdout.read(1024 * 1024):
                pass
            if decompressor.wait():
                raise OSError('zstd could not decompress the archive')
            return total
        finally:
            decompressor.stdout.close()
            if decompressor.poll() is None:
                decompressor.terminate()
            decompressor.wait()


def drill_candidate(root, scratch):
    free = shutil.disk_usage(scratch).free
    records = [record for record in store._read_index(root) if record.status == 'stored']
    for record in random.sample(records, len(records)):
        archive_path = store._archive_path(root, record)
        if 2 * record.original_bytes >= free or not archive_path.with_suffix('.sha256.json').is_file():
            continue
        try:
            fits = 2 * extracted_bytes(archive_path) < free
        except (OSError, tarfile.TarError) as exc:
            return record, archive_path, f'archive unreadable before restore: {exc}'
        if fits:
            return record, archive_path, None
    raise LookupError(f'no stored archive with a SHA-256 receipt fits in {scratch}')


def unlock_tree(path):
    for directory, names, files in os.walk(path):
        for name in names:
            os.chmod(os.path.join(directory, name), 0o700)
        for name in files:
            os.chmod(os.path.join(directory, name), 0o600)


def restored_digests(target, root):
    if target.is_file():
        with target.open('rb') as stream:
            return {root: reclaim_probe.sha256_hex(stream)}
    found = {}
    for directory, names, files in os.walk(target):
        base = PurePosixPath(root, Path(directory).relative_to(target).as_posix())
        found[str(base)] = None
        for name in files:
            with (Path(directory) / name).open('rb') as stream:
                found[str(base / name)] = reclaim_probe.sha256_hex(stream)
    return found


def check_restore(record, archive_path, scratch):
    saved = json.loads(archive_path.with_suffix('.sha256.json').read_text())
    if saved['host'] != record.host or saved['source'] != record.source_path:
        raise ValueError('archive receipt identity mismatch')
    expected = saved['manifest']
    listing = store._manifest_path(archive_path).read_text(encoding='utf-8').splitlines()
    root = PurePosixPath(next(iter(expected))).parts[0]
    work = Path(tempfile.mkdtemp(dir=scratch, prefix='restore-drill-'))
    try:
        target = work / root
        send_restore(hosts.LOCAL, dict(operation='restore', path=str(target), manifest=expected, security={}, member=None),
                     archive_path, True, work)
        unlock_tree(work)
        found = restored_digests(target, root)
        if sorted(found) != sorted(listing):
            raise ValueError('restored paths differ from .files.txt')
        if found != expected:
            raise ValueError('restored SHA-256s differ from the archive receipt')
    finally:
        unlock_tree(work)
        shutil.rmtree(work)


def drill(nas_root, report_dir, scratch):
    scratch = Path(scratch).resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    record, archive_path, problem = drill_candidate(Path(nas_root), scratch)
    try:
        if problem:
            raise RuntimeError(problem)
        check_restore(record, archive_path, scratch)
        row = dict(result='pass', reason=None)
    except Exception as exc:
        row = dict(result='fail', reason=' '.join(str(exc).split())[:500] or type(exc).__name__)
    row = dict(at=datetime.now(timezone.utc).isoformat(), host=record.host, id=record.id,
               archive=str(archive_path), **row)
    log = Path(report_dir) / DRILL_LOG
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(row, sort_keys=True) + '\n')
    return row


def check_local_archive(root, mount, source=None):
    if not os.path.ismount(mount):
        raise RuntimeError(f'archive drive is not mounted at {mount}')
    drive = os.stat(mount).st_dev
    destination = Path(root).resolve()
    while not destination.exists():
        destination = destination.parent
    if os.stat(destination).st_dev != drive:
        raise RuntimeError(f'archive folder {root} is not on the drive mounted at {mount}')
    if drive == os.stat('/').st_dev:
        raise RuntimeError(f'archive drive at {mount} is on the same filesystem as /')
    kind = subprocess.run(['findmnt', '-T', str(mount), '-n', '-o', 'FSTYPE'],
                          capture_output=True, text=True, check=True).stdout.split()
    if set(kind) & {'tmpfs', 'ramfs', 'devtmpfs'}:
        raise RuntimeError(f'archive drive at {mount} is memory-backed and will not survive a reboot')
    if source is not None and drive == os.stat(source).st_dev:
        raise RuntimeError(f'archive drive at {mount} is on the same filesystem as the data being removed')
    return drive


def check_nas(root, mount=None, source=None):
    if mount:
        return check_local_archive(root, mount, source)
    result = subprocess.run(['findmnt', '-T', str(root), '-n', '-o', 'FSTYPE'],
                            capture_output=True, text=True, check=True)
    filesystems = set(result.stdout.split())
    allowed = {'nfs', 'nfs4', 'cifs', 'smb3'}
    if not filesystems & allowed or filesystems - allowed - {'autofs'}:
        raise RuntimeError('archive target is not a mounted NAS filesystem')


def retention(path, days):
    normalized = path.replace('\\', '/').casefold()
    if normalized.startswith(('/tmp/', '/var/tmp/')) or '/appdata/local/temp/' in normalized or '/windows/temp/' in normalized:
        return max(7, days)
    return days


def package_cache(path):
    return reclaim_probe.package_cache(path)


def blocked(reason):
    if reason:
        if 'incomplete' in reason or 'unavailable' in reason or 'timed out' in reason:
            raise RuntimeError(reason)
        raise ValueError(reason)


def rotate_actions(live, now):
    data = live.read_bytes()
    packed = live.with_name(f'reclaim-actions-{now:%Y%m%dT%H%M%S%fZ}.jsonl.gz')
    partial = packed.with_name(packed.name + '.partial')
    with partial.open('xb') as stream:
        stream.write(gzip.compress(data))
        stream.flush(); os.fsync(stream.fileno())
    if gzip.decompress(partial.read_bytes()) != data:
        raise ValueError(f'rotated actions log {partial} does not read back')
    os.link(partial, packed)
    partial.unlink()
    live.unlink()


def item_id(host, tier, path, info, head=None):
    key = [host, tier, path, head, info['digest']]
    return hashlib.sha256(json.dumps(key).encode()).hexdigest()[:16]


@contextlib.contextmanager
def approvals(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / APPROVALS
    with (directory / 'approvals.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        found = json.loads(path.read_text()) if path.exists() else {}
        if not isinstance(found, dict) or not all(ITEM_ID.fullmatch(key) and isinstance(row, dict) for key, row in found.items()):
            raise ValueError(f'{path} is not a map of approved item IDs')
        before = json.dumps(found, sort_keys=True)
        yield found
        if json.dumps(found, sort_keys=True) != before:
            partial = path.with_name(path.name + '.partial')
            with partial.open('w') as stream:
                stream.write(json.dumps(found, indent=1, sort_keys=True))
                stream.flush(); os.fsync(stream.fileno())
            partial.replace(path)


def write_plan(path, reports, rules_sha256):
    items = [dict(id=row['id'], host=entry.name, tier=row['tier'], path=row['path'], bytes=row['bytes'],
                  approval=row['approval'], rule=row['rule'], reason=row['reason'])
             for entry in reports for row in entry.actions if 'id' in row]
    Path(path).write_text(json.dumps(dict(rules_sha256=rules_sha256, items=items), indent=1))
    return path


def approve(directory, plan, ids):
    items = json.loads(Path(plan).read_text()).get('items')
    if not isinstance(items, list) or not all(
            isinstance(item, dict) and set(item) == PLAN_KEYS and isinstance(item['id'], str) and ITEM_ID.fullmatch(item['id'])
            and item['tier'] in rules.APPROVAL_TIERS and type(item['bytes']) is int and type(item['approval']) is bool
            and all(isinstance(item[key], str) for key in ('host', 'path', 'rule', 'reason')) for item in items):
        raise ValueError(f'{plan} is not a reclaim dry-run plan')
    items = {item['id']: item for item in items}
    if 'all' in ids and len(ids) > 1:
        raise ValueError('approve takes item IDs or all, not both')
    chosen = list(items) if ids == ['all'] else list(dict.fromkeys(ids))
    unknown = [ident for ident in chosen if ident not in items]
    if unknown:
        raise ValueError(f'not in plan {plan}: ' + ', '.join(unknown))
    at = datetime.now(timezone.utc).isoformat()
    with approvals(directory) as found:
        for ident in chosen:
            found[ident] = dict(host=items[ident]['host'], tier=items[ident]['tier'], path=items[ident]['path'],
                                plan=str(Path(plan).resolve()), approved_at=at)
    return chosen


class Reclaimer:
    def __init__(self, host, config, apply, protection, report):
        self.host, self.config, self.apply = host, config, apply
        self.protection, self.report = protection, report
        self.rules = config['hosts'].get(host.name, {})
        if isinstance(self.protection, protect.Protection):
            self.protection.broad_paths.update(self.rules.get('shared_roots', []))
        self.listings = {}; self.prs = {}
        self.checked = {}; self.activity = None; self.prefetched = {}; self.unsized = []
        self.code = version.revision()
        self.removed = 0; self.removed_bytes = 0; self.limit_reached = False
        self.discovered = []; self.discovery = None
        self.deadline = None

    def unlisted(self):
        try:
            found = probe(self.host, 'unlisted', roots=[*self.rules.get('roots', []), '~'],
                          covered=rules.archive_patterns(self.rules),
                          skip=self.discovered, seconds=UNLISTED_SECONDS, timeout=UNLISTED_SECONDS + 60)
        except Exception as exc:
            self.report.notes.append(f'Large unlisted folder scan unavailable: {exc}')
            self.report.unlisted_complete = False
            return
        rows = sorted(found['rows'], key=lambda row: row['bytes'], reverse=True)[:UNLISTED_ROWS]
        self.report.unlisted = [dict(row, hint=hint(row['path'])) for row in rows]
        self.report.unlisted_complete = found['complete']

    def check_deadline(self, progress):
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise DeadlineReached(f'{DEADLINE} {progress}; the rest waits for the next run')

    def limit(self, key):
        return self.rules.get(key, self.config.get(key, rules.LIMIT_KEYS[key]))

    def budget(self, size, reserve=True):
        if not self.limit_reached:
            self.limit_reached = (self.removed + 1 > self.limit('max_items_per_run')
                                  or self.removed_bytes + size > self.limit('max_gib_per_run') * 1024**3)
        if self.limit_reached:
            raise ValueError(LIMIT_REACHED)
        if reserve:
            self.removed += 1
            self.removed_bytes += size

    def archive_target(self, path, expected=None):
        if self.config.get('local_archive_mount') and self.host.ssh is not None:
            raise RuntimeError('local_archive_mount only supports data on the controller; the remote host cannot recheck the drive')
        drive = check_nas(self.config['nas_root'], self.config.get('local_archive_mount'), path if self.host.ssh is None else None)
        if expected is not None and drive != expected:
            raise RuntimeError('archive drive changed while the copy was being made')
        return drive

    def keep(self, record):
        if record and self.host.ssh is None:
            return dict(file=record.archive_path, bytes=record.archive_bytes, mount=self.config.get('local_archive_mount'))

    def archive_present(self, path, drive, record):
        self.archive_target(path, drive)
        final = Path(record.archive_path)
        if not final.is_file() or final.stat().st_size != record.archive_bytes:
            raise ValueError('verified archive is no longer present')

    def archive_days(self, patterns, path):
        days = [rules.archive_entry(self.rules, pattern)['days'] for pattern in patterns]
        return retention(path, max(self.config['archive_idle_days'] if value is None else value for value in days))

    def gated(self, tier, patterns=()):
        return tier == 'clone' or tier in self.config.get('approval', []) or any(
            rules.archive_entry(self.rules, pattern)['approval'] for pattern in patterns)

    def check_approval(self, ident, tier, path):
        if self.host.kind == 'powershell':
            raise ValueError(APPROVAL_WINDOWS)
        with approvals(self.config['report_dir']) as found:
            if ident in found:
                return
            stale = any((row.get('host'), row.get('tier'), row.get('path')) == (self.host.name, tier, path) for row in found.values())
        raise ValueError(APPROVAL_STALE if stale else APPROVAL_NEEDED)

    def consume(self, ident):
        with approvals(self.config['report_dir']) as found:
            found.pop(ident, None)

    def rule(self, key, match):
        return f'{self.host.name}.{key}:{match}'

    def log(self, tier, path, action, size=0, reason='', record=True, *, rule, idle_days, **extra):
        row = dict(tier=tier, path=path, action=action, bytes=size, reason=reason, rule=rule, idle_days=idle_days,
                   rules_sha256=self.config.get('rules_sha256'), code=self.code, **extra)
        self.report.actions.append(row)
        if record:
            self.record(row)
        return row

    def skip(self, tier, path, size, reason, *, rule, idle_days, **extra):
        row = self.log(tier, path, 'skip', size, reason, record=bool(size), rule=rule, idle_days=idle_days, **extra)
        if not size:
            self.unsized.append(row)

    def record(self, row):
        if self.apply:
            directory = Path(self.config['report_dir'])
            directory.mkdir(parents=True, exist_ok=True)
            now = datetime.now(timezone.utc)
            line = json.dumps(dict(host=self.host.name, at=now.isoformat(), **row)) + '\n'
            live = directory / 'reclaim-actions.jsonl'
            with (directory / 'reclaim-actions.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                if live.exists() and live.stat().st_size + len(line) > self.config.get('actions_log_mb', 10) * 1024 * 1024:
                    rotate_actions(live, now)
                with live.open('a') as stream:
                    stream.write(line)
                    stream.flush(); os.fsync(stream.fileno())

    def size_skips(self):
        rows, self.unsized = self.unsized, []
        deadline = time.monotonic() + SIZE_SECONDS
        partial = 0
        try:
            for start in range(0, len(rows), BATCH):
                chunk = rows[start:start + BATCH]
                left = deadline - time.monotonic()
                if left <= 0:
                    partial += len(rows) - start
                    break
                for row, found in zip(chunk, probe(self.host, 'sizes', paths=[row['path'] for row in chunk], seconds=left)):
                    row['bytes'] = found['bytes']
                    partial += not found['complete']
            if partial:
                self.report.notes.append(f'{rows[0]["tier"]} skip sizes: {partial} are lower bounds (unreadable entries or the {SIZE_SECONDS}s cap)')
        except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
            self.report.notes.append(f'{rows[0]["tier"]} skip sizes unavailable: {exc}')
        finally:
            for row in rows:
                self.record(row)

    def proof(self, path, fresh=False):
        state = probe(self.host, 'repo', path=path)
        repo = repository(state['remote'])
        if fresh or repo not in self.listings:
            url = 'https://github.com/' + repo + '.git'
            effective = hosts.run(hosts.LOCAL,
                'git ls-remote --get-url -- ' + shlex.quote(url), timeout=180).stdout.decode().strip()
            if repository(effective).casefold() != repo.casefold():
                raise ValueError('origin URL is rewritten to another repository')
            try:
                result = hosts.run(hosts.LOCAL,
                    'GIT_TERMINAL_PROMPT=0 git ls-remote -- ' + shlex.quote(url), timeout=180)
            except subprocess.CalledProcessError as exc:
                if b'remote: Repository not found.' in (exc.stderr or b''):
                    raise ValueError('UNIQUE: GitHub repository not found: ' + repo) from None
                raise
            self.listings[repo] = result.stdout.decode()
        state = probe(self.host, 'repo', path=path, listing=self.listings[repo])
        key = repo, state['branch'], state['head']
        if fresh or key not in self.prs:
            self.prs[key] = pull_requests(*key)
        return state, self.prs[key], self.listings[repo]

    def prefetch(self, candidates):
        self.check_deadline('while preparing, before the activity probe')
        try:
            self.load_activity()
        except (RuntimeError, ValueError, OSError, subprocess.SubprocessError):
            return
        if self.activity['blocked']:
            return
        requests = [dict(operation=operation, path=path, **(dict(days=days, protected=self.rules.get('protected', [])) if operation == 'guard' else {}))
                    for path, days in candidates for operation in ('guard', 'context', 'repositories')]
        for start in range(0, len(requests), BATCH):
            self.check_deadline(f'while preparing, after {start // BATCH} of {-(-len(requests) // BATCH)} prefetch batches; 0 items done')
            chunk = requests[start:start + BATCH]
            try:
                results = probe(self.host, 'batch', requests=chunk, activity=self.activity)
            except (RuntimeError, ValueError, OSError, subprocess.SubprocessError):
                continue
            for request, result in zip(chunk, results):
                self.prefetched[request['operation'], request['path'], request.get('days')] = result

    def load_activity(self):
        if self.activity is None:
            self.activity = probe(self.host, 'activity')
            for note in self.activity['notes'] + self.activity['blocked']:
                if note not in self.report.notes:
                    self.report.notes.append(note)

    def ask(self, operation, path, fresh, **request):
        found = None if fresh else self.prefetched.get((operation, path, request.get('days')))
        if found is None or 'skipped' in found:
            return probe(self.host, operation, path=path, **request)
        if 'error' in found:
            raise (ValueError if found['value'] else RuntimeError)(found['error'])
        return found['result']

    def safe(self, path, days=0, allow_git=False, fresh=False, archive=False):
        if not fresh:
            self.load_activity()
            if self.activity['blocked']:
                raise ValueError('; '.join(self.activity['blocked']))
        info = self.ask('guard', path, fresh, days=days, activity=None if fresh else self.activity,
                        protected=self.rules.get('protected', []))
        context = self.ask('context', path, fresh)
        contexts = self.ask('repositories', path, fresh)
        if context and context not in contexts:
            contexts.append(context)
        for context in contexts:
            state = probe(self.host, 'repo', path=context, stub_ok=True)
            if state is None:
                note = f'Not a repository, skipped: {context}: .git holds no HEAD, index, refs or reflogs'
                if note not in self.report.notes:
                    self.report.notes.append(note)
                allow_git = True
                continue
            inside = os.path.normcase(context.replace('\\', '/')).startswith(os.path.normcase(path.replace('\\', '/')).rstrip('/') + '/')
            same = os.path.normcase(context.replace('\\', '/')) == os.path.normcase(path.replace('\\', '/'))
            if archive and (same or inside) and state['worktree']:
                raise ValueError('registered worktree must use Git retirement')
            if not state['worktree'] and state['linked_worktrees']:
                raise ValueError('IN USE: repository owns other registered worktrees')
            if not state['worktree'] and (inside or archive and same):
                problem = 'IN USE: uncommitted work or stashes' if state['dirty'] or state['stashes'] else ''
                if problem:
                    raise ValueError(problem)
                if state['remote']:
                    repo = repository(state['remote'])
                    key = repo, state['branch'], state['head']
                    if fresh or key not in self.prs:
                        self.prs[key] = pull_requests(*key)
                    if any(row['state'] == 'OPEN' for row in self.prs[key]):
                        problem = 'IN USE: open pull request'
            else:
                state, prs, _ = self.proof(context, fresh)
                problem = completion(state, prs)
            if problem:
                raise ValueError(problem)
            allow_git = True
        protection = protect.collect(self.host) if fresh else self.protection
        if isinstance(protection, protect.Protection):
            protection.broad_paths.update(self.rules.get('shared_roots', []))
        if self.host.kind == 'powershell':
            if protection.errors:
                raise RuntimeError('protection inventory incomplete: ' + '; '.join(protection.errors))
            references = [reference for reference in protection.paths if
                (path.replace('\\', '/').casefold().rstrip('/') == reference.replace('\\', '/').casefold().rstrip('/')
                 if reference in protection.broad_paths or protect.broad_reference(reference, protection.home, True)
                 else protect.overlaps(path, reference, True))]
            reason = 'scheduler references ' + ', '.join(references) if references else ''
        else:
            reason = protection.reason(path, allow_git=allow_git) if fresh or path not in self.checked else self.checked[path]
        blocked(reason)
        return info

    def worktrees(self):
        discovery = self.discovery = probe(self.host, 'discover', roots=self.rules.get('roots', []))
        paths = self.discovered = discovery['paths']
        self.report.errors.extend('Worktree discovery incomplete: ' + error for error in discovery['errors'])
        self.report.notes.extend(discovery['notes'])
        self.check_deadline('while preparing, before the protection check; 0 items done')
        self.checked = self.protection.batch(paths, allow_git=True) if self.host.kind != 'powershell' else {}
        try:
            for done, path in enumerate(paths):
                self.check_deadline(f'after {done} of {len(paths)} items')
                size = 0; days = None
                rule = self.rule('roots', discovery['roots'][path])
                try:
                    local = probe(self.host, 'repo', path=path)
                    if local['dirty'] or local['stashes']:
                        raise ValueError('IN USE: uncommitted work or stashes')
                    state, prs, listing = self.proof(path)
                    reason = completion(state, prs)
                    if reason.startswith('UNIQUE: unpushed'):
                        reason += ': head ' + state['head'][:12] + ' is not on ' + state['remote']
                    if reason:
                        raise ValueError(reason)
                    days = (min(self.config['worktree_idle_days'], WORKTREE_MERGED_DAYS)
                            if state['merged'] else self.config['worktree_idle_days'])
                    info = self.safe(path, days, True)
                    size = info['bytes']
                    gated = self.gated('worktree')
                    ident = item_id(self.host.name, 'worktree', path, info, state['head'])
                    if not self.apply or 'worktree' not in self.config['live']:
                        self.log('worktree', path, 'would remove worktree', size,
                                 'DURABLE ELSEWHERE: current head is published and merged/closed; ' +
                                 ('unique reflog history and ' if state['reflog'] else '') + 'ignored data require a verified NAS copy'
                                 if state['ignored'] or state['reflog'] else
                                 'DURABLE ELSEWHERE: clean published head is merged/closed',
                                 head=state['head'], branch=state['branch'], remote=state['remote'],
                                 merged=state['merged'], rule=rule, idle_days=days, id=ident, approval=gated,
                                 pull_requests=[row['url'] for row in prs if row['headRefOid'] == state['head']])
                        continue
                    if gated:
                        self.check_approval(ident, 'worktree', path)
                    def recheck():
                        current, current_prs, _ = self.proof(path, True)
                        problem = completion(current, current_prs)
                        if problem or current['head'] != state['head']:
                            raise ValueError(problem or 'head changed after preview')
                        checked = self.safe(path, days, True, True)
                        if gated and item_id(self.host.name, 'worktree', path, checked, state['head']) != ident:
                            raise ValueError(APPROVAL_STALE)
                        return checked
                    if self.limit_reached:
                        raise ValueError(LIMIT_REACHED)
                    probe(self.host, 'allowed', path=path, worktree=True)
                    fresh = recheck()['bytes']
                    self.budget(fresh, reserve=False)
                    manifest = None; saved = None; security = None
                    if state['ignored'] or state['reflog']:
                        drive = self.archive_target(path)
                        saved, manifest, security = preserve(self.host, path, self.config['nas_root'], lambda: (recheck(), self.archive_target(path, drive)),
                                                             state['reflog'])
                    current, current_prs, listing = self.proof(path, True)
                    if completion(current, current_prs) or current['head'] != state['head']:
                        raise ValueError('Git completion changed before removal')
                    if saved:
                        self.archive_present(path, drive, saved)
                    self.budget(max(fresh, saved.original_bytes if saved else 0))
                    removed = probe(self.host, 'remove', path=path, days=days, protected=self.rules.get('protected', []),
                                    head=state['head'], branch=current['branch'], remote=current['remote'],
                                    listing=listing, manifest=manifest, security=security, keep=self.keep(saved),
                                    reflog=state['reflog'], digest=info['digest'] if gated else None)
                    action = 'remove worktree and local branch' if removed['branch_removed'] else 'remove worktree; retain local branch'
                    self.log('worktree', path, action, size,
                             'DURABLE ELSEWHERE: published merged/closed head; clean, no process, T3 or Codex use' +
                             ('; ignored files SHA-256 verified at ' + saved.archive_path if saved else '') +
                             ('; unique reflog commits bundled in head.bundle' if state['reflog'] else ''),
                             head=removed['head'], branch=removed['branch'], remote=removed['remote'],
                             merged=removed['merged'], rule=rule, idle_days=days,
                             pull_requests=[row['url'] for row in current_prs if row['headRefOid'] == removed['head']])
                    if gated:
                        self.consume(ident)
                except ValueError as exc:
                    self.skip('worktree', path, size, str(exc), rule=rule, idle_days=days)
                except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                    self.log('worktree', path, 'error', size, str(exc), rule=rule, idle_days=days)
        finally:
            self.size_skips()

    def clone_state(self, path, fresh=False):
        local = probe(self.host, 'repo', path=path)
        if local['dirty'] or local['stashes']:
            raise ValueError('IN USE: uncommitted work or stashes')
        if local['linked_worktrees']:
            raise ValueError('IN USE: repository owns other registered worktrees')
        state, prs, listing = self.proof(path, fresh)
        reason = completion(state, prs)
        if reason:
            raise ValueError(reason)
        found = probe(self.host, 'clone', path=path, listing=listing)
        if found['unique_refs']:
            raise ValueError('UNIQUE: local refs not on GitHub origin: ' + ', '.join(found['unique_refs'][:5]))
        if found['reflog']:
            raise ValueError(f"UNIQUE: {len(found['reflog'])} reflog commits not on GitHub origin")
        return state

    def clones(self):
        discovery = self.discovery or probe(self.host, 'discover', roots=self.rules.get('roots', []))
        paths = discovery['clones']
        repos = {}
        for done, path in enumerate(paths):
            self.check_deadline(f'while preparing, after {done} of {len(paths)} clone probes; 0 items done')
            try:
                repos[path] = repository(probe(self.host, 'repo', path=path)['remote']).casefold()
            except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
                repos[path] = exc
        self.check_deadline('while preparing, before the protection check; 0 items done')
        self.checked = self.protection.batch(paths, allow_git=True) if self.host.kind != 'powershell' else {}
        days = self.config['worktree_idle_days']
        gone = set()
        def keeper(path, key):
            for other in paths:
                if other == path or other in gone or repos[other] != key or other.startswith((path + '/', path + '\\')):
                    continue
                try:
                    state = probe(self.host, 'repo', path=other)
                    if not state['worktree'] and repository(state['remote']).casefold() == key:
                        return
                except (RuntimeError, ValueError, OSError, subprocess.SubprocessError):
                    continue
            raise ValueError('KEEP: only checkout of ' + key + ' on this host')
        try:
            for done, path in enumerate(sorted(paths, key=lambda item: (len(item), item), reverse=True)):
                self.check_deadline(f'after {done} of {len(paths)} items')
                size = 0
                rule = self.rule('roots', discovery['roots'][path])
                try:
                    key = repos[path]
                    if not isinstance(key, str):
                        raise key
                    state = self.clone_state(path)
                    keeper(path, key)
                    info = self.safe(path, days, True)
                    size = info['bytes']
                    ident = item_id(self.host.name, 'clone', path, info, state['head'])
                    if not self.apply or 'clone' not in self.config['live']:
                        gone.add(path)
                        self.log('clone', path, 'would remove clone', size,
                                 'DURABLE ELSEWHERE: every local ref, HEAD and reflog is on GitHub; another checkout remains; '
                                 'the clone requires a verified NAS copy',
                                 head=state['head'], branch=state['branch'], remote=state['remote'],
                                 rule=rule, idle_days=days, id=ident, approval=True)
                        continue
                    self.check_approval(ident, 'clone', path)
                    def recheck():
                        keeper(path, key)
                        current = self.clone_state(path, True)
                        if current['head'] != state['head']:
                            raise ValueError('head changed after preview')
                        checked = self.safe(path, days, True, True)
                        if item_id(self.host.name, 'clone', path, checked, state['head']) != ident:
                            raise ValueError(APPROVAL_STALE)
                        return checked
                    if self.limit_reached:
                        raise ValueError(LIMIT_REACHED)
                    probe(self.host, 'allowed', path=path, worktree=True)
                    fresh = recheck()['bytes']
                    self.budget(fresh, reserve=False)
                    drive = self.archive_target(path)
                    saved, manifest, security = preserve(self.host, path, self.config['nas_root'],
                                                         lambda: (recheck(), self.archive_target(path, drive)))
                    self.archive_present(path, drive, saved)
                    self.budget(max(fresh, saved.original_bytes))
                    probe(self.host, 'remove', path=path, days=days, protected=self.rules.get('protected', []), clone=True,
                          manifest=manifest, security=security, keep=self.keep(saved), digest=info['digest'])
                    gone.add(path)
                    self.log('clone', path, 'remove clone', size,
                             'DURABLE ELSEWHERE: every local ref, HEAD and reflog is on GitHub; clean, idle, not in use; another checkout remains; '
                             'every file SHA-256 verified at ' + saved.archive_path,
                             head=state['head'], branch=state['branch'], remote=state['remote'], rule=rule, idle_days=days)
                    self.consume(ident)
                except ValueError as exc:
                    self.skip('clone', path, size, str(exc), rule=rule, idle_days=days)
                except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                    self.log('clone', path, 'error', size, str(exc), rule=rule, idle_days=days)
        finally:
            self.size_skips()

    def archives(self):
        listed = rules.archive_patterns(self.rules)
        patterns = probe(self.host, 'expand', patterns=listed,
                         exclude={pattern: rules.archive_entry(self.rules, pattern)['exclude'] for pattern in listed})
        paths = list(patterns)
        tagged = {}
        for pattern in listed:
            if rules.archive_entry(self.rules, pattern)['category']:
                self.check_deadline('while preparing archive patterns; 0 items done')
                tagged[pattern] = set(probe(self.host, 'expand', patterns=[pattern], exclude={}))
        self.checked = {}
        self.prefetch([(path, self.archive_days(patterns[path], path)) for path in paths if not package_cache(path)])
        try:
            for done, path in enumerate(paths):
                self.check_deadline(f'after {done} of {len(paths)} items')
                size = 0
                rule = self.rule('archive', patterns[path][0])
                category = next((rules.archive_entry(self.rules, pattern)['category'] for pattern, matched in tagged.items()
                                 if path in matched), rules.CATEGORIES[0])
                exclude = [item for pattern in patterns[path] for item in rules.archive_entry(self.rules, pattern)['exclude']]
                days = None
                try:
                    if package_cache(path):
                        raise ValueError('package caches are excluded')
                    days = self.archive_days(patterns[path], path)
                    info = self.safe(path, days, archive=True)
                    size = info['bytes']
                    policies = {entry.get('preservation', rules.PRESERVATION[0]) for entry in self.rules.get('archive', [])
                                if isinstance(entry, dict) and entry.get('category') == 'artifact'
                                and any(protect.overlaps(path, item, self.host.kind == 'powershell') for item in tagged[entry['path']])}
                    policy = next((name for name in rules.PRESERVATION if name in policies), None)
                    receipt = policy and rules.preservation_receipt(self.config, self.host.name, path, policy)
                    gated = self.gated('archive', patterns[path])
                    ident = item_id(self.host.name, 'archive', path, info)
                    if not self.apply or 'archive' not in self.config['live']:
                        self.log('archive', path, 'would archive and remove', size,
                                 'UNIQUE: copy to NAS and verify every file SHA-256 before removal', rule=rule, idle_days=days,
                                 category=category, id=ident, approval=gated)
                        continue
                    if gated:
                        self.check_approval(ident, 'archive', path)
                    def recheck():
                        checked = self.safe(path, days, fresh=True, archive=True)
                        if gated and item_id(self.host.name, 'archive', path, checked) != ident:
                            raise ValueError(APPROVAL_STALE)
                        return checked
                    if self.limit_reached:
                        raise ValueError(LIMIT_REACHED)
                    probe(self.host, 'allowed', path=path, worktree=False)
                    fresh = recheck()['bytes']
                    self.budget(fresh, reserve=False)
                    drive = self.archive_target(path)
                    saved, manifest, security = preserve(self.host, path, self.config['nas_root'], lambda: (recheck(), self.archive_target(path, drive)))
                    receipt = policy and rules.preservation_receipt(self.config, self.host.name, path, policy)
                    if policy == 'sha256' and receipt['sha256'] != rules.content_hash(manifest):
                        raise ValueError('preservation receipt sha256 does not match the original')
                    self.archive_present(path, drive, saved)
                    self.budget(max(fresh, saved.original_bytes))
                    probe(self.host, 'remove', path=path, days=days, protected=self.rules.get('protected', []), exclude=exclude, manifest=manifest, security=security, keep=self.keep(saved),
                          digest=info['digest'] if gated else None)
                    self.log('archive', path, 'archive and remove', size,
                             'DURABLE ELSEWHERE: every file SHA-256 verified at ' + saved.archive_path, rule=rule, idle_days=days,
                             category=category)
                    if gated:
                        self.consume(ident)
                except ValueError as exc:
                    self.skip('archive', path, size, str(exc), rule=rule, idle_days=days, category=category)
                except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                    self.log('archive', path, 'error', size, str(exc), rule=rule, idle_days=days, category=category)
        finally:
            self.size_skips()
