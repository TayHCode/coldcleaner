"""Stdlib probe sent to a cleanup host; every operation uses an explicit path."""
import hashlib
from contextlib import closing
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import sqlite3
import stat
import subprocess
import sys
import tarfile
import time


def windows_file_safety(path):
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ValueError('Windows path is open or unreadable: ' + str(path))
    try:
        if not os.path.isdir(path):
            ntdll = ctypes.WinDLL('ntdll')
            ntdll.NtQueryInformationFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                                     ctypes.c_ulong, ctypes.c_int]
            users = ctypes.create_string_buffer(65536)
            status = ntdll.NtQueryInformationFile(handle, (ctypes.c_void_p * 2)(), users, len(users), 47)
            if status or ctypes.c_ulong.from_buffer(users).value:
                raise ValueError('Windows file is mapped by a running program: ' + str(path))
    finally:
        kernel.CloseHandle(handle)
    if not os.path.isdir(path):
        handle = kernel.CreateFileW(str(path), 0x2, 7, None, 3, 0, None)
        if handle != ctypes.c_void_p(-1).value:
            kernel.CloseHandle(handle)
        elif ctypes.get_last_error() == 32:
            raise ValueError('Windows file is mapped by a running program or driver: ' + str(path))
    class Streams(ctypes.Structure):
        _fields_ = [('size', ctypes.c_longlong), ('name', wintypes.WCHAR * 296)]
    kernel.FindFirstStreamW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(Streams), wintypes.DWORD]
    kernel.FindFirstStreamW.restype = wintypes.HANDLE
    kernel.FindNextStreamW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Streams)]
    kernel.FindClose.argtypes = [wintypes.HANDLE]
    stream = Streams()
    handle = kernel.FindFirstStreamW(str(path), 0, ctypes.byref(stream), 0)
    if handle == ctypes.c_void_p(-1).value:
        if ctypes.get_last_error() != 38:
            raise ValueError('NTFS stream inventory incomplete: ' + str(path))
        return
    try:
        while True:
            if stream.name != '::$DATA':
                raise ValueError('NTFS alternate streams require preservation: ' + str(path))
            if not kernel.FindNextStreamW(handle, ctypes.byref(stream)):
                if ctypes.get_last_error() != 38:
                    raise ValueError('NTFS stream inventory incomplete: ' + str(path))
                break
    finally:
        kernel.FindClose(handle)


def git(path, *args, check=True):
    result = subprocess.run(['git', '-C', str(path), *args], capture_output=True, text=True,
                            env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0',
                                 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1'})
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or 'Git check failed')
    return result.stdout.strip() if check else result


def overlap(a, b):
    a, b = os.path.normcase(os.path.realpath(a)), os.path.normcase(os.path.realpath(b))
    try:
        return os.path.commonpath((a, b)) in (a, b)
    except ValueError:
        return False


def contained(path, root):
    root = os.path.normcase(os.path.abspath(os.path.expandvars(os.path.expanduser(root))))
    return Path(os.path.normcase(os.path.abspath(path))).is_relative_to(root)


def threads():
    root = Path.home() / '.t3/userdata'
    database = root / 'statev2.sqlite'
    if not root.exists():
        return []
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=10)) as db:
        rows = db.execute('''SELECT t.payload_json, t.archived_at, EXISTS
              (SELECT 1 FROM orchestration_v2_projection_runs r WHERE r.thread_id=t.thread_id
               AND r.status IN ('running','waiting')) FROM orchestration_v2_projection_threads t
            WHERE t.deleted_at IS NULL''')
        paths = []
        for text, archived, running in rows:
            row = json.loads(text)
            settled = row.get('settledOverride') == 'settled' or (
                not row.get('settledOverride') and
                (row.get('settledAt') or '') > (row.get('unsettledAt') or ''))
            if running or row.get('pinnedAt') or row.get('pinOrderKey') is not None or (
                    not (row.get('archivedAt') or archived) and not settled):
                if row.get('worktreePath'):
                    paths.append(row['worktreePath'])
                elif row.get('projectId'):
                    project = db.execute('SELECT workspace_root FROM projection_projects WHERE project_id=?',
                                         (row['projectId'],)).fetchone()
                    if project:
                        paths.append(project[0])
        return paths


def windows_arguments(command):
    import ctypes
    from ctypes import wintypes
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    shell.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    kernel.LocalFree.argtypes = [wintypes.LPVOID]
    count = ctypes.c_int()
    arguments = shell.CommandLineToArgvW(command, ctypes.byref(count))
    if not arguments:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return [arguments[index] for index in range(count.value)]
    finally:
        kernel.LocalFree(arguments)


def windows_paths(arguments):
    return [path for argument in arguments for path in re.findall(r'''[A-Za-z]:[\\/][^\r\n<>"'|;,]*''', argument)]


def exited(pid):
    import ctypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x1000, 0, pid)
    if not handle:
        return ctypes.get_last_error() == 87
    try:
        code = ctypes.c_ulong()
        return bool(kernel.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value != 259
    finally:
        kernel.CloseHandle(handle)


def drivers():
    import ctypes
    from ctypes import wintypes
    psapi = ctypes.WinDLL('psapi', use_last_error=True)
    psapi.EnumDeviceDrivers.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    psapi.GetDeviceDriverFileNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    bases = (ctypes.c_void_p * 4096)()
    needed = wintypes.DWORD()
    if not psapi.EnumDeviceDrivers(bases, ctypes.sizeof(bases), ctypes.byref(needed)) or needed.value > ctypes.sizeof(bases):
        raise RuntimeError('process-use inventory incomplete: loaded drivers unreadable')
    root = os.environ.get('SystemRoot', 'C:\\Windows')
    name = ctypes.create_unicode_buffer(32768)
    paths = []
    for base in bases[:needed.value // ctypes.sizeof(ctypes.c_void_p)]:
        if not base or not psapi.GetDeviceDriverFileNameW(base, name, len(name)):
            raise RuntimeError('process-use inventory incomplete: loaded driver name unreadable')
        value = name.value
        paths.append(value[4:] if value.startswith('\\??\\') else
                     root + value[11:] if value.lower().startswith('\\systemroot\\') else value)
    return paths


def extended(path):
    path = str(path)
    return '\\\\?\\' + os.path.abspath(path) if os.name == 'nt' and not path.startswith('\\\\?\\') else path


def delete(path):
    import shutil
    def writable(function, name, error):
        if os.name != 'nt' or not isinstance(error, PermissionError):
            raise error
        os.chmod(name, stat.S_IWRITE)
        function(name)
    target = extended(path)
    if os.path.isdir(target) and not os.path.islink(target) and sys.version_info < (3, 12):
        shutil.rmtree(target, onerror=lambda function, name, info: writable(function, name, info[1]))
    elif os.path.isdir(target) and not os.path.islink(target):
        shutil.rmtree(target, onexc=writable)
    else:
        try:
            os.unlink(target)
        except PermissionError as error:
            writable(os.unlink, target, error)


def protected_process(pid):
    import ctypes

    class ExtendedBasicInformation(ctypes.Structure):
        _fields_ = [('Size', ctypes.c_size_t), ('ExitStatus', ctypes.c_int32), ('PebBaseAddress', ctypes.c_void_p),
                    ('AffinityMask', ctypes.c_size_t), ('BasePriority', ctypes.c_int32),
                    ('UniqueProcessId', ctypes.c_size_t), ('InheritedFromUniqueProcessId', ctypes.c_size_t),
                    ('Flags', ctypes.c_uint32)]

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    ntdll = ctypes.WinDLL('ntdll')
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    ntdll.NtQueryInformationProcess.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong,
                                                ctypes.POINTER(ctypes.c_ulong)]
    handle = kernel.OpenProcess(0x1000, 0, pid)
    if not handle:
        return False
    try:
        returned = ctypes.c_ulong()
        level = ctypes.c_ubyte()
        status = ntdll.NtQueryInformationProcess(handle, 61, ctypes.byref(level), 1, ctypes.byref(returned))
        if status == 0 and level.value != 0:
            return True
        extended = ExtendedBasicInformation()
        extended.Size = ctypes.sizeof(extended)
        status = ntdll.NtQueryInformationProcess(handle, 0, ctypes.byref(extended), ctypes.sizeof(extended),
                                                 ctypes.byref(returned))
        return status == 0 and bool(extended.Flags & 0x81)
    finally:
        kernel.CloseHandle(handle)


PROC_SCAN = r"""
import json, os, re, sys
from pathlib import Path
by_namespace = sys.argv[2:] == ['--by-namespace']


def exited(proc):
    try:
        status = (proc / 'status').read_text()
    except (FileNotFoundError, ProcessLookupError):
        return True
    return bool(re.search(r'^State:\s+Z', status, re.M) and re.search(r'^Threads:\s+1$', status, re.M))


def kernel_thread(proc):
    try:
        return bool(int((proc / 'stat').read_text().rsplit(')', 1)[1].split()[6]) & 0x00200000)
    except (FileNotFoundError, ProcessLookupError):
        return False

paths, namespaces = [], {}
for proc in Path(sys.argv[1]).iterdir():
    if not proc.name.isdigit() or int(proc.name) == os.getpid():
        continue
    found = []
    try:
        command = (proc / 'cmdline').read_bytes()
        for name in ('cwd', 'exe'):
            try:
                found.append(os.readlink(proc / name))
            except FileNotFoundError:
                pass
        for fd in (proc / 'fd').iterdir():
            try:
                found.append(os.readlink(fd))
            except FileNotFoundError:
                pass
        text = command.decode('utf-8', 'replace') + (proc / 'environ').read_bytes().decode('utf-8', 'replace')
        for item in text.split('\x00'):
            found.extend(re.findall(r"/[^\x00:=\x27\x22;,|()<>]+", item))
            found.extend(re.findall(r"/[^\s\x00:=\x27\x22;,|()<>]+", item))
        for line in (proc / 'maps').read_bytes().decode('utf-8', 'surrogateescape').splitlines():
            fields = line.split(None, 5)
            if len(fields) == 6 and fields[5].startswith('/'):
                found.append(fields[5].removesuffix(' (deleted)'))
        if by_namespace:
            if os.readlink(proc / 'root') != '/':
                sys.exit('process ' + proc.name + ' has a changed root')
            namespace = os.readlink(proc / 'ns' / 'mnt')
            if namespace not in namespaces:
                namespaces[namespace] = dict(mountinfo=(proc / 'mountinfo').read_text(), paths=[])
            namespaces[namespace]['paths'].extend(found)
    except (FileNotFoundError, ProcessLookupError):
        if by_namespace:
            if exited(proc) or kernel_thread(proc):
                continue
            sys.exit('process ' + proc.name + ' is running but its files are unreadable')
    paths.extend(found)
print(json.dumps(list(namespaces.values()) if by_namespace else paths))
"""


def drvfs_mounts(mountinfo):
    def unescape(field):
        return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), field)
    mounts = {}
    for line in mountinfo.splitlines():
        fields = line.split()
        match = re.search(r'(?:^|,)aname=drvfs;path=([^;,]+)', fields[-1]) if ' - ' in line else None
        if match:
            root = unescape(fields[3]).strip('/')
            target = unescape(match[1]).rstrip('\\') + ('\\' + root.replace('/', '\\') if root else '')
            mounts[unescape(fields[4]).rstrip('/') or '/'] = target
    return sorted(mounts.items(), key=lambda mount: -len(mount[0]))


def windows_from_wsl(path, mounts):
    for point, target in mounts:
        if path == point or path.startswith(point.rstrip('/') + '/'):
            return target + '\\' + path[len(point):].strip('/').replace('/', '\\')
    return None


def wsl(distro, *command, stdin=None):
    result = subprocess.run(['wsl.exe', '-d', distro, '-u', 'root', '-e', *command], input=stdin,
                            capture_output=True, encoding='utf-8', errors='surrogateescape')
    if result.returncode:
        raise RuntimeError('process-use inventory incomplete: WSL distro ' + distro + ': ' + result.stderr.strip())
    return result.stdout


def wsl_references():
    listing = subprocess.run(['wsl.exe', '--list', '--running', '--quiet'], capture_output=True, check=True).stdout
    text = listing.decode('utf-16-le') if b'\x00' in listing else listing.decode()
    distros = [line.strip() for line in text.splitlines() if line.strip()]
    if not distros:
        raise RuntimeError('process-use inventory incomplete: vmmemWSL is running but no WSL distro is listed')
    paths = []
    for distro in distros:
        for namespace in json.loads(wsl(distro, 'python3', '-', '/proc', '--by-namespace', stdin=PROC_SCAN)):
            mounts = drvfs_mounts(namespace['mountinfo'])
            paths.extend(filter(None, (windows_from_wsl(path, mounts) for path in namespace['paths'])))
    return paths


def references(proc='/proc'):
    if os.name == 'nt':
        script = "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress"
        result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
                                capture_output=True, text=True, check=True)
        rows = json.loads(result.stdout)
        rows = rows if isinstance(rows, list) else [rows]
        paths, machines = [], []
        for row in rows:
            if row['ProcessId'] in (0, 4, os.getpid()):
                continue
            if not row.get('CommandLine'):
                if not row.get('ExecutablePath') and protected_process(row['ProcessId']):
                    continue
                if not row.get('ExecutablePath') and row.get('Name') in ('vmmemWSL', 'vmmemCmZygote'):
                    machines.append(row['Name'])
                    continue
                if exited(row['ProcessId']):
                    continue
                raise RuntimeError('process-use inventory incomplete: CommandLine unreadable for process ' +
                                   str(row['ProcessId']) + '; Windows reclaim requires elevation')
            if row.get('ExecutablePath'):
                paths.append(row['ExecutablePath'])
            paths.extend(windows_paths(windows_arguments(row['CommandLine'])))
        if 'vmmemCmZygote' in machines and any((row.get('Name') or '').lower().startswith('windowssandbox') for row in rows):
            raise RuntimeError('process-use inventory incomplete: a Windows Sandbox session is running')
        if machines.count('vmmemWSL') > 1:
            raise RuntimeError('process-use inventory incomplete: more than one WSL VM is running')
        if 'vmmemWSL' in machines:
            paths.extend(wsl_references())
        return paths + drivers()
    command = ['python3', '-c', PROC_SCAN, str(proc)]
    if os.geteuid() != 0:
        command = ['sudo', '-n', *command]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('process-use inventory incomplete: ' + result.stderr.strip())
    return json.loads(result.stdout)


def windows_security(path, descriptor=None):
    import ctypes
    from ctypes import wintypes
    api = ctypes.WinDLL('advapi32', use_last_error=True)
    api.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID,
                                     wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    api.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID]
    if descriptor is not None:
        buffer = ctypes.create_string_buffer(bytes.fromhex(descriptor))
        control = ctypes.c_ushort(); revision = wintypes.DWORD()
        if not api.GetSecurityDescriptorControl(buffer, ctypes.byref(control), ctypes.byref(revision)):
            raise ctypes.WinError(ctypes.get_last_error())
        flags = 7 | (0x80000000 if control.value & 0x1000 else 0x20000000)
        if not api.SetFileSecurityW(str(path), flags, buffer):
            raise ctypes.WinError(ctypes.get_last_error())
    needed = wintypes.DWORD()
    api.GetFileSecurityW(str(path), 7, None, 0, ctypes.byref(needed))
    if not needed.value:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_string_buffer(needed.value)
    if not api.GetFileSecurityW(str(path), 7, buffer, len(buffer), ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.raw[:needed.value].hex()


def mount_boundary(path):
    path = Path(os.path.abspath(path))
    if os.name != 'nt' and Path('/proc/self/mountinfo').exists():
        for row in Path('/proc/self/mountinfo').read_text().splitlines():
            name = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), row.split()[4])
            if Path(name).is_relative_to(path):
                raise ValueError('mounted filesystem in cleanup candidate: ' + name)
    elif os.path.ismount(path):
        raise ValueError('cleanup candidate is a mount point')


def package_cache(path):
    return bool(set(str(path).replace('\\', '/').casefold().split('/')) &
                {'.cache', '.npm', '.cargo', '.bun', 'node-compile-cache', 'npm-cache', 'pip-cache', 'uv-cache', 'go-build'})


def reject_package_caches(root):
    pending = [root]
    while pending:
        item = pending.pop()
        if package_cache(item):
            raise ValueError('package caches are excluded: ' + str(item))
        try:
            with os.scandir(item) as entries:
                pending.extend(Path(entry.path) for entry in entries if entry.is_dir(follow_symlinks=False)
                               and not getattr(entry.stat(follow_symlinks=False), 'st_file_attributes', 0) & 1024)
        except OSError:
            continue


def tree(path, hashes=False):
    present(path)
    path = Path(path)
    mount_boundary(path)
    path = Path(extended(path))
    reject_package_caches(path)
    result = {}; security = {}; allocated = logical = files = 0; newest = path.lstat().st_mtime
    device = path.lstat().st_dev
    pending = [path]
    while pending:
        item = pending.pop()
        if package_cache(item):
            raise ValueError('package caches are excluded: ' + str(item))
        info = item.lstat()
        if info.st_dev != device:
            raise ValueError('filesystem boundary: ' + str(item))
        if os.name != 'nt' and (os.listxattr(item, follow_symlinks=False) or
                info.st_uid != os.geteuid() or info.st_gid != os.getegid() or info.st_mode & 0o7000):
            raise ValueError('access metadata requires separate preservation: ' + str(item))
        if item.suffix.casefold() in ('.vhd', '.vhdx', '.qcow2', '.vmdk', '.vdi'):
            raise ValueError('VM disk requires hypervisor dependency proof: ' + str(item))
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 1024:
            raise ValueError('symlink or reparse point: ' + str(item))
        if os.name == 'nt':
            windows_file_safety(item)
        if item.name == '.keep-local':
            raise ValueError('.keep-local: ' + str(item))
        newest = max(newest, info.st_mtime)
        allocated += getattr(info, 'st_blocks', (info.st_size + 511) // 512) * 512
        relative = str(item.relative_to(path.parent)).replace(os.sep, '/')
        if hashes:
            security[relative] = (windows_security(item) if os.name == 'nt' else
                                  dict(mode=info.st_mode & 0o777, uid=info.st_uid,
                                       gid=info.st_gid, mtime_ns=info.st_mtime_ns))
        if '\\' in relative or any(ord(char) < 32 for char in relative):
            raise ValueError('unsupported archive member name: ' + repr(relative))
        if item.is_dir():
            pending.extend(item.iterdir())
            if hashes:
                result[relative] = None
        elif item.is_file():
            logical += info.st_size; files += 1
            if hashes:
                with item.open('rb') as stream:
                    result[relative] = hashlib.file_digest(stream, 'sha256').hexdigest()
        else:
            raise ValueError('special file: ' + str(item))
    return dict(bytes=allocated, logical_bytes=logical, files=files, newest=newest, manifest=result, security=security)


def present(path):
    if not os.path.lexists(path):
        raise ValueError('no longer exists; removed by another program')


def guard(path, days=0, activity=None):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path in (Path(path.anchor), Path.home()):
        raise ValueError('invalid cleanup root')
    present(path)
    for parent in (path, *path.parents):
        if parent.is_symlink() or getattr(parent.lstat(), 'st_file_attributes', 0) & 1024 or (parent / '.keep-local').exists():
            raise ValueError('.keep-local or symlink ancestor: ' + str(parent))
    for reference in activity['threads'] if activity is not None else threads():
        if overlap(path, reference):
            raise ValueError('T3 thread uses ' + reference)
    for reference in activity['references'] if activity is not None else references():
        reference = os.path.normcase(os.path.realpath(reference))
        normalized = os.path.normcase(os.path.realpath(path))
        if reference.startswith(normalized.rstrip(os.sep) + os.sep) or reference == normalized:
            raise ValueError('running process uses ' + reference)
    info = tree(path)
    if info['newest'] > time.time() - days * 86400:
        raise ValueError('recent activity within %s days' % days)
    return info


NOT_A_REPOSITORY = re.compile(r'fatal: (invalid gitfile format|not a git repository \(or any )')
BAD_CONFIG = re.compile(r'fatal: bad config line \d+ in file ')


def disposable_stub(path, message=''):
    marker = Path(path) / '.git'
    if marker.is_file():
        return message.startswith('fatal: invalid gitfile format')
    if not marker.is_dir() or marker.is_symlink():
        return False
    if any(entry.is_symlink() or not entry.is_dir() for entry in marker.iterdir()):
        return False
    return not any(files for name in ('refs', 'logs', 'worktrees') for _, _, files in os.walk(marker / name))


def repo(path, listing='', stub_ok=False):
    present(path)
    shown = git(path, 'rev-parse', '--show-toplevel', check=False)
    if shown.returncode:
        message = shown.stderr.strip()
        if stub_ok and NOT_A_REPOSITORY.match(message) and disposable_stub(path, message):
            return None
        raise RuntimeError(message or 'Git check failed')
    top = shown.stdout.strip()
    if os.path.normcase(os.path.realpath(top)) != os.path.normcase(os.path.realpath(path)):
        if stub_ok and disposable_stub(path):
            return None
        raise ValueError('not a repository root')
    local_refs = git(path, 'for-each-ref', '--format=%(refname)',
                     'refs/worktree/', 'refs/bisect/', 'refs/rewritten/')
    if local_refs:
        raise ValueError('per-worktree refs require preservation: ' + ', '.join(local_refs.splitlines()))
    head = git(path, 'rev-parse', '--verify', '-q', 'HEAD', check=False).stdout.strip()
    target = git(path, 'symbolic-ref', '-q', 'HEAD', check=False).stdout.strip()
    if not head and (not target.startswith('refs/heads/') or git(path, 'for-each-ref', '--format=%(refname)', target)):
        head = git(path, 'rev-parse', 'HEAD')
    branch = git(path, 'symbolic-ref', '-q', '--short', 'HEAD', check=False).stdout.strip()
    dirty = bool(git(path, 'status', '--porcelain=v1', '--untracked-files=all'))
    flags = git(path, 'ls-files', '-v').splitlines()
    dirty = dirty or any(line[:1].islower() or line.startswith('S ') for line in flags)
    dirty = dirty or bool(git(path, 'ls-files', '--unmerged')) or any(
        line.startswith('160000 ') for line in git(path, 'ls-files', '--stage').splitlines())
    ignored = bool(git(path, 'ls-files', '--others', '--ignored', '--exclude-standard'))
    common = Path(git(path, 'rev-parse', '--path-format=absolute', '--git-common-dir'))
    if (common / 'info/grafts').exists() and (common / 'info/grafts').stat().st_size:
        raise ValueError('Git grafts prevent ancestry proof')
    refs = dict((line.split()[1], line.split()[0]) for line in listing.splitlines() if len(line.split()) == 2)
    published = head in refs.values()
    if not published and head:
        containing = set(git(path, 'for-each-ref', '--format=%(objectname)', '--contains', head).splitlines())
        published = bool(containing & set(refs.values()))
    merged = False
    main = refs.get('refs/heads/main') or refs.get('refs/heads/master')
    if main and head and git(path, 'cat-file', '-e', main + '^{commit}', check=False).returncode == 0:
        merged = git(path, 'merge-base', '--is-ancestor', head, main, check=False).returncode == 0
        published = published or merged
    if published and (Path(path) / '.git').is_file():
        history = set()
        for ref in ['HEAD', *(['refs/heads/' + branch] if branch else [])]:
            history.update(git(path, 'reflog', 'show', '--format=%H', ref).splitlines())
        for commit in history - {head}:
            containing = set(git(path, 'for-each-ref', '--format=%(objectname)', '--contains', commit).splitlines())
            if not containing & set(refs.values()):
                raise ValueError('unique reflog history requires preservation: ' + commit)
    linked = [line[9:] for line in git(path, 'worktree', 'list', '--porcelain').splitlines()
              if line.startswith('worktree ') and os.path.isdir(line[9:])
              and os.path.realpath(line[9:]) != os.path.realpath(path)]
    return dict(path=str(path), head=head, branch=branch, dirty=dirty, ignored=ignored,
                stashes=bool(git(path, 'stash', 'list')), published=published, merged=merged,
                linked_worktrees=linked,
                worktree=(Path(path) / '.git').is_file(), common=str(common),
                remote=git(path, 'remote', 'get-url', 'origin', check=False).stdout.strip())


def own_config_fails(path):
    env = {key: value for key, value in os.environ.items() if key not in ('GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS')}
    result = subprocess.run(['git', '-C', str(path), 'worktree', 'list', '--porcelain'], capture_output=True, text=True,
                            env={**env, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull})
    return bool(BAD_CONFIG.match(result.stderr.strip()))


def discover(roots):
    found = set()
    errors, notes = [], []
    for root in roots:
        root = os.path.expandvars(os.path.expanduser(root))
        if not os.path.isdir(root):
            continue
        for base, dirs, files in os.walk(root, onerror=lambda e: notes.append('Unreadable, skipped: ' + str(e))
                                         if isinstance(e, PermissionError) else errors.append(str(e))):
            if '.git' in dirs or '.git' in files:
                try:
                    result = git(base, 'worktree', 'list', '--porcelain')
                except RuntimeError as exc:
                    if NOT_A_REPOSITORY.match(str(exc)):
                        notes.append('Not a repository, skipped: ' + base + ': ' + str(exc))
                    elif BAD_CONFIG.match(str(exc)) and own_config_fails(base):
                        notes.append('Git cannot read this repository, skipped: ' + base + ': ' + str(exc))
                    else:
                        errors.append(base + ': ' + str(exc))
                    dirs[:] = [d for d in dirs if d != '.git']
                    continue
                found.add(os.path.normpath(base))
                found.update(os.path.normpath(line[9:]) for line in result.splitlines() if line.startswith('worktree ')
                             and any(contained(line[9:], r) for r in roots))
                dirs[:] = []
            else:
                dirs[:] = [d for d in dirs if d not in ('node_modules', '.venv', 'venv', '.git', '__pycache__')
                           and not os.path.islink(os.path.join(base, d))]
    return dict(paths=sorted(p for p in found if (Path(p) / '.git').is_file()), errors=errors, notes=notes)


def main(request):
    op = request['operation']
    path = request.get('path')
    if op == 'batch':
        results, rejected = [], set()
        for item in request['requests']:
            if item['operation'] not in ('guard', 'context', 'repositories'):
                raise ValueError('batch only runs read-only checks')
            if item['path'] in rejected:
                results.append(dict(skipped=True))
                continue
            if item['operation'] == 'guard':
                item.setdefault('activity', request.get('activity'))
            try:
                results.append(dict(result=main(item)))
            except Exception as error:
                results.append(dict(error=str(error), value=isinstance(error, ValueError)))
                rejected.add(item['path'])
        return results
    if op == 'discover':
        return discover(request['roots'])
    if op == 'expand':
        import glob
        return sorted(set(p for pattern in request['patterns'] for p in glob.glob(os.path.expandvars(os.path.expanduser(pattern)))))
    if op == 'repo':
        return repo(path, request.get('listing', ''), request.get('stub_ok', False))
    if op == 'context':
        parent = path if Path(path).is_dir() else str(Path(path).parent)
        result = git(parent, 'rev-parse', '--show-toplevel', check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    if op == 'repositories':
        found = []
        if Path(path).is_dir():
            root = extended(path)
            for base, dirs, files in os.walk(root, onerror=lambda e: (_ for _ in ()).throw(e)):
                if '.git' in dirs or '.git' in files:
                    found.append(path + base[len(root):])
                dirs[:] = [name for name in dirs if name != '.git']
        return found
    if op == 'guard':
        return guard(path, request.get('days', 0), request.get('activity'))
    if op == 'activity':
        return dict(threads=threads(), references=references())
    if op == 'manifest':
        return tree(path, True)
    if op == 'bundle':
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory(prefix='coldcleaner-head-') as directory:
            bundle = Path(directory) / 'head.bundle'
            git(path, 'bundle', 'create', str(bundle), 'HEAD')
            with bundle.open('rb') as stream:
                print(json.dumps(dict(sha256=hashlib.file_digest(stream, 'sha256').hexdigest())), flush=True)
            with bundle.open('rb') as stream:
                shutil.copyfileobj(stream, sys.stdout.buffer)
        return None
    if op == 'restore-git':
        import shutil
        import tempfile
        target = Path(path)
        pointer = target / '.git'
        if not pointer.is_file() or pointer.is_symlink():
            raise ValueError('restored worktree pointer is missing or unsafe')
        with tempfile.TemporaryDirectory(prefix='coldcleaner-head-') as directory:
            bundle = Path(directory) / 'head.bundle'
            with bundle.open('xb') as output:
                shutil.copyfileobj(sys.stdin.buffer, output)
            with bundle.open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != request['sha256']:
                    raise ValueError('Git recovery bundle SHA-256 mismatch')
            pointer.unlink()
            git(path, 'init')
            git(path, 'fetch', str(bundle), 'HEAD')
            if git(path, 'rev-parse', 'FETCH_HEAD') != request['head']:
                raise ValueError('Git recovery head differs')
            if request['branch']:
                git(path, 'symbolic-ref', 'HEAD', 'refs/heads/' + request['branch'])
            git(path, 'update-ref', '--no-deref', 'HEAD', request['head']) if not request['branch'] else git(path, 'update-ref', 'HEAD', request['head'])
            git(path, 'read-tree', request['head'])
            if request['remote']:
                git(path, 'remote', 'add', 'origin', request['remote'])
        return dict(restored_git=path)
    if op == 'tar':
        path = extended(path)
        with tarfile.open(fileobj=sys.stdout.buffer, mode='w|', dereference=True) as archive:
            archive.add(path, arcname=Path(path).name)
        return None
    if op == 'restore-stage':
        import tempfile
        target = Path(path)
        if not target.is_absolute() or '..' in target.parts or target in (Path(target.anchor), Path.home()):
            raise ValueError('invalid restore destination')
        if os.path.lexists(target):
            raise FileExistsError('restore destination already exists')
        target.parent.mkdir(parents=True, exist_ok=True)
        return tempfile.mkdtemp(dir=target.parent, prefix='.coldcleaner-restore-')
    if op == 'restore-publish':
        target = Path(request['to'])
        if os.path.lexists(target):
            raise FileExistsError('restore destination already exists')
        os.rename(path, target)
        return dict(restored=str(target))
    if op == 'restore-cleanup':
        import shutil
        shutil.rmtree(path)
        return None
    if op == 'restore':
        import shutil
        import tempfile
        target = Path(path)
        if not target.is_absolute() or '..' in target.parts or target in (Path(target.anchor), Path.home()):
            raise ValueError('invalid restore destination')
        if os.path.lexists(target):
            raise FileExistsError('restore destination already exists')
        target.parent.mkdir(parents=True, exist_ok=True)
        expected = request['manifest']
        roots = {PurePosixPath(name).parts[0] for name in expected}
        if len(roots) != 1:
            raise ValueError('invalid archive root')
        root = roots.pop()
        selected = request.get('member')
        if selected is not None and selected.rstrip('/') not in expected:
            raise ValueError('member is not in the archive')
        wanted = {name: digest for name, digest in expected.items() if selected is None or
                  name == selected.rstrip('/') or name.startswith(selected.rstrip('/') + '/')}
        with tempfile.TemporaryDirectory(dir=target.parent, prefix='.coldcleaner-restore-') as staging:
            found = set()
            metadata = []
            with tarfile.open(fileobj=sys.stdin.buffer, mode='r|') as archive:
                for item in archive:
                    name = item.name.rstrip('/')
                    member_path = PurePosixPath(name)
                    if member_path.is_absolute() or '..' in member_path.parts or '\\' in name or member_path.parts[:1] != (root,):
                        raise ValueError('unsafe archive path')
                    if name not in expected or name in found or not (item.isdir() or item.isfile()):
                        raise ValueError('unexpected archive member')
                    found.add(name)
                    if name not in wanted:
                        continue
                    metadata.append(item)
                    destination = Path(staging).joinpath(*member_path.parts)
                    if item.isdir():
                        destination.mkdir(parents=True, exist_ok=True)
                    else:
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        digest = hashlib.sha256()
                        with archive.extractfile(item) as source, destination.open('xb') as output:
                            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                                output.write(chunk); digest.update(chunk)
                            output.flush(); os.fsync(output.fileno())
                        if digest.hexdigest() != wanted[name]:
                            raise ValueError('restore SHA-256 mismatch')
            if found != set(expected) or not set(wanted) <= found:
                raise ValueError('incomplete archive')
            source = Path(staging) / root
            for item in reversed(metadata):
                destination = Path(staging).joinpath(*PurePosixPath(item.name.rstrip('/')).parts)
                os.chmod(destination, item.mode & 0o777)
                os.utime(destination, (item.mtime, item.mtime))
                security = request.get('security', {}).get(item.name.rstrip('/'))
                if security is not None:
                    if os.name == 'nt':
                        windows_security(destination, security)
                    else:
                        os.chown(destination, security['uid'], security['gid'])
                        os.chmod(destination, security['mode'])
                        os.utime(destination, ns=(security['mtime_ns'], security['mtime_ns']))
            if os.path.lexists(target):
                raise FileExistsError('restore destination already exists')
            os.rename(source, target)
        return dict(restored=str(target))
    if op == 'remove':
        guard(path, request.get('days', 0))
        def verify(source):
            if request.get('manifest') is None and request.get('security') is None:
                return
            current = tree(source, True)
            for key, reason in (('manifest', 'source changed after verified NAS copy'),
                                ('security', 'source security changed after verified NAS copy')):
                actual = {Path(path).name + name[len(source.name):]: value for name, value in current[key].items()}
                if request.get(key) is not None and actual != request[key]:
                    raise ValueError(reason)
        def archived():
            keep = request.get('keep')
            if keep and (not os.path.isfile(keep['file']) or os.path.getsize(keep['file']) != keep['bytes']
                         or keep.get('mount') and not os.path.ismount(keep['mount'])):
                raise ValueError('verified archive is no longer present')
        branch_removed = False
        if request.get('head'):
            state = repo(path, request['listing'])
            if (state['head'] != request['head'] or state['dirty'] or state['stashes'] or not state['published']
                    or state['ignored'] and request.get('manifest') is None):
                raise ValueError('Git proof changed before removal')
            branch = state['branch']
            verify(Path(path))
            branches = git(path, 'worktree', 'list', '--porcelain').splitlines()
            keep_branch = branches.count('branch refs/heads/' + branch) > 1
            archived()
            git(state['common'], 'worktree', 'remove', '--', path)
            if branch and not keep_branch:
                subprocess.run(['git', '--git-dir', state['common'], 'update-ref', '-d',
                                'refs/heads/' + branch, state['head']], check=True, capture_output=True)
                branch_removed = True
        else:
            import uuid
            source = Path(path)
            verify(source)
            quarantine = source.with_name('.' + source.name + '.coldcleaner-removing-' + uuid.uuid4().hex)
            os.rename(source, quarantine)
            try:
                verify(quarantine)
                archived()
            except Exception:
                os.rename(quarantine, source)
                raise
            delete(quarantine)
        return dict(removed=path, branch_removed=branch_removed)
    raise ValueError('unknown operation')
