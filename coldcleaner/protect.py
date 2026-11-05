import base64
import json
import ntpath
import posixpath
import re
import subprocess
from dataclasses import dataclass, field

from . import disk, hosts


SCHEDULERS = r'''
import glob, json, os, subprocess, sys
text = []
errors = []
seen = set()
def read(path):
    path = os.path.realpath(path)
    if path in seen:
        return
    seen.add(path)
    try:
        with open(path) as f:
            text.append(f.read())
    except (OSError, UnicodeError) as exc:
        errors.append(str(exc))
if sys.platform == 'darwin':
    import plistlib
    for root in ('~/Library/LaunchAgents', '/Library/LaunchAgents', '/Library/LaunchDaemons'):
        for path in glob.glob(os.path.expanduser(root) + '/*.plist'):
            try:
                with open(path, 'rb') as f:
                    obj = plistlib.load(f)
                text.append(json.dumps(obj))
            except Exception as exc:
                errors.append(str(exc))
else:
    result = subprocess.run(['systemctl', '--user', 'cat', '*'], capture_output=True, text=True)
    text.append(result.stdout)
    if result.returncode and 'No files found' not in result.stderr:
        errors.append('user systemd inventory failed: ' + result.stderr.strip())
    for root in ('/etc/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system'):
        for base, dirs, files in os.walk(root):
            for name in files:
                path = os.path.join(base, name)
                read(path)
    for path in glob.glob('/etc/cron.d/*') + glob.glob('/etc/crontab'):
        read(path)
r = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
text.append(r.stdout)
if r.returncode and 'no crontab' not in r.stderr.lower():
    errors.append('crontab inventory failed: ' + r.stderr.strip())
print(json.dumps(dict(home=os.path.expanduser('~'), text='\n'.join(text), errors=errors)))
'''


def extract_paths(text, home, windows=False, environment=None):
    text = text.replace('\\/', '/').replace('\\\\', '\\')
    text = re.sub(r'\$(?:\{HOME\}|HOME\b)', lambda _: home, text)
    text = text.replace('%h', home).replace('~/', home.rstrip('/') + '/')
    text = re.sub(r'(?<=[=\s])~(?=\s|$)', lambda _: home, text)
    for key, value in (environment or {}).items():
        text = re.sub('%' + re.escape(key) + '%', lambda _: value, text, flags=re.I)
        text = re.sub(r'\$env:' + re.escape(key), lambda _: value, text, flags=re.I)
    pattern = r'[A-Za-z]:[\\/][^\s\"<>|;,}]*' if windows else r'/(?:[^\s\"\'<>;,}\\]|\\ )+'
    paths = set(re.findall(pattern, text))
    quoted = r'[\"\']([A-Za-z]:[\\/][^\"\']+)[\"\']' if windows else r'[\"\'](/[^\"\'\n]+)[\"\']'
    paths.update(re.findall(quoted, text))
    paths.update(re.findall(r'<string>(/[^<]+)</string>', text))
    if not windows and re.search(r'''(?:^|[=\s"'])/(?:$|[\s"'])''', text, re.M):
        paths.add('/')
    return {p.replace('\\ ', ' ').rstrip('):]') for p in paths if p != '//'}


def overlaps(left, right, windows=False):
    module = ntpath if windows else posixpath
    left, right = module.normcase(module.normpath(left)), module.normcase(module.normpath(right))
    try:
        return module.commonpath((left, right)) in (left, right)
    except ValueError:
        return False


def broad_reference(path, home, windows=False):
    module = ntpath if windows else posixpath
    path, home = module.normcase(module.normpath(path)), module.normcase(module.normpath(home))
    if path == home:
        return True
    if windows:
        return path in ('c:\\', r'c:\users', r'c:\windows') or (
            module.dirname(path) == 'c:\\' and module.basename(path).startswith('program files'))
    return path in ('/', '/usr', '/etc', '/var', '/opt', '/bin', '/sbin', '/tmp',
                    '/Users', '/home', '/System', '/Library') or (
        module.dirname(path) == '/' and module.basename(path).startswith('lib'))


POSIX_BATCH = r'''
import codecs, json, os, re, shutil, signal, subprocess, sys, time
from pathlib import Path
paths, allow_git, open_files = json.load(sys.stdin)
deadline = time.monotonic() + 840
def timed_out(*args):
    raise TimeoutError('protection check timed out')
signal.signal(signal.SIGALRM, timed_out)
signal.setitimer(signal.ITIMER_REAL, 840)
def check_time():
    if time.monotonic() >= deadline:
        raise TimeoutError('protection check timed out')
def check(path):
    check_time()
    p = Path(path)
    p.lstat()
    if p.is_symlink() or any(x.is_symlink() for x in p.parents):
        return 'symlink'
    if not allow_git and p.name == '.git':
        return 'git metadata requires GitHub safety review'
    if any((x / '.keep-local').exists() for x in (p, *p.parents)):
        return '.keep-local'
    for base, dirs, files in (os.walk(p, onerror=lambda e: (_ for _ in ()).throw(e)) if p.is_dir() else []):
        check_time()
        if not allow_git and ('.git' in files or '.git' in dirs):
            return 'git metadata requires GitHub safety review'
        if '.keep-local' in files or '.keep-local' in dirs:
            return '.keep-local'
        if any(os.path.islink(os.path.join(base, n)) for n in dirs + files):
            return 'symlink descendant'
    return ''
reasons = {}
pending = []
try:
    for path in paths:
        try:
            reason = check(path)
            if reason:
                reasons[path] = reason
            else:
                pending.append(path)
        except TimeoutError:
            raise
        except Exception as exc:
            reasons[path] = 'protection check incomplete: ' + str(exc)
    if pending and not open_files:
        reasons.update(dict.fromkeys(pending, ''))
    elif pending:
        check_time()
        if not shutil.which('lsof'):
            reasons.update(dict.fromkeys(pending, 'lsof unavailable'))
        else:
            result = subprocess.run(['lsof', '-nP', '-Fn'], capture_output=True,
                timeout=min(30, deadline - time.monotonic()))
            mounts = []
            unknown_error = False
            for line in os.fsdecode(result.stderr).splitlines():
                warning = re.fullmatch(r"lsof: WARNING: can't stat\(\) \S+ file system (/[^\r\n]+)", line)
                if warning:
                    mounts.append(os.path.normpath(warning[1]))
                elif not (mounts and (line.strip() == 'Output information may be incomplete.'
                        or re.fullmatch(r'\s+assuming "dev=[0-9]+" from mount table', line))):
                    unknown_error = True
            if unknown_error or result.returncode != 0 and not (result.returncode == 1 and not result.stdout):
                reasons.update(dict.fromkeys(pending, 'lsof check incomplete'))
            else:
                control_names = str.maketrans({code: '^' + chr(code ^ 64) for code in (*range(32), 127)})
                def visible_name(name):
                    previous = None
                    while name != previous:
                        previous = name
                        name = re.sub(rb"\\(?:[abfnrtv\\'\"]|x[0-9a-fA-F]{2}|[0-7]{1,3})",
                                      lambda match: codecs.escape_decode(match[0])[0], name)
                    return os.fsdecode(name.replace(bytes([92]), b'')).translate(control_names)
                open_paths = {visible_name(line[1:]) for line in result.stdout.splitlines()
                              if line.startswith(b'n')}
                for path in pending:
                    check_time()
                    normalized = os.path.normpath(path)
                    if any(os.path.commonpath((normalized, mount)) in (normalized, mount) for mount in mounts):
                        reasons[path] = 'lsof check incomplete'
                    else:
                        visible = visible_name(os.fsencode(normalized))
                        reasons[path] = 'open files' if any(
                            item == visible or item.startswith(visible.rstrip('/') + '/') for item in open_paths) else ''
except (TimeoutError, subprocess.TimeoutExpired):
    reason = 'protection check timed out' if time.monotonic() >= deadline else 'lsof check timed out'
    reasons.update({path: reason for path in paths if path not in reasons})
except Exception as exc:
    reasons.update({path: 'protection check incomplete: ' + str(exc) for path in paths if path not in reasons})
finally:
    signal.setitimer(signal.ITIMER_REAL, 0)
print(json.dumps(reasons))
'''

POWERSHELL_BATCH = r'''$ErrorActionPreference='Stop'
$paths=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('PATHS_BASE64')))
$allowGit=ALLOW_GIT
$deadline=[DateTime]::UtcNow.AddSeconds(895)
function Check-Time {
if([DateTime]::UtcNow -ge $deadline) {throw 'protection check timed out'}
}
function Check-Path($path) {
Check-Time
$root=Get-Item -LiteralPath $path -Force -ErrorAction Stop
$p=$root
if(!$p.PSIsContainer) {$p=$p.Directory}
while($null -ne $p) {
Check-Time
if($p.Attributes -band [IO.FileAttributes]::ReparsePoint) {return 'reparse point'}
if(Test-Path -LiteralPath (Join-Path $p.FullName '.keep-local') -ErrorAction Stop) {return '.keep-local'}
$p=$p.Parent
}
$pending=New-Object 'System.Collections.Generic.Stack[System.IO.FileSystemInfo]'
$pending.Push($root)
while($pending.Count) {
Check-Time
$item=$pending.Pop()
if($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {return 'reparse point'}
if($item.Name -eq '.keep-local') {return '.keep-local'}
if(!$allowGit -and $item.Name -eq '.git') {return 'git metadata requires GitHub safety review'}
if($item.PSIsContainer) {
foreach($child in Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop) {
Check-Time
$pending.Push($child)
}
}
}
return ''
}
$reasons=@{}
foreach($path in $paths) {
try {$reasons[$path]=Check-Path $path}
catch {$reasons[$path]=$_.Exception.Message}
}
ConvertTo-Json -InputObject $reasons -Compress
'''


@dataclass
class Protection:
    host: hosts.Host
    home: str
    paths: set[str]
    errors: list[str]
    broad_paths: set[str] = field(default_factory=set)

    def reason(self, path, *, allow_git=False):
        return self.batch([path], allow_git=allow_git)[path]

    def batch(self, paths, *, allow_git=False, open_files=True):
        reasons = {}
        windows = self.host.kind == 'powershell'
        module = ntpath if windows else posixpath
        for path in paths:
            if self.errors:
                reasons[path] = 'protection inventory incomplete: ' + '; '.join(self.errors)
                continue
            normalized = module.normcase(module.normpath(path))
            referenced = sorted(item for item in self.paths
                if (normalized == module.normcase(module.normpath(item))
                    if item in self.broad_paths or broad_reference(item, self.home, windows) else overlaps(path, item, windows)))
            if referenced:
                reasons[path] = 'scheduler references ' + ', '.join(referenced[:3])
        pending = list(dict.fromkeys(path for path in paths if path not in reasons))
        if not pending:
            return reasons
        try:
            if windows:
                encoded = base64.b64encode(json.dumps(pending).encode()).decode()
                script = POWERSHELL_BATCH.replace('PATHS_BASE64', encoded).replace('ALLOW_GIT', '$true' if allow_git else '$false')
                result = disk.powershell(self.host, script, check=False, timeout=900)
                if result.returncode:
                    detail = result.stderr.decode(errors='replace').strip() or 'protection check failed'
                    return dict(reasons, **{path: detail for path in pending})
                checked = json.loads(result.stdout)
            else:
                checked = disk.python(self.host, POSIX_BATCH, timeout=900,
                    stdin_bytes=json.dumps([pending, allow_git, open_files]).encode())
            if not isinstance(checked, dict):
                raise ValueError('invalid protection response')
            for path in pending:
                reason = checked.get(path)
                reasons[path] = reason if isinstance(reason, str) else 'protection check incomplete: missing or invalid result'
        except (TimeoutError, subprocess.TimeoutExpired):
            reasons.update({path: 'protection check timed out' for path in pending})
        except Exception as exc:
            reasons.update({path: 'protection check incomplete: ' + str(exc) for path in pending})
        return reasons


def psquote(value):
    return "'" + value.replace("'", "''") + "'"


def collect(host):
    if host.kind == 'powershell':
        script = r'''$ErrorActionPreference='Stop'
$actions=@(Get-ScheduledTask -ErrorAction Stop | ForEach-Object { $_.Actions } | Select-Object Execute,Arguments,WorkingDirectory)
$envs=@{}; Get-ChildItem Env: | Where-Object { $_.Value -match '^[A-Za-z]:[\\/]' } | ForEach-Object { $envs[$_.Name]=$_.Value }
@{home=$env:USERPROFILE;text=($actions | ConvertTo-Json -Depth 6);env=$envs;errors=@()} | ConvertTo-Json -Depth 6 -Compress'''
        obj = json.loads(disk.powershell(host, script, timeout=120).stdout)
    else:
        obj = disk.python(host, SCHEDULERS)
    paths = extract_paths(obj['text'], obj['home'], host.kind == 'powershell', obj.get('env'))
    for path in tuple(paths):
        if any(c in path for c in '*?['):
            module = ntpath if host.kind == 'powershell' else posixpath
            paths.add(module.dirname(re.split(r'[*?\[]', path)[0]))
    return Protection(host, obj['home'], paths, obj['errors'])
