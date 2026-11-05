import json
import ntpath
import os
import posixpath
import re
import shlex
import subprocess
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone

from . import disk, gitsafe, hosts, protect, rules, store

REFERENCES = r'''
import os, re
def running_references():
    found = set()
    def add(ref):
        ref = ref.rstrip('/')
        while ref and ref not in found:
            found.add(ref)
            ref = os.path.dirname(ref)
    if not os.path.isdir('/proc'):
        return found
    for pid in (name for name in os.listdir('/proc') if name.isdigit() and int(name) != os.getpid()):
        for name in ('cmdline', 'environ'):
            try:
                with open('/proc/%s/%s' % (pid, name), 'rb') as stream:
                    text = stream.read().decode('utf-8', 'replace')
            except OSError:
                continue
            for piece in text.split('\0'):
                for match in re.finditer(r'/[^\s:=\'";,&|()<>]+', piece):
                    add(match.group())
                if '/' in piece:
                    add(piece[piece.index('/'):])
        try:
            add(os.readlink('/proc/%s/cwd' % pid))
        except OSError:
            pass
    return found
'''

IN_USE = REFERENCES + r'''
import json, sys
found = running_references()
print(json.dumps([p for p in json.load(sys.stdin) if os.path.normpath(p) in found]))
'''

INVENTORY = REFERENCES + r'''
import fnmatch, glob, json, os, pwd, re, stat, subprocess, sys, time
from pathlib import Path
config = json.load(sys.stdin)
items = []
errors = []
def error(exc, path=None):
    reason = ('unreadable: ' if isinstance(exc, PermissionError) else '') + str(exc)
    errors.append(dict(path=getattr(exc, 'filename', None) or path, reason=reason))
def expand(pattern):
    if not glob.has_magic(pattern):
        try:
            os.lstat(pattern)
        except (FileNotFoundError, NotADirectoryError):
            return
        except OSError as exc:
            error(exc, pattern)
            return
        yield pattern
        return
    parent, name = os.path.split(pattern)
    parents = expand(parent) if glob.has_magic(parent) else [parent]
    for base in parents:
        if not glob.has_magic(name):
            yield from expand(os.path.join(base, name))
            continue
        try:
            names = os.listdir(base or '.')
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as exc:
            error(exc, base or '.')
            continue
        for match in fnmatch.filter(names, name):
            if name.startswith('.') or not match.startswith('.'):
                yield os.path.join(base, match)
def last_run_failed(path):
    records = []
    try:
        with open(os.path.join(path, '.cold', 'verify-history.jsonl'), encoding='utf-8', errors='replace') as stream:
            for line in stream:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict):
                    records.append(record)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return bool(records) and any(r.get('status') == 'fail' for r in records if r.get('run_id') == records[-1].get('run_id'))
referenced = None
started_at = last_progress = time.monotonic()
scanned_dirs = scanned_files = scanned_bytes = completed = 0
total = 0
batch_started = started_at
def progress(force=False):
    global last_progress
    now = time.monotonic()
    if not force and now - last_progress < 5:
        return
    elapsed = now - started_at
    eta = ('%.1fs' % ((now - batch_started) / completed * (total - completed))
           if completed and total > completed else 'unknown')
    print('[scan] %s: dirs=%d files=%d bytes=%d elapsed=%.1fs ETA=%s' %
          (pattern, scanned_dirs, scanned_files, scanned_bytes, elapsed, eta), file=sys.stderr, flush=True)
    last_progress = now
def scan(path, skip_git, owner_uid=None):
    global scanned_dirs, scanned_files, scanned_bytes
    started = len(errors)
    root = os.lstat(path)
    def scan_error(exc, error_path):
        if not (owner_uid is not None and root.st_uid != owner_uid and isinstance(exc, PermissionError)):
            error(exc, error_path)
    newest, size, owners = root.st_mtime, 0, {root.st_uid}
    if stat.S_ISLNK(root.st_mode):
        raise ValueError('symlink')
    if stat.S_ISDIR(root.st_mode):
        scanned_dirs += 1
        pending = [path]
        while pending:
            base = pending.pop()
            if base != path and os.path.islink(base):
                continue
            try:
                with os.scandir(base) as entries:
                    for entry in entries:
                        if skip_git and entry.name == '.git':
                            continue
                        try:
                            st = entry.stat(follow_symlinks=False)
                        except OSError as exc:
                            scan_error(exc, entry.path)
                            try:
                                if entry.is_dir(follow_symlinks=False):
                                    pending.append(entry.path)
                            except OSError:
                                pass
                            continue
                        newest = max(newest, st.st_mtime)
                        owners.add(st.st_uid)
                        if stat.S_ISDIR(st.st_mode):
                            scanned_dirs += 1
                            pending.append(entry.path)
                        else:
                            scanned_files += 1
                            size += st.st_size
                            scanned_bytes += st.st_size
                        progress()
            except OSError as exc:
                scan_error(exc, base)
            progress()
    else:
        size = root.st_size
        scanned_files += 1
        scanned_bytes += size
    if len(errors) == started:
        return dict(path=path, bytes=size, newest=newest, owners=sorted(owners))
for tier, entries in config.items():
    for entry in entries:
        pattern = os.path.expanduser(entry['path'])
        progress(True)
        for root in expand(pattern):
            if entry.get('clone') and not os.path.exists(os.path.join(root, '.git')):
                continue
            try:
                paths = [root]
                contents = tier == 'cache' and not entry.get('command') and not entry.get('clone') and stat.S_ISDIR(os.lstat(root).st_mode)
                if contents and entry.get('days'):
                    paths = [os.path.join(root, p) for p in os.listdir(root)]
                    contents = False
            except OSError as exc:
                error(exc, root)
                continue
            completed, total = 0, len(paths)
            batch_started = time.monotonic()
            for path in paths:
                try:
                    obj = scan(path, tier in ('worktree', 'project') or bool(entry.get('clone')), pwd.getpwnam(entry['owner']).pw_uid if entry.get('owner') else None)
                    if obj is None:
                        continue
                    obj.update(tier=tier, contents=contents, command=entry.get('command'),
                               days=entry.get('days', 0), runner=entry.get('runner', False), owner=entry.get('owner'))
                    if entry.get('clone'):
                        obj['clone'] = True
                    if tier == 'cache' and not entry.get('clone') and any((p / '.git').exists() for p in (Path(path), *Path(path).parents)):
                        obj['blocked'] = 'git metadata requires GitHub safety review'
                    if tier == 'cache':
                        if referenced is None:
                            referenced = running_references()
                        if os.path.normpath(path) in referenced:
                            obj['blocked'] = 'in use by a running process'
                        if entry.get('failed_days') and last_run_failed(path):
                            obj['days'] = max(obj['days'], entry['failed_days'])
                    if obj['owner'] and obj['owners'] != [pwd.getpwnam(obj['owner']).pw_uid]:
                        obj['blocked'] = 'not entirely owned by ' + obj['owner']
                    if tier in ('worktree', 'project'):
                        result = subprocess.run(['git', '-C', path, 'log', '-1', '--format=%ct'], capture_output=True, text=True)
                        if result.returncode == 0 and result.stdout.strip():
                            obj['newest'] = max(obj['newest'], int(result.stdout.strip()))
                    items.append(obj)
                except Exception as exc:
                    error(exc, path)
                finally:
                    completed += 1
                    progress()
        progress(True)
print(json.dumps(dict(items=items, errors=errors)))
'''


WORKTREE_MERGED_DAYS = 1
WORKTREE_IGNORED_KB = 1024


def describe(exc):
    if isinstance(exc, subprocess.CalledProcessError):
        detail = (exc.stderr or b'').decode(errors='replace').strip()
        return '\n'.join(detail.splitlines()[:3])[:1000] or f'command exited with status {exc.returncode}'
    return str(exc)


@dataclass(frozen=True)
class Candidate:
    path: str
    bytes: int
    newest: float
    tier: str
    contents: bool = False
    command: str | None = None
    days: int = 0
    runner: bool = False
    owner: str | None = None
    blocked: str = ''
    clone: bool = False


def inventory(host, config):
    items, errors = [], []
    for tier, entries in config.items():
        for entry in entries:
            try:
                found, skipped = inventory_entry(host, {tier: [entry]})
                items.extend(found)
                errors.extend(skipped)
            except Exception as exc:
                errors.append(dict(path=entry['path'], reason=str(exc)))
    return items, errors


def inventory_entry(host, config):
    if host.kind != 'powershell':
        obj = disk.python(host, INVENTORY, timeout=900, progress=True,
                          stdin_bytes=json.dumps(config).encode())
        for entry in obj['items']:
            entry.pop('owners', None)
    else:
        encoded = protect.psquote(json.dumps(config))
        script = r'''$ErrorActionPreference='Stop'
$config=ConvertFrom-Json CONFIG
$rows=@(); $errors=@()
foreach($tier in $config.PSObject.Properties) {
foreach($entry in $tier.Value) {
$pattern=[Environment]::ExpandEnvironmentVariables($entry.path)
foreach($root in @(Get-Item -Path $pattern -Force -ErrorAction SilentlyContinue)) {
$paths=@($root); $contents=($tier.Name -eq 'cache' -and !$entry.command -and $root.PSIsContainer)
if($contents -and $entry.days) {$paths=@(Get-ChildItem -LiteralPath $root.FullName -Force); $contents=$false}
foreach($p in $paths) {try {
if($p.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'reparse point'}
$all=@($p); if($p.PSIsContainer) {$all+=@(Get-ChildItem -LiteralPath $p.FullName -Force -Recurse -ErrorAction Stop)}
$size=($all | Where-Object {!$_.PSIsContainer} | Measure-Object Length -Sum).Sum
$newest=($all | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1).LastWriteTimeUtc
$rows+=@{path=$p.FullName;bytes=[long]$size;newest=([DateTimeOffset]$newest).ToUnixTimeSeconds();tier=$tier.Name;contents=$contents;command=$entry.command;days=[int]$entry.days;runner=[bool]$entry.runner}
} catch {$errors+=@{path=$p.FullName;reason=$_.Exception.Message}}}
}}}
@{items=$rows;errors=$errors} | ConvertTo-Json -Depth 6 -Compress
'''.replace('CONFIG', encoded)
        obj = json.loads(disk.powershell(host, script, timeout=900).stdout)
    return [Candidate(**entry) for entry in obj['items']], obj['errors']


def git_allowed(candidate):
    return candidate.tier in ('worktree', 'project') or candidate.clone


def idle(candidate, days, now=None):
    return candidate.newest <= (time.time() if now is None else now) - days * 86400


def runner_busy(host):
    if host.kind == 'powershell':
        script = "if(Get-Process -Name 'Runner.Worker' -ErrorAction SilentlyContinue) {'busy'} else {'idle'}"
        result = disk.powershell(host, script, timeout=60)
        return result.stdout.decode().strip() != 'idle'
    result = hosts.run(host, "pgrep -f 'Runner[.]Worker'", check=False, timeout=60)
    if result.returncode not in (0, 1):
        raise RuntimeError('runner process inventory incomplete')
    return result.returncode == 0


def remove(host, item):
    if host.kind == 'powershell':
        path = protect.psquote(item.path)
        action = f'Get-ChildItem -LiteralPath {path} -Force | Remove-Item -Recurse -Force -ErrorAction Stop' if item.contents else f'Remove-Item -LiteralPath {path} -Recurse -Force -ErrorAction Stop'
        script = "$ErrorActionPreference='Stop'; " + action
    elif item.command:
        tool = shlex.quote(item.command.split()[0])
        command = item.command.replace('{path}', shlex.quote(item.path))
        script = f'command -v {tool} >/dev/null && {command}'
    else:
        path = shlex.quote(item.path)
        script = f'find {path} -mindepth 1 -maxdepth 1 -exec rm -rf -- {{}} +' if item.contents else f'rm -rf -- {path}'
    (disk.powershell if host.kind == 'powershell' else hosts.run)(host, script, timeout=3600)


class Cleaner:
    def __init__(self, host, config, apply, protection, report, gitsafe=gitsafe, store=store):
        self.host, self.config, self.apply = host, config, apply
        self.protection, self.report = protection, report
        self.live_protection = None
        self.git, self.store = gitsafe, store
        self.host_rules = config['hosts'].get(host.name, {})
        self.repos = []
        self.accounted = set()
        self.accounted_parents = set()
        self.checked = None
        self.rechecked = {}

    def log(self, tier, path, action, size=0, reason=''):
        self.report.actions.append(dict(tier=tier, path=path, action=action, bytes=size, reason=reason))

    def check_batch(self, items):
        self.live_protection = None
        items = [item for item in items if not item.blocked]
        self.rechecked = {}
        self.checked = {}
        live = rules.enabled(self.config, items[0].tier, self.apply) if items else False
        for allow_git in (False, True):
            group = [item for item in items if git_allowed(item) is allow_git]
            if group:
                self.checked.update(self.protection.batch([item.path for item in group], allow_git=allow_git))
                if live:
                    self.recheck(group[0].tier, [item for item in group if not self.checked.get(item.path)], allow_git)

    def recheck(self, tier, items, allow_git):
        if not items:
            return
        paths = [item.path for item in items]
        try:
            if self.live_protection is None:
                try:
                    self.live_protection = protect.collect(self.host)
                except Exception as exc:
                    self.live_protection = protect.Protection(self.host, self.protection.home, set(), [str(exc)])
            current, _ = inventory_entry(self.host, {tier: [{'path': item.path, 'owner': item.owner, 'clone': item.clone} for item in items]})
            reasons = self.live_protection.batch(paths, allow_git=allow_git)
        except Exception as exc:
            self.rechecked = dict.fromkeys(paths, 'protection check incomplete: ' + str(exc))
            return
        current = {found.path: found for found in current}
        changed = 'candidate changed or could not be revalidated'
        for item in items:
            found = current.get(item.path)
            days = item.days or self.config.get(tier + '_idle_days', 0)
            if found is None or found.blocked or not idle(found, days):
                self.rechecked[item.path] = changed
            else:
                self.rechecked[item.path] = reasons.get(item.path, changed)

    def safe(self, item, *, recheck=False):
        try:
            reason = item.blocked
            if not reason:
                protection = self.protection
                if recheck:
                    if self.live_protection is None:
                        try:
                            self.live_protection = protect.collect(self.host)
                        except Exception as exc:
                            self.live_protection = protect.Protection(self.host, protection.home, set(), [str(exc)])
                    protection = self.live_protection
                reason = (protection.reason(item.path, allow_git=git_allowed(item))
                    if recheck or self.checked is None else self.checked.get(item.path,
                        'protection check incomplete: missing or invalid result'))
            if not reason and item.runner and runner_busy(self.host):
                reason = 'Runner.Worker is running'
        except Exception as exc:
            reason = 'protection check incomplete: ' + str(exc)
        if reason:
            self.log(item.tier, item.path, 'skip', item.bytes, reason)
            return False
        return True

    def approved(self, item, live):
        if not self.safe(item):
            return False
        reason = self.rechecked.get(item.path, 'candidate changed or could not be revalidated') if live else ''
        if reason:
            self.log(item.tier, item.path, 'skip', item.bytes, reason)
        return not reason

    def act(self, item, description, operation):
        live = rules.enabled(self.config, item.tier, self.apply)
        if not self.approved(item, live):
            return
        if live:
            try:
                operation()
            except Exception as exc:
                self.log(item.tier, item.path, 'error', item.bytes, describe(exc))
                return
        self.record(item, description, live)

    def record(self, item, description, live):
        module = ntpath if self.host.kind == 'powershell' else posixpath
        path = module.normcase(module.normpath(item.path))
        parents = {path}
        parent = module.dirname(path)
        while parent not in parents:
            parents.add(parent)
            parent = module.dirname(parent)
        size = 0 if path in self.accounted_parents or self.accounted & parents else item.bytes
        self.accounted.add(path)
        self.accounted_parents.update(parents)
        self.log(item.tier, item.path, description if live else 'would ' + description, size)

    def candidates(self, tier, entries):
        items, errors = inventory(self.host, {tier: entries})
        for error in errors:
            action = 'unreadable' if error['reason'].startswith('unreadable: ') else 'skip'
            self.log(tier, error['path'], action, reason=error['reason'])
            if action != 'unreadable' and error['reason'] not in ('symlink', 'reparse point'):
                self.report.errors.append(f"{tier} inventory incomplete: {error['path']}: {error['reason']}")
        return items

    def cache(self):
        started = len(self.report.actions)
        now = time.time()
        items = self.candidates('cache', self.host_rules.get('cache', []))
        self.check_batch([item for item in items if idle(item, item.days)])
        live = rules.enabled(self.config, 'cache', self.apply)
        swept = []
        for item in items:
            if not idle(item, item.days):
                self.log('cache', item.path, 'skip', item.bytes, f'active within {item.days} days')
            elif item.clone:
                self.clone(item)
            elif live and self.host.kind != 'powershell' and not item.command and not item.contents:
                if self.approved(item, live):
                    swept.append(item)
            else:
                self.act(item, 'clean cache', lambda: remove(self.host, item))
        try:
            if swept:
                busy = self.in_use(swept)
                for item in swept:
                    if item.path in busy:
                        self.log('cache', item.path, 'skip', item.bytes, 'in use by a running process')
                swept = [item for item in swept if item.path not in busy]
            if swept:
                self.sweep(swept)
        finally:
            ages = {item.path: f'age {max(0, now - item.newest) / 3600:.2f} hours; minimum {item.days * 24} hours'
                    for item in items}
            for row in self.report.actions[started:]:
                if row['path'] in ages:
                    row['age'] = ages[row['path']]

    def clone(self, item):
        if item.blocked:
            return self.act(item, 'clean cache', None)
        state = self.git.inspect(self.host, item.path)
        if state.verdict != 'on_github':
            return self.log('cache', item.path, 'skip', item.bytes, 'clone not fully on GitHub: ' + state.verdict)
        if self.clone_has_local_data(item):
            return self.log('cache', item.path, 'skip', item.bytes, 'clone contains local or ignored data')
        self.act(item, 'clean cache', lambda: self.remove_clone(item))

    def clone_has_local_data(self, item):
        path = shlex.quote(item.path)
        status = hosts.run(self.host, f'git -C {path} status --porcelain=v1 --ignored --untracked-files=all --ignore-submodules=none', timeout=180).stdout
        entries = hosts.run(self.host, f'git -C {path} ls-files --stage -z', timeout=180).stdout
        return bool(status) or any(entry.startswith(b'160000 ') for entry in entries.split(b'\0'))

    def in_use(self, items):
        paths = json.dumps([item.path for item in items]).encode()
        return set(disk.python(self.host, IN_USE, timeout=300, stdin_bytes=paths))

    def remove_clone(self, item):
        verdict = self.git.inspect(self.host, item.path).verdict
        if verdict != 'on_github':
            raise RuntimeError('git safety changed before removal: ' + verdict)
        if self.clone_has_local_data(item):
            raise RuntimeError('clone contains local or ignored data')
        if self.in_use([item]):
            raise RuntimeError('in use by a running process')
        remove(self.host, item)

    def sweep(self, swept):
        paths = b''.join(os.fsencode(item.path) + b'\0' for item in swept)
        try:
            hosts.run(self.host, 'xargs -0 rm -rf --', stdin_bytes=paths, timeout=3600)
        except Exception:
            script = "while IFS= read -r -d '' p; do [ -e \"$p\" ] || [ -L \"$p\" ] || printf '%s\\0' \"$p\"; done"
            gone = set(hosts.run(self.host, script, stdin_bytes=paths, timeout=3600).stdout.split(b'\0'))
            for item in swept:
                if os.fsencode(item.path) in gone:
                    self.record(item, 'clean cache', True)
            raise
        for item in swept:
            self.record(item, 'clean cache', True)

    def github(self):
        if self.host.kind == 'powershell':
            raise NotImplementedError('GitHub inspection requires POSIX or WSL; native Windows repos retained')
        self.repos = []
        unreadable = []
        with gitsafe.clean_worktree_cache(self.host):
            for path in self.git.find_repos(self.host, self.host_rules.get('roots', []), unreadable):
                try:
                    state = self.git.inspect(self.host, path)
                    if state.verdict == 'backup_needed':
                        live = rules.enabled(self.config, 'github', self.apply)
                        messages = self.git.backup(self.host, path, apply=live)
                        reason = (f'{len(messages)} backup refs' if messages and
                                  all(message.startswith('refs/') for message in messages) else '; '.join(messages))
                        self.log('github', path, 'backup' if live else 'would backup', reason=reason)
                        if live:
                            state = self.git.inspect(self.host, path)
                    self.repos.append(state)
                except Exception as exc:
                    self.log('github', path, 'skip', reason=str(exc))
        for path in unreadable:
            self.log('github', path, 'skip', reason='cannot read directory')
            self.report.errors.append('Git discovery incomplete: cannot read directory ' + path)
        self.report.repos = self.repos
        self.report.summary = self.git.summary(self.repos)

    def worktree(self):
        planned, states = [], {}
        with gitsafe.clean_worktree_cache(self.host):
            for state in self.repos:
                if not state.is_worktree:
                    continue
                if not self.within_roots(state.path):
                    self.log('worktree', state.path, 'skip', reason='outside configured project roots')
                    continue
                try:
                    reason, days = self.worktree_rule(state)
                except Exception as exc:
                    reason = 'worktree check failed: ' + describe(exc)
                    self.report.errors.append(state.path + ': ' + reason)
                if reason:
                    self.log('worktree', state.path, 'skip', reason=reason)
                    continue
                states[state.path] = (state, days)
        if not states:
            return
        for item in self.candidates('worktree', [{'path': path} for path in states]):
            item = replace(item, days=states[item.path][1])
            if idle(item, item.days):
                planned.append(item)
            else:
                self.log('worktree', item.path, 'skip', item.bytes, 'recent worktree activity')
        self.check_batch(planned)
        for item in planned:
            self.act(item, 'remove worktree', lambda: self.remove_worktree(item))

    def worktree_rule(self, state):
        check = self.git.worktree_check(self.host, state.path, WORKTREE_IGNORED_KB)
        if not check.clean:
            return 'local changes', 0
        if check.ignored_kb < 0:
            return 'ignored files could not be measured', 0
        if check.ignored_kb > WORKTREE_IGNORED_KB:
            return f'ignored files over {WORKTREE_IGNORED_KB} KB; kept until they can be archived', 0
        if check.ignored_kb:
            return 'ignored files require a verified archive; retained', 0
        if check.merged and state.verdict in ('on_github', 'backup_needed') and gitsafe._is_github_url(state.remote_url):
            return '', WORKTREE_MERGED_DAYS
        if state.verdict == 'on_github':
            return '', self.config['worktree_idle_days']
        return 'needs attention: ' + state.verdict, 0

    def within_roots(self, path):
        module = ntpath if self.host.kind == 'powershell' else posixpath
        for root in self.host_rules.get('roots', []):
            root = root.replace('~/', self.protection.home.rstrip('/') + '/')
            root = re.sub('%USERPROFILE%', lambda _: self.protection.home, root, flags=re.I)
            root, path = module.normcase(module.normpath(root)), module.normcase(module.normpath(path))
            try:
                if module.commonpath((root, path)) == root:
                    return True
            except ValueError:
                pass
        return False

    def remove_worktree(self, item):
        state = self.git.inspect(self.host, item.path)
        reason, days = self.worktree_rule(state)
        if reason or days > item.days:
            raise RuntimeError('git safety changed before removal: ' + (reason or 'no longer merged'))
        delete_branch = state.verdict == 'on_github'
        if self.host.kind == 'powershell':
            path = protect.psquote(state.path)
            script = f'''$ErrorActionPreference='Stop'
$branch=git -C {path} symbolic-ref -q --short HEAD
$common=git -C {path} rev-parse --path-format=absolute --git-common-dir
if($LASTEXITCODE -ne 0) {{throw 'cannot resolve common git dir'}}
git --git-dir=$common worktree remove -- {path}
if($LASTEXITCODE -ne 0) {{throw 'worktree removal failed'}}
if($branch -and ${str(delete_branch).lower()}) {{git --git-dir=$common branch -d -- $branch}}
'''
            disk.powershell(self.host, script)
            return
        path = shlex.quote(state.path)
        script = f'''set -eu
branch=$(git -C {path} symbolic-ref -q --short HEAD || true)
common=$(git -C {path} rev-parse --path-format=absolute --git-common-dir)
git --git-dir="$common" worktree remove -- {path}
if [ "{delete_branch}" = True ] && [ -n "$branch" ]; then git --git-dir="$common" branch -d -- "$branch" || true; fi
'''
        hosts.run(self.host, script)

    def archive(self):
        items = self.candidates('archive', [{'path': path} for path in self.host_rules.get('archive', [])])
        self.check_batch([item for item in items if idle(item, self.config['archive_idle_days'])])
        for item in items:
            if not idle(item, self.config['archive_idle_days']):
                self.log('archive', item.path, 'skip', item.bytes, 'recent archive activity')
            elif self.host.kind == 'powershell':
                self.log('archive', item.path, 'report only', item.bytes, 'store requires posix or WSL')
            else:
                self.act(item, 'archive and verify then remove', lambda: self.archive_one(item))

    def archive_one(self, item):
        level = self.store.compression_level(self.host, item.path, self.config['already_compressed_extensions'])
        record = self.store.archive(self.host, item.path, apply=True, nas_root=self.config['nas_root'], level=level)
        if record is None:
            raise RuntimeError('archive not verified; source must be retained')
        return record

    def project(self):
        planned = []
        for item in self.candidates('project', [{'path': root.rstrip('/\\') + '/*'} for root in self.host_rules.get('roots', [])]):
            if not idle(item, self.config['project_idle_days']):
                self.log('project', item.path, 'skip', item.bytes, 'recent project activity')
                continue
            states = [s for s in self.repos if protect.overlaps(item.path, s.path, self.host.kind == 'powershell')]
            if not states or any(s.verdict != 'on_github' for s in states):
                self.log('project', item.path, 'skip', item.bytes, 'GitHub safety unproven for every repo')
            elif self.host.kind == 'powershell':
                self.log('project', item.path, 'report only', item.bytes, 'project archive requires posix and store')
            elif len(states) != 1 or states[0].path.rstrip('/') != item.path.rstrip('/') or states[0].is_worktree:
                self.log('project', item.path, 'report only', item.bytes, 'nested/non-root repos or worktrees require manual review')
            else:
                planned.append((item, self.regenerable(item)))
        self.check_batch([path for item, regenerable in planned for path in [item, *regenerable]])
        for item, regenerable in planned:
            if not self.safe(item) or not all(self.safe(path) for path in regenerable):
                continue
            remaining = max(0, item.bytes - sum(path.bytes for path in regenerable))
            if not rules.enabled(self.config, 'project', self.apply):
                for path in regenerable:
                    self.log('project', path.path, 'would remove regenerable data', path.bytes)
            self.act(replace(item, bytes=remaining), 'archive project and verify then remove',
                     lambda: self.remove_project(item))

    def regenerable(self, item):
        entries = [{'path': posixpath.join(item.path, path)} for path in dict.fromkeys(self.config['regenerable_paths'])]
        paths, errors = inventory(self.host, {'project': entries})
        if errors:
            raise RuntimeError('regenerable inventory incomplete: ' + str(errors))
        return [path for path in paths if not any(
            path.path.startswith(parent.path.rstrip('/') + '/') for parent in paths)]

    def remove_project(self, item):
        if self.git.inspect(self.host, item.path).verdict != 'on_github':
            raise RuntimeError('git safety changed before project removal')
        if not self.safe(item, recheck=True):
            raise RuntimeError('project is protected; project retained')
        for path in self.regenerable(item):
            if not self.safe(path, recheck=True):
                raise RuntimeError('regenerable data is protected; project retained')
            remove(self.host, path)
            self.log('project', path.path, 'remove regenerable data', path.bytes)
        if self.git.inspect(self.host, item.path).verdict != 'on_github' or not self.safe(item, recheck=True):
            raise RuntimeError('project changed during archive; project retained')
        self.archive_one(item)

    def compact(self):
        if datetime.now(timezone.utc).strftime('%a').lower() != self.config['compact_weekday']:
            self.log('compact', '', 'skip', reason='not the configured weekly compact day')
            return
        if self.host.kind == 'posix':
            items = self.candidates('compact', [{'path': p, 'runner': True} for p in self.host_rules.get('compact', [])])
            self.check_batch(items)
            for item in items:
                if not re.fullmatch(r'(bin|externals)\.\d+\.\d+\.\d+', item.path.rsplit('/', 1)[-1]):
                    self.log('compact', item.path, 'skip', item.bytes, 'not a runner version directory')
                    continue
                self.act(item, 'remove old runner version', lambda: self.remove_runner(item))
        elif self.host.kind == 'powershell':
            self.compact_wsl()

    def remove_runner(self, item):
        path = shlex.quote(item.path)
        base = shlex.quote(item.path.rsplit('/', 1)[0] + '/' + item.path.rsplit('/', 1)[1].split('.')[0])
        hosts.run(self.host, f'test ! {path} -ef {base} && rm -rf -- {path}')

    def compact_wsl(self):
        script = r'''$ErrorActionPreference='Stop'
$running=@(wsl.exe --list --running --quiet | ForEach-Object {($_ -replace "`0",'').Trim()} | Where-Object {$_})
if($LASTEXITCODE -ne 0) {throw 'WSL inventory failed'}
$files=@(PATTERNS | ForEach-Object {[Environment]::ExpandEnvironmentVariables($_)} | ForEach-Object {Get-Item -Path $_ -ErrorAction SilentlyContinue} | Select-Object -ExpandProperty FullName)
@{running=$running;files=$files} | ConvertTo-Json -Compress
'''.replace('PATTERNS', '@(' + ','.join(protect.psquote(p) for p in self.host_rules.get('compact', [])) + ')')
        obj = json.loads(disk.powershell(self.host, script, timeout=60).stdout)
        items = [Candidate(path, 0, 0, 'compact') for path in obj['files']]
        if not obj['running']:
            self.check_batch(items)
        for item in items:
            path = item.path
            if obj['running']:
                self.log('compact', path, 'skip', reason='WSL distributions are running')
                continue
            def operation():
                p = protect.psquote(path)
                command = f'''$ErrorActionPreference='Stop'
if(@(wsl.exe --list --running --quiet | Where-Object {{($_ -replace "`0",'').Trim()}}).Count) {{throw 'WSL is running'}}
if($LASTEXITCODE -ne 0) {{throw 'WSL inventory failed'}}
wsl.exe --shutdown
if($LASTEXITCODE -ne 0) {{throw 'WSL shutdown failed'}}
if(Get-Command Optimize-VHD -ErrorAction SilentlyContinue) {{Optimize-VHD -Path {p} -Mode Full -ErrorAction Stop}}
else {{
$temp=New-TemporaryFile
try {{
$instructions=@('select vdisk file="' + {p} + '"','attach vdisk readonly','compact vdisk','detach vdisk','exit')
$instructions | Set-Content -LiteralPath $temp.FullName -Encoding Ascii
$output=& diskpart.exe /s $temp.FullName
if($LASTEXITCODE -ne 0 -or ($output -join "`n") -notmatch 'successfully compacted') {{throw 'diskpart compaction not confirmed'}}
}} finally {{Remove-Item -LiteralPath $temp.FullName -Force}}
}}
'''
                disk.powershell(self.host, command)
            self.act(item, 'compact WSL virtual disk', operation)
