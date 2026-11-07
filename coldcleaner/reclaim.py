"""Reclaim explicitly configured agent data without touching package caches."""
import hashlib
import json
import ntpath
import os
from pathlib import Path
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

from . import gitsafe, hosts, protect, reclaim_probe, store, tiers


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


def probe(host, operation, **request):
    try:
        result = hosts.python_run(host, SOURCE, dict(operation=operation, **request))
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as exc:
        reason = exc.stderr.decode(errors='replace').strip() or 'host probe failed'
        raise (ValueError if exc.returncode == 3 else RuntimeError)(reason) from None


BATCH = 50


def repository(url):
    if not gitsafe._is_github_url(url):
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


def preserve_git(host, path, directory):
    context = probe(host, 'context', path=path)
    module = ntpath if host.kind == 'powershell' else os.path
    if context is None or module.normcase(module.normpath(context)) != module.normcase(module.normpath(path)):
        return None
    state = probe(host, 'repo', path=path)
    if not state['worktree']:
        return None
    destination = directory / 'head.bundle'
    with tempfile.TemporaryFile() as errors:
        process = hosts.python_stream(host, SOURCE, dict(operation='bundle', path=path), stderr=errors)
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
    with tempfile.TemporaryDirectory(prefix='coldcleaner-verify-') as verifier:
        subprocess.run(['git', 'init', '--bare', verifier], check=True, capture_output=True)
        subprocess.run(['git', '-C', verifier, 'bundle', 'verify', str(destination)], check=True, capture_output=True)
    heads = subprocess.run(['git', 'bundle', 'list-heads', str(destination)], check=True, capture_output=True, text=True).stdout.strip()
    if heads != state['head'] + ' HEAD':
        raise ValueError('Git recovery bundle head differs')
    return dict(head=state['head'], branch=state['branch'], remote=state['remote'], **metadata)


def preserve(host, path, root, before_remove):
    initial = probe(host, 'manifest', path=path)
    root = Path(root)
    with store._index_lock(root):
        if shutil.disk_usage(root).free < 2 * initial['logical_bytes'] + len(initial['manifest']) * 1024:
            raise ValueError('NAS has insufficient free space for a complete verified copy')
        ident = uuid.uuid4().hex
        directory = root / host.name / datetime.now(timezone.utc).strftime('%Y-%m-%d') / ident
        directory.mkdir(parents=True, mode=0o700)
        git_recovery = preserve_git(host, path, directory)
        final = directory / (ident + '.tar.zst')
        partial = final.with_suffix('.partial')
        receipt = final.with_suffix('.sha256.json')
        manifest_path = store._manifest_path(final)
        store._pipe(lambda errors: hosts.python_stream(host, SOURCE, dict(operation='tar', path=path), stderr=errors),
                    lambda source, errors: subprocess.Popen(['zstd', '-T2', '-3', '-o', str(partial)], stdin=source, stderr=errors))
        found = {}
        with tempfile.TemporaryFile() as errors:
            decompressor = subprocess.Popen(['zstd', '-dc', '--', str(partial)], stdout=subprocess.PIPE, stderr=errors)
            try:
                with tarfile.open(fileobj=decompressor.stdout, mode='r|') as archive:
                    for member in archive:
                        if member.name in found or not (member.isdir() or member.isfile()):
                            raise ValueError('unexpected archive member')
                        found[member.name.rstrip('/')] = (hashlib.file_digest(archive.extractfile(member), 'sha256').hexdigest()
                                                          if member.isfile() else None)
                if decompressor.wait():
                    raise RuntimeError('NAS archive test-read failed')
            finally:
                decompressor.stdout.close()
                if decompressor.poll() is None:
                    decompressor.terminate(); decompressor.wait()
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
        records = store._read_index(root)
        store._write_index(root, [*records, record])
    before_remove()
    if not final.is_file() or final.stat().st_size != record.archive_bytes:
        raise ValueError('verified archive is no longer present')
    current = probe(host, 'manifest', path=path)
    if current['manifest'] != found or current['security'] != initial['security']:
        raise ValueError('source changed after verified NAS copy')
    return record, found, initial['security']


def restore_archive(host, record, archive_path, *, to=None, member=None):
    saved = json.loads(archive_path.with_suffix('.sha256.json').read_text())
    if saved['host'] != host.name or saved['source'] != record.source_path:
        raise ValueError('archive receipt identity mismatch')
    if saved.get('distro'):
        host = hosts.Host(host.name, 'wsl-maintenance', host.ssh, saved['distro'])
    request = dict(operation='restore', path=to if to is not None else record.source_path,
                   manifest=saved['manifest'], security=saved.get('security', {}), member=member)
    def transfer(request, path, compressed):
        with tempfile.NamedTemporaryFile(dir=archive_path.parent, prefix='.restore-', mode='wb') as header:
            header.write(hosts.python_payload(SOURCE, request)); header.flush()
            source = 'import os,sys;from pathlib import Path;sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes());sys.stdout.buffer.flush();args=["zstd","-dc","--",sys.argv[2]] if sys.argv[3]=="True" else ["cat","--",sys.argv[2]];os.execvp(args[0],args)'
            store._pipe(lambda errors: subprocess.Popen(['python3', '-c', source, header.name, str(path), str(compressed)],
                                                       stdout=subprocess.PIPE, stderr=errors),
                        lambda source, errors: hosts.python_sink(host, stdin=source, stderr=errors))
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


class Reclaimer:
    def __init__(self, host, config, apply, protection, report):
        self.host, self.config, self.apply = host, config, apply
        self.protection, self.report = protection, report
        self.rules = config['hosts'].get(host.name, {})
        if isinstance(self.protection, protect.Protection):
            self.protection.broad_paths.update(self.rules.get('shared_roots', []))
        self.listings = {}; self.prs = {}
        self.checked = {}; self.activity = None; self.prefetched = {}

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

    def log(self, tier, path, action, size=0, reason=''):
        row = dict(tier=tier, path=path, action=action, bytes=size, reason=reason)
        self.report.actions.append(row)
        if self.apply:
            directory = Path(self.config['report_dir'])
            directory.mkdir(parents=True, exist_ok=True)
            with (directory / 'reclaim-actions.jsonl').open('a') as stream:
                stream.write(json.dumps(dict(host=self.host.name, at=datetime.now(timezone.utc).isoformat(), **row)) + '\n')
                stream.flush(); os.fsync(stream.fileno())

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
        try:
            if self.activity is None:
                self.activity = probe(self.host, 'activity')
        except (RuntimeError, ValueError, OSError, subprocess.SubprocessError):
            return
        requests = [dict(operation=operation, path=path, **(dict(days=days) if operation == 'guard' else {}))
                    for path, days in candidates for operation in ('guard', 'context', 'repositories')]
        for start in range(0, len(requests), BATCH):
            chunk = requests[start:start + BATCH]
            try:
                results = probe(self.host, 'batch', requests=chunk, activity=self.activity)
            except (RuntimeError, ValueError, OSError, subprocess.SubprocessError):
                continue
            for request, result in zip(chunk, results):
                self.prefetched[request['operation'], request['path'], request.get('days')] = result

    def ask(self, operation, path, fresh, **request):
        found = None if fresh else self.prefetched.get((operation, path, request.get('days')))
        if found is None or 'skipped' in found:
            return probe(self.host, operation, path=path, **request)
        if 'error' in found:
            raise (ValueError if found['value'] else RuntimeError)(found['error'])
        return found['result']

    def safe(self, path, days=0, allow_git=False, fresh=False, archive=False):
        if self.activity is None and not fresh:
            self.activity = probe(self.host, 'activity')
        info = self.ask('guard', path, fresh, days=days, activity=None if fresh else self.activity)
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
        if reason:
            if 'incomplete' in reason or 'unavailable' in reason or 'timed out' in reason:
                raise RuntimeError(reason)
            raise ValueError(reason)
        return info

    def worktrees(self):
        discovery = probe(self.host, 'discover', roots=self.rules.get('roots', []))
        paths = discovery['paths']
        self.report.errors.extend('Worktree discovery incomplete: ' + error for error in discovery['errors'])
        self.report.notes.extend(discovery['notes'])
        self.checked = self.protection.batch(paths, allow_git=True) if self.host.kind != 'powershell' else {}
        for path in paths:
            size = 0
            try:
                local = probe(self.host, 'repo', path=path)
                if local['dirty'] or local['stashes']:
                    raise ValueError('IN USE: uncommitted work or stashes')
                state, prs, listing = self.proof(path)
                reason = completion(state, prs)
                if reason:
                    raise ValueError(reason)
                days = (min(self.config['worktree_idle_days'], tiers.WORKTREE_MERGED_DAYS)
                        if state['merged'] else self.config['worktree_idle_days'])
                info = self.safe(path, days, True)
                size = info['bytes']
                if not self.apply or 'worktree' not in self.config['live']:
                    self.log('worktree', path, 'would remove worktree', size,
                             'DURABLE ELSEWHERE: current head is published and merged/closed; ignored data requires a verified NAS copy' if state['ignored'] else
                             'DURABLE ELSEWHERE: clean published head is merged/closed')
                    continue
                def recheck():
                    current, current_prs, _ = self.proof(path, True)
                    problem = completion(current, current_prs)
                    if problem or current['head'] != state['head']:
                        raise ValueError(problem or 'head changed after preview')
                    self.safe(path, days, True, True)
                recheck()
                manifest = None; saved = None; security = None
                if state['ignored']:
                    drive = self.archive_target(path)
                    saved, manifest, security = preserve(self.host, path, self.config['nas_root'], lambda: (recheck(), self.archive_target(path, drive)))
                current, current_prs, listing = self.proof(path, True)
                if completion(current, current_prs) or current['head'] != state['head']:
                    raise ValueError('Git completion changed before removal')
                if saved:
                    self.archive_present(path, drive, saved)
                removed = probe(self.host, 'remove', path=path, days=days,
                                head=state['head'], listing=listing, manifest=manifest, security=security, keep=self.keep(saved))
                action = 'remove worktree and local branch' if removed['branch_removed'] else 'remove worktree; retain local branch'
                self.log('worktree', path, action, size,
                         'DURABLE ELSEWHERE: published merged/closed head; clean, no process or T3 use' +
                         ('; ignored files SHA-256 verified at ' + saved.archive_path if saved else ''))
            except ValueError as exc:
                self.log('worktree', path, 'skip', size, str(exc))
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                self.log('worktree', path, 'error', size, str(exc))

    def archives(self):
        paths = probe(self.host, 'expand', patterns=self.rules.get('archive', []))
        self.checked = {}
        self.prefetch([(path, retention(path, self.config['archive_idle_days'])) for path in paths if not package_cache(path)])
        for path in paths:
            size = 0
            try:
                if package_cache(path):
                    raise ValueError('package caches are excluded')
                days = retention(path, self.config['archive_idle_days'])
                info = self.safe(path, days, archive=True)
                size = info['bytes']
                if not self.apply or 'archive' not in self.config['live']:
                    self.log('archive', path, 'would archive and remove', size,
                             'UNIQUE: copy to NAS and verify every file SHA-256 before removal')
                    continue
                recheck = lambda: self.safe(path, days, fresh=True, archive=True)
                recheck()
                drive = self.archive_target(path)
                saved, manifest, security = preserve(self.host, path, self.config['nas_root'], lambda: (recheck(), self.archive_target(path, drive)))
                self.archive_present(path, drive, saved)
                probe(self.host, 'remove', path=path, days=days, manifest=manifest, security=security, keep=self.keep(saved))
                self.log('archive', path, 'archive and remove', size,
                         'DURABLE ELSEWHERE: every file SHA-256 verified at ' + saved.archive_path)
            except ValueError as exc:
                self.log('archive', path, 'skip', size, str(exc))
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                self.log('archive', path, 'error', size, str(exc))
