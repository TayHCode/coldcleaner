import contextlib
from contextlib import closing
import ctypes
import hashlib
import io
import json
import shutil
import os
import re
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from coldcleaner import cli, disk, hosts, protect, reclaim, reclaim_probe, report, rules
from coldcleaner import store
from tests import outside_git

outside_git.use()


class ReclaimTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = rules.load(Path(__file__).parent / 'fixtures' / 'rules.toml')
        self.host = hosts.Host('test', 'posix')
        mock = patch.dict(hosts.HOSTS, {'test': self.host})
        mock.start(); self.addCleanup(mock.stop)
        self.config.update(nas_root=str(self.root / 'nas'), report_dir=str(self.root / 'reports'),
                           worktree_idle_days=0, archive_idle_days=0, live=['worktree', 'archive'])
        self.config['hosts']['test'] = dict(roots=[], archive=[])
        retry = patch.object(cli, 'RETRY_SECONDS', 0)
        retry.start(); self.addCleanup(retry.stop)
        self.entry = report.HostReport('test')
        self.protection = Mock()
        self.protection.reason.return_value = ''
        self.protection.batch.side_effect = lambda paths, **kw: dict.fromkeys(paths, '')
        self.engine = reclaim.Reclaimer(self.host, self.config, False, self.protection, self.entry)
        self.env = patch.dict(os.environ, HOME=str(self.root), GIT_ALLOW_PROTOCOL='file',
                              GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
        self.env.start(); self.addCleanup(self.env.stop)
        policy = self.root / '.config' / 'coldcleaner' / 'local.json'
        policy.parent.mkdir(parents=True)
        policy.write_text(json.dumps(dict(roots=[str(self.root)], archive=[str(self.root / '/'.join('*' * depth))
                                                                           for depth in range(1, 5)])))
        original = reclaim_probe.main
        self.read_threads = reclaim_probe.threads
        self.read_codex = getattr(reclaim_probe, 'codex_threads', None)
        self.read_claude = getattr(reclaim_probe, 'claude_threads', None)
        self.read_references = reclaim_probe.references
        self.read_drivers = getattr(reclaim_probe, 'drivers', None)
        for name, value in (('drivers', []), ('exited', False)):
            mock = patch.object(reclaim_probe, name, create=True, return_value=value)
            mock.start(); self.addCleanup(mock.stop)
        def local_probe(host, operation, **request):
            try:
                return original(dict(operation=operation, **request))
            except ValueError:
                raise
            except Exception as exc:
                raise RuntimeError(str(exc)) from None
        for target, value in ((reclaim_probe, 'references'), (reclaim_probe, 'threads'), (reclaim_probe, 'codex_threads'),
                              (reclaim_probe, 'claude_threads')):
            mock = patch.object(target, value, create=True, return_value=[])
            mock.start(); self.addCleanup(mock.stop)
        mock = patch.object(reclaim, 'probe', side_effect=local_probe)
        mock.start(); self.addCleanup(mock.stop)
        self.real_check_nas = reclaim.check_nas
        mock = patch.object(reclaim, 'check_nas')
        mock.start(); self.addCleanup(mock.stop)

    def failure(self, call):
        try:
            call()
        except Exception as exc:
            return exc
        return None

    def git(self, path, *args):
        return subprocess.run(['git', '-C', str(path), *args], check=True, capture_output=True,
                              text=True).stdout.strip()

    def worktree(self, object_format='sha1'):
        repo = self.root / 'repo'; remote = self.root / 'remote.git'; work = self.root / 'work'
        repo.mkdir()
        self.git(repo, 'init', '-b', 'main', '--object-format=' + object_format)
        self.git(repo, 'config', 'user.name', 'Test')
        self.git(repo, 'config', 'user.email', 'test@localhost')
        self.git(repo, 'config', 'commit.gpgsign', 'false')
        (repo / 'tracked').write_text('durable')
        (repo / '.gitignore').write_text('evidence/\n')
        self.git(repo, 'add', '.')
        self.git(repo, 'commit', '-m', 'initial')
        self.git(self.root, 'init', '--bare', '--object-format=' + object_format, str(remote))
        self.git(repo, 'remote', 'add', 'origin', str(remote))
        self.git(repo, 'push', 'origin', 'main')
        self.git(repo, 'worktree', 'add', '-b', 'done', str(work))
        self.git(repo, 'push', 'origin', 'done')
        self.config['hosts']['test']['roots'] = [str(self.root)]
        def proof(path, fresh=False):
            listing = self.git(repo, 'ls-remote', str(remote))
            return reclaim.probe(self.host, 'repo', path=path, listing=listing), [], listing
        self.engine.proof = proof
        return repo, work

    def test_removal_row_records_what_is_needed_to_restore_the_worktree(self):
        repo, work = self.worktree()
        head = self.git(work, 'rev-parse', 'HEAD')
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
        self.assertFalse(work.exists(), self.entry.actions)
        logged = [json.loads(line) for line in
                  (Path(self.config['report_dir']) / 'reclaim-actions.jsonl').read_text().splitlines()]
        row = next(row for row in logged if row['path'] == str(work))
        self.assertEqual((row.get('head'), row.get('branch'), row.get('remote'),
                          row.get('merged'), row.get('pull_requests')),
                         (head, 'done', str(self.root / 'remote.git'), True, []))
        self.git(repo, 'worktree', 'add', '-b', row['branch'], row['path'], row['head'])
        self.assertEqual(self.git(work, 'rev-parse', 'HEAD'), row['head'])

    def test_removal_retains_worktree_when_proved_branch_changes(self):
        repo, work = self.worktree()
        original = reclaim.probe
        def switch_branch(host, operation, **request):
            if operation == 'remove':
                self.git(work, 'checkout', '-b', 'replacement')
            return original(host, operation, **request)
        self.engine.apply = True
        with patch.object(reclaim, 'probe', side_effect=switch_branch), \
             patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
        self.assertTrue(work.exists(), self.entry.actions)
        row = self.entry.actions[-1]
        self.assertEqual((row['action'], row['reason']), ('skip', 'Git proof changed before removal'))
        self.assertEqual(self.git(work, 'symbolic-ref', '--short', 'HEAD'), 'replacement')
        self.assertEqual(self.git(repo, 'branch', '--list', '--format=%(refname:short)', 'done'), 'done')

    def test_preview_row_records_closed_head_and_matching_pull_requests(self):
        repo, work = self.worktree()
        proof = self.engine.proof
        head = self.git(work, 'rev-parse', 'HEAD')
        def closed_proof(path, fresh=False):
            state, _, listing = proof(path, fresh)
            state['merged'] = False
            return state, [dict(state='CLOSED', headRefOid=head, url='https://github.com/example/repo/pull/1'),
                           dict(state='MERGED', headRefOid='other', url='https://github.com/example/repo/pull/2')], listing
        self.engine.proof = closed_proof
        self.engine.worktrees()
        row = next(row for row in self.entry.actions if row['path'] == str(work))
        self.assertEqual(row['action'], 'would remove worktree')
        self.assertEqual((row.get('head'), row.get('branch'), row.get('remote'),
                          row.get('merged'), row.get('pull_requests')),
                         (head, 'done', str(self.root / 'remote.git'), False,
                          ['https://github.com/example/repo/pull/1']))

    def test_completion_rejects_open_unpushed_and_unmerged_work(self):
        state = dict(dirty=False, stashes=False, published=True, merged=True, head='abc')
        self.assertEqual(reclaim.completion(state, []), '')
        self.assertIn('open', reclaim.completion(state, [dict(state='OPEN', headRefOid='abc')]))
        self.assertIn('unpushed', reclaim.completion({**state, 'published': False}, []))
        self.assertIn('uncommitted', reclaim.completion({**state, 'dirty': True}, []))
        state['merged'] = False
        self.assertIn('neither merged nor closed', reclaim.completion(state, []))
        self.assertIn('neither merged nor closed', reclaim.completion(state, [dict(state='CLOSED', headRefOid='different')]))
        self.assertEqual(reclaim.completion(state, [dict(state='CLOSED', headRefOid='abc')]), '')

    def test_fork_inventory_includes_open_upstream_pull_request(self):
        def page(parent, nodes):
            return Mock(stdout=json.dumps(dict(data=dict(repository=dict(
                parent=parent and dict(nameWithOwner=parent),
                pullRequests=dict(nodes=nodes, pageInfo=dict(hasNextPage=False, endCursor=None)))))))
        upstream = dict(state='OPEN', headRefOid='abc', url='u',
                        headRepository=dict(nameWithOwner='me/repo'))
        with patch.dict(hosts.HOSTS, {'server-a': self.host}), patch.object(
                hosts, 'run', side_effect=[page('up/repo', []), page(None, [upstream])]) as run:
            prs = reclaim.pull_requests('me/repo', 'done', 'abc')
        self.assertIn('owner=up', run.call_args.args[1])
        self.assertEqual(prs, [upstream])
        state = dict(dirty=False, stashes=False, published=True, merged=True, head='abc')
        self.assertIn('open', reclaim.completion(state, prs))

    def test_only_github_origins_name_a_repository(self):
        for url in ['https://github.com/test/x', 'git@github.com:test/x.git', 'ssh://git@github.com/test/x']:
            self.assertEqual(reclaim.repository(url), 'test/x')
        for url in ['https://github.com.evil/test/x', 'https://github.com@evil/test/x', 'file:///github.com/test/x', '/local/repo']:
            with self.assertRaisesRegex(ValueError, 'origin must be GitHub'):
                reclaim.repository(url)

    def test_pr_lookup_rejects_same_head_from_another_repository(self):
        own = dict(state='CLOSED', headRefOid='abc', url='own',
                   headRepository=dict(nameWithOwner='me/repo'))
        foreign = dict(state='CLOSED', headRefOid='abc', url='foreign',
                       headRepository=dict(nameWithOwner='someone/repo'))
        missing = dict(state='CLOSED', headRefOid='abc', url='deleted', headRepository=None)
        for branch in ('done', ''):
            with self.subTest(branch=branch):
                page = dict(nodes=[foreign, missing, own], pageInfo=dict(hasNextPage=False, endCursor=None))
                root = dict(parent=None, pullRequests=page, object=dict(associatedPullRequests=page))
                with patch.dict(hosts.HOSTS, {'server-a': self.host}), patch.object(
                        hosts, 'run', return_value=Mock(stdout=json.dumps(dict(data=dict(repository=root))))):
                    prs = reclaim.pull_requests('me/repo', branch, 'abc')
                self.assertEqual(prs, [own])

    def test_missing_github_repository_is_a_skip_and_other_failures_stay_errors(self):
        missing = json.dumps(dict(data=dict(repository=None), errors=[dict(type='NOT_FOUND', path=['repository'])]))
        for stdout, expected in ((missing.encode(), ValueError), (b'', subprocess.CalledProcessError)):
            failure = subprocess.CalledProcessError(1, 'gh', output=stdout, stderr=b'gh: failed')
            with self.subTest(expected=expected.__name__), patch.dict(hosts.HOSTS, {'server-a': self.host}), \
                    patch.object(hosts, 'run', side_effect=failure):
                raised = self.failure(lambda: reclaim.pull_requests('me/gone', 'done', 'abc'))
                self.assertIs(type(raised), expected, raised)
                if expected is ValueError:
                    self.assertIn('UNIQUE', str(raised))

    def test_path_removed_by_another_program_is_skipped_not_an_error(self):
        for operation in ('guard', 'repo'):
            with self.subTest(operation=operation):
                raised = self.failure(lambda: reclaim.probe(self.host, operation, path=str(self.root / 'vanished')))
                self.assertIsInstance(raised, ValueError, raised)
                self.assertIn('no longer exists', str(raised))

    def written(self, path, size):
        path.write_bytes(os.urandom(size))
        deadline = time.monotonic() + 30
        while path.stat().st_blocks * 512 < size and time.monotonic() < deadline:
            time.sleep(0.1)

    def skipped_worktrees(self, apply=False):
        repo, unique = self.worktree()
        self.written(unique / 'unpushed', 200_000)
        self.git(unique, 'add', '.'); self.git(unique, 'commit', '-m', 'local only')
        dirty = self.root / 'dirty'
        self.git(repo, 'worktree', 'add', '-b', 'dirty', str(dirty))
        self.git(repo, 'push', 'origin', 'dirty')
        self.written(dirty / 'draft', 1_000_000)
        calls = []
        local = reclaim.probe.side_effect
        def counted(host, operation, **request):
            calls.append(operation)
            return local(host, operation, **request)
        self.engine.apply = apply
        with patch.object(reclaim, 'probe', side_effect=counted):
            self.engine.worktrees()
        return {row['path']: row for row in self.entry.actions}, calls, unique, dirty

    def test_skipped_worktrees_report_real_bytes_from_one_sizing_call(self):
        rows, calls, unique, dirty = self.skipped_worktrees()
        self.assertIn('UNIQUE', rows[str(unique)]['reason'])
        self.assertIn('uncommitted', rows[str(dirty)]['reason'])
        self.assertGreaterEqual(rows[str(unique)]['bytes'], 200_000)
        self.assertGreaterEqual(rows[str(dirty)]['bytes'], 1_000_000)
        self.assertEqual(calls.count('sizes'), 1)
        self.assertEqual(self.entry.notes, [])
        text = report.render([self.entry])
        head = self.git(unique, 'rev-parse', 'HEAD')[:12]
        remote = self.root / 'remote.git'
        self.assertIn(f"| UNIQUE: unpushed commits or incomplete origin proof: head {head} is not on {remote} | 1 | {rows[str(unique)]['bytes']} |", text)
        largest = text.split('Largest 20 skipped:')[1]
        self.assertLess(largest.index(str(dirty)), largest.index(str(unique)))

    def test_apply_logs_skipped_worktrees_with_measured_bytes(self):
        rows, _, unique, dirty = self.skipped_worktrees(apply=True)
        logged = [json.loads(line) for line in (self.root / 'reports' / 'reclaim-actions.jsonl').read_text().splitlines()]
        self.assertEqual({row['path']: row['bytes'] for row in logged},
                         {str(unique): rows[str(unique)]['bytes'], str(dirty): rows[str(dirty)]['bytes']})
        self.assertTrue(all(row['bytes'] >= 200_000 for row in logged))

    def test_skip_sizes_that_fail_keep_zero_bytes_and_still_log(self):
        local = reclaim.probe.side_effect
        def failing(host, operation, **request):
            if operation == 'sizes':
                raise RuntimeError('ssh dropped')
            return local(host, operation, **request)
        with patch.object(reclaim.probe, 'side_effect', failing):
            rows, _, unique, dirty = self.skipped_worktrees(apply=True)
        self.assertEqual((rows[str(unique)]['bytes'], rows[str(dirty)]['bytes']), (0, 0))
        self.assertEqual(self.entry.notes, ['worktree skip sizes unavailable: ssh dropped'])
        logged = (self.root / 'reports' / 'reclaim-actions.jsonl').read_text().splitlines()
        self.assertEqual(len(logged), 2)

    def test_skip_sizes_past_the_budget_are_reported_as_lower_bounds(self):
        with patch.object(reclaim, 'SIZE_SECONDS', 0, create=True):
            rows, calls, unique, dirty = self.skipped_worktrees()
        self.assertNotIn('sizes', calls)
        self.assertEqual(self.entry.notes, ['worktree skip sizes: 2 are lower bounds (unreadable entries or the 0s cap)'])

    def sizes(self, paths, seconds=60):
        try:
            return reclaim_probe.main(dict(operation='sizes', paths=[str(path) for path in paths], seconds=seconds))
        except ValueError as exc:
            self.fail(f'sizes probe refused: {exc}')

    def test_sizes_probe_is_bounded_and_does_not_follow_links(self):
        outside = self.root / 'outside'; outside.write_bytes(os.urandom(2_000_000))
        target = self.root / 'target'; (target / 'nested').mkdir(parents=True)
        data = target / 'nested' / 'data'
        self.written(data, 300_000)
        (target / 'link').symlink_to(outside)
        (target / 'dirlink').symlink_to(self.root)
        tree, single, gone = self.sizes([target, data, self.root / 'gone'])
        self.assertTrue(tree['complete'])
        self.assertGreaterEqual(tree['bytes'], 300_000)
        self.assertLess(tree['bytes'], 2_000_000)
        self.assertEqual(single, dict(bytes=os.lstat(data).st_blocks * 512, complete=True))
        self.assertEqual(gone, dict(bytes=0, complete=True))
        self.assertFalse(self.sizes([target], seconds=-1)[0]['complete'])

    def test_sizes_probe_checks_the_deadline_between_entries(self):
        flat = self.root / 'flat'; flat.mkdir()
        for name in ('a', 'b', 'c'):
            (flat / name).write_bytes(b'x')
        clock = iter([0, 0] + [100] * 10)
        with patch.object(reclaim_probe.time, 'monotonic', side_effect=lambda: next(clock)):
            found, = self.sizes([flat], seconds=10)
        self.assertFalse(found['complete'])

    @unittest.skipIf(os.geteuid() == 0, 'root reads mode 000 directories')
    def test_sizes_probe_marks_unreadable_directories_incomplete(self):
        target = self.root / 'target'; locked = target / 'locked'
        locked.mkdir(parents=True); (locked / 'data').write_bytes(b'x')
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o755)
        found, = self.sizes([target])
        self.assertFalse(found['complete'])

    def test_worktree_whose_github_repository_is_gone_is_skipped(self):
        repo, work = self.worktree()
        self.git(work, 'remote', 'set-url', 'origin', 'https://github.com/me/gone.git')
        self.engine.proof = reclaim.Reclaimer.proof.__get__(self.engine)
        gone = subprocess.CalledProcessError(128, 'git', output=b'',
                                             stderr=b"remote: Repository not found.\nfatal: repository not found\n")
        def run(host, script, **kwargs):
            if script.startswith('git ls-remote --get-url'):
                return Mock(stdout=b'https://github.com/me/gone.git\n')
            raise gone
        with patch.object(protect, 'collect', return_value=self.protection), \
                patch.dict(hosts.HOSTS, {'server-a': self.host}), patch.object(hosts, 'run', side_effect=run):
            self.config['hosts']['test']['roots'] = [str(self.root)]
            self.engine.worktrees()
        row = self.entry.actions[-1]
        self.assertEqual((row['action'], row['path']), ('skip', str(work)), row['reason'])
        self.assertIn('UNIQUE', row['reason'])
        self.assertTrue(work.exists())

    def test_windows_argument_paths_preserve_spaces(self):
        self.assertEqual(reclaim_probe.windows_paths([
            r'C:\Program Files\Python\python.exe', r'--data=C:\actions-runners\_jobs\my job\data',
            "Write-Output 'C:\\job data'; exit"]), [r'C:\Program Files\Python\python.exe',
            r'C:\actions-runners\_jobs\my job\data', r'C:\job data'])

    def test_windows_process_inventory_rejects_unreadable_command_line(self):
        for command in (None, ''):
            with self.subTest(command=command):
                row = dict(ProcessId=4242, ExecutablePath=r'C:\Windows\service.exe', CommandLine=command)
                with patch.object(reclaim_probe.os, 'name', 'nt'), patch.object(
                        reclaim_probe.os, 'getpid', return_value=9000), patch.object(
                        reclaim_probe.subprocess, 'run', return_value=Mock(stdout=json.dumps([row]))):
                    with self.assertRaisesRegex(RuntimeError, 'process-use inventory incomplete: .*4242'):
                        self.read_references()

    def test_windows_process_inventory_exempts_kernel_pseudo_processes(self):
        rows = [dict(ProcessId=pid, ExecutablePath=None, CommandLine=None) for pid in (0, 4)]
        rows.append(dict(ProcessId=4242, ExecutablePath=r'C:\Python\python.exe',
                         CommandLine=r'python.exe C:\job\worker.py'))
        with patch.object(reclaim_probe.os, 'name', 'nt'), patch.object(
                reclaim_probe.os, 'getpid', return_value=9000), patch.object(
                reclaim_probe.subprocess, 'run', return_value=Mock(stdout=json.dumps(rows))), patch.object(
                reclaim_probe, 'windows_arguments', return_value=['python.exe', r'C:\job\worker.py']):
            self.assertEqual(self.read_references(), [r'C:\Python\python.exe', r'C:\job\worker.py'])

    def read_darwin_references(self, lsof, ps):
        def run(command, **kwargs):
            return lsof if 'lsof' in command else ps
        with patch.object(reclaim_probe.sys, 'platform', 'darwin'), patch.object(
                reclaim_probe.os, 'geteuid', return_value=501), patch.object(
                reclaim_probe.subprocess, 'run', side_effect=run) as calls:
            try:
                return self.read_references(), None, calls
            except Exception as error:
                return None, error, calls

    def test_darwin_inventory_reads_open_files_and_command_lines_with_sudo(self):
        lsof = Mock(returncode=0, stdout=b'p10\nfcwd\nn/Users/a/REPOS/app\nf3\nn*:22\nn/Users/a/log.txt\n', stderr=b'')
        ps = Mock(returncode=0, stdout=b'/usr/bin/python3 /Users/a/job/run.py --out=/Users/a/out dir\n', stderr=b'')
        found, error, calls = self.read_darwin_references(lsof, ps)
        self.assertIsNone(error)
        for expected in ('/Users/a/REPOS/app', '/Users/a/log.txt', '/Users/a/job/run.py', '/Users/a/out', '/Users/a/out dir'):
            self.assertIn(expected, found)
        self.assertNotIn('*:22', found)
        self.assertEqual([call.args[0][:3] for call in calls.call_args_list],
                         [['sudo', '-n', 'lsof'], ['sudo', '-n', 'ps']])

    def test_darwin_inventory_rejects_failed_lsof_or_ps(self):
        good = Mock(returncode=0, stdout=b'', stderr=b'')
        for lsof, ps in ((Mock(returncode=1, stdout=b'', stderr=b'lsof: denied'), good),
                         (good, Mock(returncode=1, stdout=b'', stderr=b'ps: denied'))):
            with self.subTest(failed=lsof.returncode or ps.returncode):
                found, error, _ = self.read_darwin_references(lsof, ps)
                self.assertIsNone(found)
                self.assertIsInstance(error, RuntimeError)
                self.assertIn('process-use inventory incomplete', str(error))

    def test_darwin_inventory_protects_mounts_lsof_could_not_stat(self):
        warning = (b"lsof: WARNING: can't stat() smbfs file system /Volumes/share\n"
                   b'      Output information may be incomplete.\n'
                   b'      assuming "dev=1000004" from mount table\n')
        found, error, _ = self.read_darwin_references(
            Mock(returncode=0, stdout=b'n/Users/a/x\n', stderr=warning), Mock(returncode=0, stdout=b'', stderr=b''))
        self.assertIsNone(error)
        self.assertIn('/Volumes/share', found)
        self.assertIn('/Users/a/x', found)

    def test_darwin_inventory_rejects_unrecognised_lsof_diagnostics(self):
        for stderr in (b'lsof: WARNING: something else\n',
                       b'      Output information may be incomplete.\n'):
            with self.subTest(stderr=stderr):
                found, error, _ = self.read_darwin_references(
                    Mock(returncode=0, stdout=b'n/Users/a/x\n', stderr=stderr),
                    Mock(returncode=0, stdout=b'', stderr=b''))
                self.assertIsNone(found)
                self.assertIsInstance(error, RuntimeError)
                self.assertIn('process-use inventory incomplete', str(error))

    def test_darwin_inventory_decodes_escaped_lsof_filenames(self):
        found, error, _ = self.read_darwin_references(
            Mock(returncode=0, stdout='n/Users/a/\\xe9\\x9b\\xaa/open.txt\n'.encode(), stderr=b''),
            Mock(returncode=0, stdout=b'', stderr=b''))
        self.assertIsNone(error)
        self.assertIn('/Users/a/\u96ea/open.txt', found)
        self.assertIn('/Users/a/\\xe9\\x9b\\xaa/open.txt', found)

    def inventory_failure(self, platform, run):
        with patch.object(reclaim_probe.sys, 'platform', platform), patch.object(
                reclaim_probe.os, 'geteuid', return_value=1000), patch.object(
                reclaim_probe, 'installed_scan', return_value=True), patch.object(
                reclaim_probe.subprocess, 'run', side_effect=run):
            error = self.failure(self.read_references)
        return type(error), str(error)

    def test_inventory_without_passwordless_sudo_is_a_skip_naming_the_readme(self):
        expected = (ValueError, 'IN USE: process inventory needs passwordless sudo (see README#sudo)')
        for platform, encode in (('linux', str), ('darwin', str.encode)):
            for stderr in ('sudo: a password is required\n', 'sudo: sorry, user alice is not allowed to execute x\n',
                           'sudo: unable to send audit message: Operation not permitted\nsudo: a password is required\n',
                           "sudo: I'm sorry stranger. I'm afraid I can't do that\n",
                           'sudo: interactive authentication is required\n'):
                refused = Mock(returncode=1, stdout=encode(''), stderr=encode(stderr))
                with self.subTest(platform=platform, stderr=stderr):
                    self.assertEqual(self.inventory_failure(platform, lambda *args, **kwargs: refused), expected)
            with self.subTest(platform=platform, sudo='missing'):
                self.assertEqual(self.inventory_failure(platform, FileNotFoundError(2, 'No such file', 'sudo')), expected)
        broken = Mock(returncode=1, stdout='', stderr='sudo: python3: command not found\n')
        self.assertIs(self.inventory_failure('linux', lambda *args, **kwargs: broken)[0], RuntimeError)

    @unittest.skipIf(os.geteuid() == 0, 'root reads mode 000 directories')
    def test_unreadable_proc_is_a_one_line_skip(self):
        process = self.root / 'proc/1'; (process / 'fd').mkdir(parents=True)
        (process / 'cmdline').write_bytes(b'init\0'); (process / 'environ').write_bytes(b'')
        (process / 'fd').chmod(0); self.addCleanup((process / 'fd').chmod, 0o700)
        with patch.object(reclaim_probe.os, 'geteuid', return_value=0):
            error = self.failure(lambda: self.read_references(str(self.root / 'proc')))
        self.assertEqual((type(error), str(error)), (ValueError, 'process inventory incomplete: /proc not readable'))

    def test_narrow_sudoers_rule_runs_the_installed_scan(self):
        installed = self.root / 'coldcleaner-proc-scan.py'
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            return Mock(returncode=0, stdout='[]', stderr='')
        with patch.object(reclaim_probe, 'SCAN_PATH', str(installed), create=True), patch.object(
                reclaim_probe.os, 'geteuid', return_value=1000), patch.object(
                reclaim_probe.subprocess, 'run', side_effect=run):
            for stale in (None, reclaim_probe.PROC_SCAN + '\n# older release\n'):
                if stale is not None:
                    installed.write_text(stale)
                error = self.failure(self.read_references)
                self.assertEqual((type(error), str(error)), (ValueError, reclaim_probe.NEEDS_SUDO))
            installed.write_text(reclaim_probe.PROC_SCAN)
            self.read_references()
        self.assertEqual(calls, [['sudo', '-n', 'python3', '-I', str(installed), '/proc']])
        readme = (Path(__file__).parents[1] / 'README.md').read_text()
        self.assertIn('\n## Sudo\n', readme)
        self.assertIn('NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/coldcleaner-proc-scan.py /proc\n', readme)

    def read_windows_references(self, rows, protected, gone=()):
        with patch.object(reclaim_probe.os, 'name', 'nt'), patch.object(
                reclaim_probe.os, 'getpid', return_value=9000), patch.object(
                reclaim_probe, 'exited', create=True, side_effect=lambda pid: pid in gone), patch.object(
                reclaim_probe, 'protected_process', side_effect=lambda pid: pid in protected), patch.object(
                reclaim_probe.subprocess, 'run', return_value=Mock(stdout=json.dumps(rows))), patch.object(
                reclaim_probe, 'windows_arguments', return_value=['python.exe', r'C:\job\worker.py']):
            return self.read_references()

    def test_windows_inventory_tolerates_protected_system_processes(self):
        rows = [dict(ProcessId=pid, ExecutablePath=None, CommandLine=command)
                for pid, command in ((432, None), (472, ''))]
        rows.append(dict(ProcessId=4242, ExecutablePath=r'C:\Python\python.exe',
                         CommandLine=r'python.exe C:\job\worker.py'))
        self.assertEqual(self.read_windows_references(rows, {432, 472}),
                         [r'C:\Python\python.exe', r'C:\job\worker.py'])

    def test_windows_inventory_rejects_unreadable_process_that_is_not_protected(self):
        rows = [dict(ProcessId=107372, ExecutablePath=None, CommandLine=None)]
        with self.assertRaisesRegex(RuntimeError, 'unreadable for process 107372'):
            self.read_windows_references(rows, {432})

    def test_windows_inventory_skips_processes_that_exited_during_enumeration(self):
        rows = [dict(ProcessId=67276, ExecutablePath=None, CommandLine=None),
                dict(ProcessId=4242, ExecutablePath=r'C:\Python\python.exe', CommandLine=r'python.exe C:\job\worker.py')]
        found = []
        self.assertIsNone(self.failure(lambda: found.extend(self.read_windows_references(rows, set(), gone={67276}))))
        self.assertEqual(found, [r'C:\Python\python.exe', r'C:\job\worker.py'])

    def windows_file_check(self, users, write_error=None):
        kernel, ntdll = Mock(), Mock()
        kernel.CreateFileW.side_effect = lambda path, access, *rest: (
            ctypes.c_void_p(-1).value if access == 0x2 and write_error else 10)
        kernel.FindFirstStreamW.return_value = ctypes.c_void_p(-1).value
        def query(handle, status, buffer, length, kind):
            ctypes.c_ulong.from_buffer(buffer).value = users
            return 0
        ntdll.NtQueryInformationFile.side_effect = query
        path = self.root / 'RunnerService.exe'; path.write_text('image')
        with patch.object(ctypes, 'WinDLL', create=True, side_effect=lambda name, **kw: ntdll if name == 'ntdll' else kernel), \
                patch.object(ctypes, 'get_last_error', create=True, side_effect=[write_error, 38] if write_error else [38]):
            reclaim_probe.windows_file_safety(path)

    def test_windows_file_mapped_by_a_running_program_is_in_use_whatever_its_attributes(self):
        with self.assertRaisesRegex(ValueError, 'mapped by a running program'):
            self.windows_file_check(1)
        with self.assertRaisesRegex(ValueError, 'mapped by a running program or driver'):
            self.windows_file_check(0, write_error=32)
        self.windows_file_check(0, write_error=5)
        self.windows_file_check(0)

    def test_loaded_windows_drivers_are_process_use_references(self):
        names = ['\\SystemRoot\\system32\\ntoskrnl.exe', '\\??\\C:\\WINDOWS\\temp\\cpuz159\\cpuz159_x64.sys']
        psapi = Mock()
        def enumerate(bases, size, needed):
            for index in range(len(names)):
                bases[index] = index + 1
            needed._obj.value = len(names) * ctypes.sizeof(ctypes.c_void_p)
            return 1
        def name(base, buffer, length):
            buffer.value = names[base - 1]
            return len(buffer.value)
        psapi.EnumDeviceDrivers.side_effect = enumerate
        psapi.GetDeviceDriverFileNameW.side_effect = name
        with patch.object(reclaim_probe, 'drivers', self.read_drivers), patch.object(
                ctypes, 'WinDLL', create=True, return_value=psapi), patch.dict(os.environ, SystemRoot='C:\\Windows'):
            self.assertEqual(self.read_windows_references([], set()), ['C:\\Windows\\system32\\ntoskrnl.exe',
                                                                       'C:\\WINDOWS\\temp\\cpuz159\\cpuz159_x64.sys'])

    def test_read_only_windows_files_are_made_writable_before_deletion(self):
        for kind, version in (('file', (3, 13)), ('folder', (3, 13)), ('folder', (3, 9))):
            with self.subTest(kind=kind, version=version):
                target = self.root / ('object-' + kind + '-' + str(version[1]))
                victim = target / 'b1885b' if kind == 'folder' else target
                victim.parent.mkdir(parents=True, exist_ok=True); victim.write_text('object')
                unlink, chmod, refused = os.unlink, [], []
                def guarded(name, *args, **kw):
                    if not refused:
                        refused.append(name)
                        raise PermissionError(13, 'Access is denied', str(name))
                    return unlink(name, *args, **kw)
                def on_windows(path, delete=getattr(reclaim_probe, 'delete', None), version=version):
                    with patch.object(reclaim_probe.os, 'name', 'nt'), patch.object(
                            reclaim_probe.sys, 'version_info', version), patch.object(
                            reclaim_probe, 'extended', side_effect=str):
                        delete(path)
                with patch.object(reclaim_probe, 'guard'), patch.object(
                        reclaim_probe, 'delete', create=True, side_effect=on_windows), patch.object(
                        reclaim_probe.os, 'chmod', side_effect=lambda name, mode: chmod.append(mode)), patch.object(
                        os, 'unlink', side_effect=guarded):
                    failure = self.failure(lambda: reclaim_probe.main(dict(operation='remove', path=str(target))))
                self.assertIsNone(failure)
                self.assertEqual(list(self.root.glob('.object-*')), [])
                self.assertFalse(target.exists())
                self.assertEqual(chmod, [reclaim_probe.stat.S_IWRITE])

    def test_repository_walk_uses_the_long_path_spelling_and_reports_the_callers(self):
        source = self.root / 'scratch'; source.mkdir()
        alias = self.root / 'long'; (alias / 'deep' / 'repo' / '.git').mkdir(parents=True)
        with patch.object(reclaim_probe, 'extended', create=True, return_value=str(alias)):
            found = reclaim_probe.main(dict(operation='repositories', path=str(source)))
        self.assertEqual(found, [str(source / 'deep' / 'repo')])

    def test_tree_of_a_path_removed_after_listing_is_skipped(self):
        with self.assertRaisesRegex((ValueError, OSError), 'no longer exists'):
            reclaim_probe.tree(self.root / 'tok.json')

    MOUNTS = ('134 80 0:72 / /mnt/c rw,noatime - 9p C:\\134 rw,aname=drvfs;path=C:\\;uid=1000\n'
              '131 80 0:70 / /mnt/my\\040drive rw,relatime - 9p I: rw,aname=drvfs;path=I:\\;metadata\n'
              '150 80 0:74 / /mnt/shared rw - 9p S: rw,aname=drvfs;path=S:\\134Team\\040Share;uid=1000\n'
              '140 80 0:72 /data/my\\040job /work rw,noatime - 9p C:\\134 rw,aname=drvfs;path=C:\\;uid=1000\n'
              '90 80 0:30 / /usr/lib/wsl/drivers ro - 9p drivers ro,aname=drivers\n')

    def read_vm_references(self, rows, scan=None, running=b'U\x00b\x00u\x00n\x00t\x00u\x00\r\x00\n\x00', fail=False):
        calls = []
        def run(argv, **kw):
            calls.append(argv)
            if argv[0] == 'powershell':
                return Mock(stdout=json.dumps(rows))
            if argv[1] == '--list':
                return Mock(stdout=running)
            if fail:
                return Mock(returncode=1, stdout='', stderr='python3: not found')
            return Mock(returncode=0, stdout=json.dumps(scan if isinstance(scan, list) and scan and isinstance(scan[0], dict)
                                                         else [dict(mountinfo=self.MOUNTS, paths=scan or [])]))
        with patch.object(reclaim_probe.os, 'name', 'nt'), patch.object(
                reclaim_probe.os, 'getpid', return_value=9000), patch.object(
                reclaim_probe, 'protected_process', return_value=False), patch.object(
                reclaim_probe.subprocess, 'run', side_effect=run), patch.object(
                reclaim_probe, 'windows_arguments', return_value=['python.exe', r'C:\job\worker.py']):
            return self.read_references(), calls

    def vm(self, name, pid=107372):
        return dict(ProcessId=pid, Name=name, ExecutablePath=None, CommandLine=None)

    def test_wsl_vm_is_inventoried_from_inside_each_running_distro(self):
        scan = ['/mnt/c/Users/me/job/data', '/mnt/my drive/models', '/home/me/repo', '/mnt/c', '/work/out.bin', '/workshop', '/mnt/shared/plan.xlsx']
        running = 'Ubuntu\r\nUbuntu Dev\r\n'.encode('utf-16-le')
        found, calls = self.read_vm_references([self.vm('vmmemWSL')], scan, running=running)
        self.assertEqual(found, ['C:\\Users\\me\\job\\data', 'I:\\models', 'C:\\', 'C:\\data\\my job\\out.bin',
                                 'S:\\Team Share\\plan.xlsx'] * 2)
        for distro in ('Ubuntu', 'Ubuntu Dev'):
            self.assertIn(['wsl.exe', '-d', distro, '-u', 'root', '-e', 'python3', '-', '/proc', '--by-namespace'], calls)

    def test_wsl_container_paths_map_through_their_own_mount_namespace(self):
        container = '77 70 0:72 /src /workspace rw - 9p C:\\134 rw,aname=drvfs;path=C:\\;uid=1000\n'
        scan = [dict(mountinfo=self.MOUNTS, paths=['/workspace/app']),
                dict(mountinfo=container, paths=['/workspace/app', '/mnt/c/Users/me'])]
        found, _ = self.read_vm_references([self.vm('vmmemWSL')], scan)
        self.assertEqual(found, ['C:\\src\\app'])
        rooted = '80 70 0:72 /share/box / rw - 9p C:\\134 rw,aname=drvfs;path=C:\\;uid=1000\n'
        found, _ = self.read_vm_references([self.vm('vmmemWSL')], [dict(mountinfo=rooted, paths=['/project/data.bin', '/'])])
        self.assertEqual(found, ['C:\\share\\box\\project\\data.bin', 'C:\\share\\box\\'])

    def test_proc_scan_groups_paths_by_mount_namespace(self):
        for pid, namespace, cwd in ((10, 'mnt:[1]', '/mnt/c/job'), (11, 'mnt:[2]', '/workspace/app')):
            process = self.root / 'proc' / str(pid); (process / 'fd').mkdir(parents=True); (process / 'ns').mkdir()
            (process / 'cmdline').write_bytes(b'tool\0' if pid == 10 else b''); (process / 'environ').write_bytes(b''); (process / 'maps').write_text('')
            (process / 'cwd').symlink_to(cwd); (process / 'ns/mnt').symlink_to(namespace)
            (process / 'root').symlink_to('/')
            (process / 'mountinfo').write_text(namespace + '\n')
        result = subprocess.run([sys.executable, '-c', reclaim_probe.PROC_SCAN, str(self.root / 'proc'), '--by-namespace'],
                                capture_output=True, text=True, check=True)
        grouped = {row['mountinfo'].strip(): row['paths'] for row in json.loads(result.stdout)}
        self.assertEqual(grouped, {'mnt:[1]': ['/mnt/c/job'], 'mnt:[2]': ['/workspace/app']})
        (self.root / 'proc/11/mountinfo').chmod(0)
        failed = subprocess.run([sys.executable, '-c', reclaim_probe.PROC_SCAN, str(self.root / 'proc'), '--by-namespace'],
                                capture_output=True, text=True)
        if os.geteuid():
            self.assertNotEqual(failed.returncode, 0)

    def scan_namespaces(self, setup):
        process = self.root / 'proc/20'; (process / 'fd').mkdir(parents=True); (process / 'ns').mkdir()
        (process / 'cmdline').write_bytes(b'tool\0'); (process / 'environ').write_bytes(b''); (process / 'maps').write_text('')
        (process / 'cwd').symlink_to('/mnt/c/job'); (process / 'ns/mnt').symlink_to('mnt:[1]')
        (process / 'root').symlink_to('/'); (process / 'mountinfo').write_text('m\n')
        setup(process)
        return subprocess.run([sys.executable, '-c', reclaim_probe.PROC_SCAN, str(self.root / 'proc'), '--by-namespace'],
                              capture_output=True, text=True)

    def test_stacked_drvfs_mounts_map_to_the_visible_drive(self):
        stacked = ('134 80 0:72 / /mnt/c rw - 9p C:\\134 rw,aname=drvfs;path=C:\\;uid=1000\n'
                   '160 134 0:75 / /mnt/c rw - 9p D:\\134 rw,aname=drvfs;path=D:\\;uid=1000\n')
        found, _ = self.read_vm_references([self.vm('vmmemWSL')], [dict(mountinfo=stacked, paths=['/mnt/c/job/data'])])
        self.assertEqual(found, ['D:\\job\\data'])

    def test_proc_scan_fails_for_a_changed_root(self):
        def chroot(process):
            (process / 'root').unlink(); (process / 'root').symlink_to('/mnt/c/job')
        result = self.scan_namespaces(chroot)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('changed root', result.stderr)

    def test_proc_scan_fails_when_a_live_process_hides_its_files(self):
        def leader_exited(process):
            (process / 'fd').rmdir()
            (process / 'status').write_text('Name:\ttool\nState:\tZ (zombie)\nThreads:\t3\n')
        result = self.scan_namespaces(leader_exited)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unreadable', result.stderr)

    def test_proc_scan_skips_processes_that_really_exited(self):
        def zombie(process):
            (process / 'fd').rmdir()
            (process / 'status').write_text('Name:\ttool\nState:\tZ (zombie)\nThreads:\t1\n')
        result = self.scan_namespaces(zombie)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [])

    def test_proc_scan_includes_mapped_files(self):
        def mapped(process):
            (process / 'maps').write_text('7f00-7f10 r--p 00000000 00:4b 12 /mnt/c/job/model bin (deleted)\n'
                                          '7f10-7f20 rw-p 00000000 00:00 0 \n7f20-7f30 rw-p 00000000 00:00 0 [heap]\n')
        result = self.scan_namespaces(mapped)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('/mnt/c/job/model bin', json.loads(result.stdout)[0]['paths'])

    def test_proc_scan_accepts_undecodable_mapped_names(self):
        result = self.scan_namespaces(lambda process: (process / 'maps').write_bytes(
            b'7f00-7f10 r--p 00000000 00:4b 12 /mnt/c/job/\xff.bin\n'))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_second_wsl_vm_keeps_inventory_incomplete(self):
        with self.assertRaisesRegex(RuntimeError, 'more than one WSL VM'):
            self.read_vm_references([self.vm('vmmemWSL'), self.vm('vmmemWSL', 107400)])

    def test_proc_scan_skips_kernel_threads(self):
        def kernel_thread(process):
            (process / 'cmdline').write_bytes(b''); (process / 'environ').unlink()
            (process / 'status').write_text('Name:\tkthreadd\nState:\tS (sleeping)\nThreads:\t1\n')
            (process / 'stat').write_text('2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0\n')
        result = self.scan_namespaces(kernel_thread)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [])

    def test_wsl_inventory_failure_keeps_inventory_incomplete(self):
        with self.assertRaisesRegex(RuntimeError, 'process-use inventory incomplete: WSL distro Ubuntu'):
            self.read_vm_references([self.vm('vmmemWSL')], fail=True)

    def test_wsl_vm_without_a_listed_distro_is_incomplete(self):
        with self.assertRaisesRegex(RuntimeError, 'no WSL distro is listed'):
            self.read_vm_references([self.vm('vmmemWSL')], running=b'')

    def test_sandbox_template_vm_counts_only_while_no_sandbox_session_runs(self):
        found, calls = self.read_vm_references([self.vm('vmmemCmZygote', 12500)])
        self.assertEqual(found, [])
        self.assertEqual(len(calls), 1)
        session = dict(ProcessId=777, Name='WindowsSandboxClient.exe', ExecutablePath=r'C:\Windows\System32\WindowsSandboxClient.exe',
                       CommandLine='WindowsSandboxClient.exe')
        with self.assertRaisesRegex(RuntimeError, 'Windows Sandbox session is running'):
            self.read_vm_references([self.vm('vmmemCmZygote', 12500), session])

    def test_vm_names_with_a_readable_path_are_not_trusted(self):
        rows = [dict(ProcessId=50, Name='vmmemWSL', ExecutablePath=r'C:\Users\me\vmmemWSL.exe', CommandLine=None)]
        with self.assertRaisesRegex(RuntimeError, 'unreadable for process 50'):
            self.read_vm_references(rows)

    def test_incomplete_process_inventory_retains_archive_source(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('private')
        self.config['hosts']['test']['archive'] = [str(source)]
        self.engine.apply = True
        with patch.object(reclaim_probe, 'references', side_effect=RuntimeError(
                'process-use inventory incomplete: CommandLine unreadable for process 4242')):
            self.engine.archives()
        self.assertEqual((source / 'unique').read_text(), 'private')
        self.assertEqual(self.entry.actions[-1]['action'], 'error')
        self.assertIn('process-use inventory incomplete', self.entry.actions[-1]['reason'])
        self.assertFalse((self.root / 'nas').exists())

    def test_posix_process_arguments_preserve_spaces(self):
        process = self.root / 'proc/4242'; (process / 'fd').mkdir(parents=True)
        job = self.root / 'my job'; job.mkdir()
        (process / 'cmdline').write_bytes(b'tool\0--data=' + str(job / 'input').encode() + b'\0')
        (process / 'environ').write_bytes(b'')
        with patch.object(reclaim_probe.os, 'geteuid', return_value=0):
            found = self.read_references(str(self.root / 'proc'))
        self.assertIn(str(job / 'input'), found)
        with self.assertRaisesRegex(ValueError, 'running process'):
            reclaim_probe.guard(job, activity=dict(threads=[], references=found))

    def test_every_logged_row_names_the_policy_it_ran_under(self):
        with patch.object(reclaim.version, 'revision', return_value='c0de' * 10):
            self.engine = reclaim.Reclaimer(self.host, self.config, True, self.protection, self.entry)
        repo, work = self.worktree()
        stamp = time.time() - 8 * 86400
        old = self.root / 'evidence-old'; old.mkdir(); (old / 'unique').write_text('keep a copy')
        for path in (old / 'unique', old):
            os.utime(path, (stamp, stamp))
        fresh = self.root / 'evidence-new'; fresh.mkdir(); (fresh / 'unique').write_text('still in use')
        pattern = str(self.root / 'evidence-*')
        self.config['hosts']['test']['archive'] = [pattern]
        self.config['archive_idle_days'] = 5
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
            self.engine.archives()
        logged = {row['path']: row for row in (json.loads(line) for line in
                  (Path(self.config['report_dir']) / 'reclaim-actions.jsonl').read_text().splitlines())}
        policy = dict(rules_sha256=hashlib.sha256((Path(__file__).parent / 'fixtures' / 'rules.toml').read_bytes()).hexdigest(),
                      code='c0de' * 10)
        expected = {
            str(work): dict(action='remove worktree and local branch', rule='test.roots:' + str(self.root), idle_days=0),
            str(old): dict(action='archive and remove', rule='test.archive:' + pattern, idle_days=reclaim.retention(str(old), 5)),
            str(fresh): dict(action='skip', rule='test.archive:' + pattern, idle_days=reclaim.retention(str(fresh), 5)),
        }
        for path, fields in expected.items():
            row = logged[path]
            self.assertEqual({key: row.get(key) for key in (*fields, *policy)}, {**fields, **policy}, row)

    def test_real_worktree_preview_preserves_then_apply_removes_branch(self):
        repo, work = self.worktree()
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
            self.assertTrue(work.exists())
            self.assertEqual(self.entry.actions[-1]['action'], 'would remove worktree')
            self.engine.apply = True
            self.engine.worktrees()
        self.assertFalse(work.exists())
        self.assertEqual(self.git(repo, 'branch', '--list', 'done'), '')
        self.assertEqual(self.entry.actions[-1]['action'], 'remove worktree and local branch')

    def test_worktree_removal_does_not_run_git_inside_the_worktree(self):
        repo, work = self.worktree()
        shim = self.root / 'bin'; shim.mkdir()
        (shim / 'git').write_text(
            '#!/bin/sh\n'
            'case " $* " in *" worktree remove "*)\n'
            '  dir=$PWD; [ "$1" = -C ] && dir=$2\n'
            '  for target; do :; done\n'
            '  case "$(cd "$dir" && pwd -P)/" in "$(cd "$target" && pwd -P)/"*)\n'
            '    echo "error: failed to delete $target: Permission denied" >&2; exit 1;; esac;;\n'
            'esac\n'
            f'exec {shutil.which("git")} "$@"\n')
        (shim / 'git').chmod(0o755)
        with patch.object(protect, 'collect', return_value=self.protection), \
                patch.dict(os.environ, PATH=f'{shim}{os.pathsep}{os.environ["PATH"]}'):
            self.engine.apply = True
            self.engine.worktrees()
        self.assertEqual(self.entry.actions[-1]['action'], 'remove worktree and local branch', self.entry.actions[-1]['reason'])
        self.assertFalse(work.exists())

    def test_discovery_lists_each_worktree_once_whatever_spelling_git_reports(self):
        repo, work = self.worktree()
        real = reclaim_probe.git
        def respelled(path, *args, **kwargs):
            return real(path, *args, **kwargs).replace(str(self.root) + '/', str(self.root) + '//')
        with patch.object(reclaim_probe, 'git', side_effect=respelled):
            found = reclaim_probe.discover([str(self.root)])
        self.assertEqual(found['paths'], [str(work)])

    def test_per_worktree_refs_retain_unique_commits(self):
        repo, work = self.worktree()
        head = self.git(work, 'rev-parse', 'HEAD')
        unique = self.git(work, 'commit-tree', 'HEAD^{tree}', '-p', head, '-m', 'unique worktree state')
        self.engine.apply = True
        for ref in ('refs/worktree/private', 'refs/bisect/good-' + unique, 'refs/rewritten/private'):
            with self.subTest(ref=ref):
                candidate = self.root / ref.split('/')[1]
                self.git(repo, 'worktree', 'add', '--detach', str(candidate), head)
                self.git(candidate, 'update-ref', ref, unique)
                with patch.object(protect, 'collect', return_value=self.protection):
                    self.engine.worktrees()
                self.assertTrue(candidate.is_dir(), self.entry.actions)
                self.assertEqual(self.git(candidate, 'rev-parse', ref), unique)
                action = next(row for row in self.entry.actions if row['path'] == str(candidate))
                self.assertIn('per-worktree refs', action['reason'])
                self.git(candidate, 'update-ref', '-d', ref)

    def test_removal_keeps_branch_checked_out_in_another_worktree(self):
        repo, work = self.worktree()
        other = self.root / 'other'
        self.git(repo, 'worktree', 'add', '--force', str(other), 'done')
        self.config['hosts']['test']['roots'] = [str(work)]
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
        self.assertFalse(work.exists(), self.entry.actions)
        self.assertEqual(self.git(other, 'symbolic-ref', '--short', 'HEAD'), 'done')
        self.assertEqual(self.git(repo, 'branch', '--list', '--format=%(refname:short)', 'done'), 'done')
        self.assertEqual(self.git(repo, 'rev-parse', 'refs/heads/done'),
                         self.git(other, 'rev-parse', 'HEAD'))
        self.assertEqual(self.entry.actions[-1]['action'], 'remove worktree; retain local branch')
        row = self.entry.actions[-1]
        self.assertEqual(row.get('head'), self.git(other, 'rev-parse', 'HEAD'))
        self.git(repo, 'worktree', 'add', '--detach', row['path'], row['head'])
        self.assertEqual(self.git(work, 'rev-parse', 'HEAD'), row['head'])

    def restored_copy(self, path):
        record = next(item for item in store._read_index(self.root / 'nas') if item.source_path == str(path))
        restored = self.root / ('restored-' + path.name)
        store.restore(record.id, self.root / 'nas', to=str(restored))
        return restored

    def test_unique_head_and_branch_reflogs_are_bundled_before_removal(self):
        repo, work = self.worktree()
        head = self.git(work, 'rev-parse', 'HEAD')
        self.engine.apply = True
        for name in ('head-history', 'branch-history'):
            with self.subTest(name=name):
                candidate = self.root / name
                self.git(repo, 'worktree', 'add', '-b', name, str(candidate), head)
                (candidate / 'tracked').write_text('unique reset history')
                self.git(candidate, 'commit', '-am', 'unique history')
                unique = self.git(candidate, 'rev-parse', 'HEAD')
                self.git(candidate, 'reset', '--hard', head)
                if name == 'branch-history':
                    self.git(candidate, 'reflog', 'expire', '--expire=all', 'HEAD')
                else:
                    self.git(candidate, 'checkout', '--detach')
                with patch.object(protect, 'collect', return_value=self.protection), contextlib.chdir(self.root):
                    self.engine.worktrees()
                self.assertFalse(candidate.exists(), self.entry.actions)
                action = next(row for row in self.entry.actions if row['path'] == str(candidate))
                self.assertIn('reflog commits bundled', action['reason'])
                restored = self.restored_copy(candidate)
                self.assertEqual(self.git(restored, 'rev-parse', 'refs/coldcleaner/reflog/' + unique), unique)
                self.assertEqual(self.git(restored, 'rev-parse', 'HEAD'), head)

    def test_amended_commit_is_restored_from_the_bundle_after_removal(self):
        self.amended_commit_round_trip('sha1')

    def test_amended_commit_in_a_sha256_repository_is_restored_from_the_bundle(self):
        self.amended_commit_round_trip('sha256')

    def amended_commit_round_trip(self, object_format):
        repo, work = self.worktree(object_format)
        self.assertEqual(len(self.git(work, 'rev-parse', 'HEAD')), 40 if object_format == 'sha1' else 64)
        (work / 'tracked').write_text('draft')
        self.git(work, 'commit', '-am', 'draft')
        draft = self.git(work, 'rev-parse', 'HEAD')
        self.git(work, 'commit', '--amend', '-m', 'final')
        final = self.git(work, 'rev-parse', 'HEAD')
        self.git(work, 'push', 'origin', 'done', 'done:main')
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
        self.assertIn('unique reflog history', self.entry.actions[-1]['reason'])
        self.assertTrue(work.exists())
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection), contextlib.chdir(self.root):
            self.engine.worktrees()
        self.assertFalse(work.exists(), self.entry.actions)
        restored = self.restored_copy(work)
        self.assertEqual(self.git(restored, 'rev-parse', 'HEAD'), final)
        self.assertEqual(self.git(restored, 'show', '-s', '--format=%s', draft), 'draft')
        self.assertEqual(self.git(restored, 'rev-parse', 'refs/coldcleaner/reflog/' + draft), draft)

    def test_removal_refuses_unique_reflog_history_that_was_not_bundled(self):
        repo, work = self.worktree()
        head = self.git(work, 'rev-parse', 'HEAD')
        (work / 'tracked').write_text('unique')
        self.git(work, 'commit', '-am', 'unique')
        unique = self.git(work, 'rev-parse', 'HEAD')
        self.git(work, 'reset', '--hard', head)
        listing = self.git(repo, 'ls-remote', str(self.root / 'remote.git'))
        self.assertEqual(reclaim.probe(self.host, 'repo', path=str(work), listing=listing)['reflog'], [unique])
        for request in (dict(), dict(manifest={}, security={}, reflog=[])):
            with self.subTest(request=request), self.assertRaisesRegex(ValueError, 'Git proof changed before removal'):
                reclaim.probe(self.host, 'remove', path=str(work), head=head, branch='done',
                              remote=str(self.root / 'remote.git'), listing=listing, **request)
        self.assertTrue(work.exists())
        with self.assertRaisesRegex(ValueError, 'invalid reflog commit'):
            reclaim_probe.reflog_ref('HEAD')

    def test_published_reflog_history_allows_worktree_cleanup(self):
        repo, work = self.worktree()
        head = self.git(work, 'rev-parse', 'HEAD')
        (work / 'tracked').write_text('published history')
        self.git(work, 'commit', '-am', 'published history')
        self.git(work, 'push', 'origin', 'done')
        self.git(work, 'reset', '--hard', head)
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
        self.assertFalse(work.exists(), self.entry.actions)
        self.assertEqual(self.entry.actions[-1]['action'], 'remove worktree and local branch')

    def test_stash_in_the_main_checkout_does_not_hold_a_clean_linked_worktree(self):
        repo, work = self.worktree()
        (repo / 'tracked').write_text('stashed')
        self.git(repo, 'stash')
        stash = self.git(repo, 'rev-parse', 'refs/stash')
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
        self.assertFalse(work.exists(), self.entry.actions)
        self.assertEqual(self.git(repo, 'rev-parse', 'refs/stash'), stash)
        self.assertTrue(reclaim.probe(self.host, 'repo', path=str(repo))['stashes'])
        with self.assertRaisesRegex(ValueError, 'uncommitted work or stashes'):
            self.engine.safe(str(repo), archive=True)
        self.assertTrue(repo.exists())
        self.assertEqual(self.git(repo, 'rev-parse', 'refs/stash'), stash)
        self.git(repo, 'init', '--separate-git-dir', str(self.root / 'metadata'))
        self.git(repo, 'config', 'core.worktree', str(repo))
        self.assertTrue((repo / '.git').is_file())
        self.assertTrue(reclaim.probe(self.host, 'repo', path=str(repo))['stashes'])
        self.engine.worktrees()
        self.assertIn('uncommitted work or stashes', self.entry.actions[-1]['reason'])
        with self.assertRaisesRegex(ValueError, 'registered worktree must use Git retirement'):
            self.engine.safe(str(repo), archive=True)
        self.assertEqual(self.git(repo, 'rev-parse', 'refs/stash'), stash)
        self.shared_stash_keeps_other_worktree_holds_strict(repo, stash)

    def test_unpushed_skip_names_the_remote_that_was_checked(self):
        repo, work = self.worktree()
        (work / 'tracked').write_text('local only')
        self.git(work, 'commit', '-am', 'local only')
        head = self.git(work, 'rev-parse', 'HEAD')
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
        action = next(row for row in self.entry.actions if row['path'] == str(work))
        self.assertEqual(action['action'], 'skip')
        self.assertIn('is not on ' + str(self.root / 'remote.git'), action['reason'])
        self.assertIn(head[:12], action['reason'])

    def test_real_dirty_and_unpushed_worktrees_are_retained(self):
        repo, work = self.worktree()
        (work / 'tracked').write_text('unique dirty data')
        self.engine.apply = True
        self.engine.worktrees()
        self.assertEqual((work / 'tracked').read_text(), 'unique dirty data')
        self.assertIn('uncommitted', self.entry.actions[-1]['reason'])
        self.git(work, 'commit', '-am', 'unpushed')
        self.engine.worktrees()
        self.assertTrue(work.exists())
        self.assertIn('unpushed', self.entry.actions[-1]['reason'])

    def shared_stash_keeps_other_worktree_holds_strict(self, repo, stash):
        work = self.root / 'work'
        self.git(repo, 'worktree', 'add', '-b', 'done', str(work))
        original = self.engine.proof
        self.engine.apply = True
        for hold in ('dirty', 'unpushed', 'open', 'process', 'thread'):
            with self.subTest(hold=hold):
                self.engine.activity = None
                def proof(path, fresh=False):
                    state, prs, listing = original(path, fresh)
                    if hold == 'open':
                        prs = [dict(state='OPEN', headRefOid=state['head'])]
                    elif hold in ('process', 'thread'):
                        prs = [dict(state='CLOSED', headRefOid=state['head'])]
                    return state, prs, listing
                self.engine.proof = proof
                if hold in ('dirty', 'unpushed'):
                    (work / 'tracked').write_text(hold)
                if hold == 'unpushed':
                    self.git(work, 'commit', '-am', 'unpushed')
                with patch.object(reclaim_probe, 'references', return_value=[str(work)] if hold == 'process' else []), \
                        patch.object(reclaim_probe, 'threads', return_value=[str(work)] if hold == 'thread' else []):
                    self.engine.worktrees()
                self.assertTrue(work.exists(), self.entry.actions)
                expected = dict(dirty='uncommitted', unpushed='unpushed', open='open pull request',
                                process='running process', thread='T3 thread')[hold]
                self.assertIn(expected, self.entry.actions[-1]['reason'])
                if hold == 'dirty':
                    self.git(work, 'restore', 'tracked')
                if hold == 'unpushed':
                    self.git(work, 'push', 'origin', 'done')
                self.assertEqual(self.git(repo, 'rev-parse', 'refs/stash'), stash)

    def test_merged_worktree_uses_existing_one_day_grace(self):
        repo, work = self.worktree()
        self.config['worktree_idle_days'] = 7
        stamp = time.time() - 2 * 86400
        for path in [*work.rglob('*'), work]:
            os.utime(path, (stamp, stamp))
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
        self.assertFalse(work.exists(), self.entry.actions)
        self.assertEqual(self.git(repo, 'branch', '--list', 'done'), '')

    def test_closed_unmerged_worktree_keeps_configured_seven_day_grace(self):
        repo, work = self.worktree()
        (work / 'tracked').write_text('closed work')
        self.git(work, 'commit', '-am', 'closed change')
        self.git(work, 'push', 'origin', 'done')
        original = self.engine.proof
        def closed(path, fresh=False):
            state, prs, listing = original(path, fresh)
            return state, [dict(state='CLOSED', headRefOid=state['head'])], listing
        self.engine.proof = closed
        self.config['worktree_idle_days'] = 7
        stamp = time.time() - 2 * 86400
        for path in [*work.rglob('*'), work]:
            os.utime(path, (stamp, stamp))
        self.engine.apply = True
        self.engine.worktrees()
        self.assertTrue(work.exists())
        self.assertIn('within 7 days', self.entry.actions[-1]['reason'])

    def test_shared_namespace_protects_root_and_explicit_child_references(self):
        namespace = str(self.root / 'factory'); child = namespace + '/old-data'
        protection = protect.Protection(self.host, str(self.root), {namespace}, [], {namespace})
        with patch.object(disk, 'python', return_value={child: ''}) as remote:
            checked = protection.batch([namespace, child])
        self.assertIn('scheduler references', checked[namespace])
        self.assertEqual(checked[child], '')
        remote.assert_called_once()
        protection.paths.add(child + '/live-state')
        self.assertIn('live-state', protection.batch([child])[child])

    def test_archive_retains_nested_dirty_repository(self):
        repo, work = self.worktree()
        stage = self.root / 'stage'; stage.mkdir()
        nested = stage / 'clone'
        self.git(self.root, 'clone', str(repo), str(nested))
        (nested / 'tracked').write_text('another agent is editing this')
        stamp = time.time() - 8 * 86400
        for path in [*stage.rglob('*'), stage]:
            os.utime(path, (stamp, stamp))
        self.config['hosts']['test']['archive'] = [str(stage)]
        self.engine.apply = True
        self.engine.archives()
        self.assertEqual((nested / 'tracked').read_text(), 'another agent is editing this')
        self.assertIn('uncommitted', self.entry.actions[-1]['reason'])
        self.assertFalse((self.root / 'nas').exists())

    def test_permission_change_after_backup_retains_original(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('private'); (source / 'unique').chmod(0o644)
        record, manifest, security = reclaim.preserve(self.host, str(source), self.root / 'nas', lambda: None)
        (source / 'unique').chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'security changed'):
            reclaim.probe(self.host, 'remove', path=str(source), manifest=manifest, security=security)
        self.assertEqual((source / 'unique').read_text(), 'private')
        self.assertTrue(Path(record.archive_path).exists())

    def archive_preview(self):
        stamp = time.time() - 8 * 86400
        for name in ('old', 'older'):
            folder = self.root / name; folder.mkdir(); (folder / 'data').write_text(name)
            for path in (folder / 'data', folder):
                os.utime(path, (stamp, stamp))
        (self.root / 'fresh').mkdir(); (self.root / 'fresh' / 'data').write_text('new')
        self.config['archive_idle_days'] = 4
        self.config['hosts']['test']['archive'] = [str(self.root / name) for name in ('old', 'older', 'fresh', 'missing')]
        self.entry.actions.clear()
        calls = []
        def counted(host, operation, **request):
            calls.append(operation)
            return local(host, operation, **request)
        local = reclaim.probe.side_effect
        with patch.object(reclaim, 'probe', side_effect=counted):
            self.engine = reclaim.Reclaimer(self.host, self.config, False, self.protection, self.entry)
            self.engine.archives()
        return [(row['path'], row['action'], row['reason']) for row in self.entry.actions], calls

    def test_archive_preview_batches_read_only_checks(self):
        (self.root / 'missing').mkdir(); (self.root / 'missing').rmdir()
        with patch.object(reclaim, 'BATCH', 1000):
            batched, calls = self.archive_preview()
        self.assertEqual(calls.count('batch'), 1)
        self.assertFalse({'guard', 'context', 'repositories'} & set(calls))
        for name in ('old', 'older', 'fresh'):
            shutil.rmtree(self.root / name)
        with patch.object(reclaim.Reclaimer, 'prefetch'):
            single, calls = self.archive_preview()
        self.assertIn('guard', calls)
        self.assertEqual(batched, single)
        self.assertEqual([action for _, action, _ in batched], ['skip', 'would archive and remove', 'would archive and remove'])

    def test_archive_preview_falls_back_when_a_batch_fails(self):
        local = reclaim.probe.side_effect
        def failing(host, operation, **request):
            if operation == 'batch':
                raise RuntimeError('ssh dropped')
            return local(host, operation, **request)
        with patch.object(reclaim.probe, 'side_effect', failing):
            actions, calls = self.archive_preview()
        self.assertIn('guard', calls)
        self.assertEqual([action for _, action, _ in actions], ['skip', 'would archive and remove', 'would archive and remove'])

    def test_batch_skips_remaining_checks_for_a_rejected_path(self):
        (self.root / 'fresh').mkdir()
        results = reclaim_probe.main(dict(operation='batch', activity=dict(threads=[], references=[]), requests=[
            dict(operation='guard', path=str(self.root / 'fresh'), days=4),
            dict(operation='repositories', path=str(self.root / 'fresh'))]))
        self.assertTrue(results[0]['value'])
        self.assertEqual(results[1], dict(skipped=True))

    def test_batch_refuses_changing_operations(self):
        with self.assertRaisesRegex(ValueError, 'read-only'):
            reclaim_probe.main(dict(operation='batch', requests=[dict(operation='remove', path=str(self.root))]))

    def test_archive_keeps_common_repository_and_registered_worktree(self):
        repo, work = self.worktree()
        stamp = time.time() - 8 * 86400
        for root in (repo, work):
            for path in [*root.rglob('*'), root]:
                os.utime(path, (stamp, stamp))
        self.config['hosts']['test']['archive'] = [str(repo), str(work)]
        self.engine.apply = True
        self.engine.archives()
        self.assertTrue(repo.is_dir())
        self.assertTrue(work.is_dir())
        reasons = {row['path']: row['reason'] for row in self.entry.actions}
        self.assertIn('owns other registered worktrees', reasons[str(repo)])
        self.assertIn('must use Git retirement', reasons[str(work)])
        self.assertFalse((self.root / 'nas').exists())

    def test_discovery_retains_bad_git_marker_and_finds_other_real_worktrees(self):
        repo, work = self.worktree()
        broken = self.root / 'broken'; broken.mkdir(); (broken / '.git').write_text('invalid')
        found = reclaim_probe.discover([str(self.root)])
        self.assertEqual(found['paths'], [str(work)])
        self.assertEqual(found['errors'], [])
        self.assertTrue(any(str(broken) in note for note in found['notes']))
        self.assertEqual((broken / '.git').read_text(), 'invalid')

    def stale_archive_with_nested_git_stub(self, held=None):
        stamp = time.time() - 8 * 86400
        temp = self.root / ('tmpstub-' + (held or 'empty').replace('/', '-'))
        stub = temp / 'runs' / 'work' / '.git' / 'objects'
        stub.mkdir(parents=True)
        if held:
            (stub.parent / held).parent.mkdir(parents=True, exist_ok=True)
            (stub.parent / held).write_text('0' * 40)
        (temp / 'runs' / 'work' / 'data').write_text('scratch')
        for path in (*temp.rglob('*'), temp):
            os.utime(path, (stamp, stamp))
        self.config['archive_idle_days'] = 4
        self.config['hosts']['test']['archive'] = [str(temp)]
        self.entry.actions.clear()
        return temp

    def test_broken_nested_git_stub_is_a_note_but_a_broken_repository_with_git_data_is_an_error(self):
        stub = self.stale_archive_with_nested_git_stub()
        damaged = {name: self.stale_archive_with_nested_git_stub(data) for name, data in (
            ('refs', 'refs/heads/main'), ('worktrees', 'worktrees/linked/gitdir'), ('packed-refs', 'packed-refs'),
            ('logs', 'logs/HEAD'), ('index', 'index'), ('orig-head', 'ORIG_HEAD'), ('config', 'config'))}
        self.config['hosts']['test']['archive'] = [str(stub), *map(str, damaged.values())]
        self.entry.actions.clear()
        self.engine.archives()
        actions = {row['path']: row for row in self.entry.actions}
        self.assertEqual(actions[str(stub)]['action'], 'would archive and remove')
        for name, path in damaged.items():
            self.assertEqual(actions[str(path)]['action'], 'error', name)
            self.assertIn('not a git repository', actions[str(path)]['reason'], name)
        self.assertEqual(len(self.entry.notes), 1)
        self.assertIn(str(stub / 'runs' / 'work'), self.entry.notes[0])

    def test_broken_nested_git_stub_inside_an_enclosing_repository_is_still_a_stub(self):
        enclosing = self.root / 'enclosing'; enclosing.mkdir()
        self.git(enclosing, 'init', '-b', 'main')
        stub = enclosing / 'scratch'
        (stub / '.git' / 'objects').mkdir(parents=True)
        request = dict(operation='repo', path=str(stub), stub_ok=True)
        found = []
        self.assertIsNone(self.failure(lambda: found.append(reclaim_probe.main(request))))
        self.assertEqual(found, [None])
        (stub / '.git' / 'index').write_text('staged')
        with self.assertRaisesRegex(ValueError, 'not a repository root'):
            reclaim_probe.main(request)
        with self.assertRaisesRegex(ValueError, 'not a repository root'):
            reclaim_probe.main(dict(request, stub_ok=False))

    def test_broken_nested_git_stub_marks_the_git_check_satisfied(self):
        self.stale_archive_with_nested_git_stub()
        self.engine.archives()
        self.protection.reason.assert_called()
        self.assertTrue(self.protection.reason.call_args.kwargs['allow_git'])

    def test_non_repository_markers_are_notes_and_do_not_fail_the_host(self):
        broken = self.root / 'backup'; broken.mkdir(); (broken / '.git').mkdir()
        self.config['hosts']['test']['roots'] = [str(self.root)]
        self.engine.worktrees()
        self.assertEqual(self.entry.errors, [])
        self.assertEqual(len(self.entry.notes), 1)
        self.assertIn(str(broken), self.entry.notes[0])
        self.assertIn(str(broken), report.render([self.entry]))

    def test_other_git_failures_during_discovery_stay_errors(self):
        repo = self.root / 'not a git repository (or any parent)' / 'repo'; repo.mkdir(parents=True); (repo / '.git').mkdir()
        failure = RuntimeError(f"fatal: detected dubious ownership in repository at '{repo}' (not a git repository (or any parent)")
        with patch.object(reclaim_probe, 'git', side_effect=failure):
            found = reclaim_probe.discover([str(self.root)])
        self.assertEqual(found['notes'], [])
        self.assertEqual(len(found['errors']), 1)
        self.assertIn('dubious ownership', found['errors'][0])

    def test_unreadable_folders_and_unloadable_repositories_are_retained_as_notes(self):
        locked = self.root / 'container-evidence'; locked.mkdir(); locked.chmod(0)
        self.addCleanup(locked.chmod, 0o700)
        include = self.root / 'not-git-config.json'; include.write_text('{"key": "value"}\n')
        fixture = self.root / 'config-include'
        self.git(self.root, 'init', '-q', str(fixture))
        self.git(fixture, 'config', 'include.path', str(include))
        self.config['hosts']['test']['roots'] = [str(self.root)]
        self.engine.worktrees()
        self.assertEqual(self.entry.errors, [])
        self.assertEqual(len(self.entry.notes), 2)
        self.assertTrue(any('Unreadable, skipped' in note and str(locked) in note for note in self.entry.notes))
        self.assertTrue(any('Git cannot read' in note and str(fixture) in note for note in self.entry.notes))
        self.assertEqual(self.entry.actions, [])
        self.assertTrue((fixture / '.git').is_dir())
        healthy = self.root / 'healthy'
        self.git(self.root, 'init', '-q', '-b', 'main', str(healthy))
        self.git(healthy, '-c', 'user.name=t', '-c', 'user.email=t@localhost', 'commit', '-q', '--allow-empty', '-m', 'base')
        conditional = self.root / 'global.gitconfig'
        conditional.write_text(f'[includeIf "onbranch:main"]\n\tpath = {include}\n')
        for shared in (dict(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='include.path', GIT_CONFIG_VALUE_0=str(include)),
                       dict(GIT_CONFIG_GLOBAL=str(conditional))):
            with patch.dict(os.environ, shared):
                found = reclaim_probe.discover([str(self.root)])
            self.assertTrue(any(str(healthy) in error and 'bad config' in error for error in found['errors']), shared)
            self.assertFalse(any(str(healthy) in note for note in found['notes']), shared)

    def test_empty_unborn_repository_is_archived_but_one_with_staged_work_is_kept(self):
        stamp = time.time() - 8 * 86400
        scratch = {}
        for name in ('empty', 'staged', 'tagged'):
            scratch[name] = self.root / name
            repo = scratch[name] / 'base' / 'self-product'
            self.git(self.root, 'init', '-q', '-b', 'master', str(repo))
            if name == 'staged':
                (repo / 'draft.txt').write_text('only copy')
                self.git(repo, 'add', 'draft.txt')
            if name == 'tagged':
                self.git(repo, 'symbolic-ref', 'HEAD', 'refs/tags/missing')
            for path in (*scratch[name].rglob('*'), scratch[name]):
                os.utime(path, (stamp, stamp))
        self.config['archive_idle_days'] = 4
        self.config['hosts']['test']['archive'] = [str(path) for path in scratch.values()]
        self.engine.archives()
        actions = {row['path']: row for row in self.entry.actions}
        self.assertEqual(actions[str(scratch['empty'])]['action'], 'would archive and remove')
        self.assertEqual(actions[str(scratch['staged'])]['action'], 'skip')
        self.assertIn('uncommitted work', actions[str(scratch['staged'])]['reason'])
        self.assertEqual(actions[str(scratch['tagged'])]['action'], 'error')

    def test_worktree_with_missing_gitdir_stays_an_error(self):
        orphan = self.root / 'orphan'; orphan.mkdir()
        (orphan / '.git').write_text(f'gitdir: {self.root}/gone/.git/worktrees/orphan\n')
        found = reclaim_probe.discover([str(self.root)])
        self.assertEqual(found['notes'], [])
        self.assertEqual(len(found['errors']), 1)
        self.assertIn(str(orphan), found['errors'][0])

    def test_temp_retention_cache_exclusion_and_vm_disks_are_retained(self):
        self.assertEqual(reclaim.retention('/tmp/test-output', 4), 7)
        self.assertEqual(reclaim.retention('C:\\Users\\user\\AppData\\Local\\Temp\\job', 4), 7)
        self.assertEqual(reclaim.retention('/evidence', 14), 14)
        for path in ('/tmp/node-compile-cache', '/home/user/.cache/uv', 'C:\\Users\\user\\npm-cache'):
            self.assertTrue(reclaim.package_cache(path))
        path = self.root / 'base.vhdx'; path.write_bytes(b'VM state')
        with self.assertRaisesRegex(ValueError, 'hypervisor dependency'):
            reclaim_probe.guard(path)
        self.assertEqual(path.read_bytes(), b'VM state')

    def test_drive_unmounted_after_the_copy_keeps_the_worktree(self):
        repo, work = self.worktree()
        evidence = work / 'evidence/result.bin'; evidence.parent.mkdir(); evidence.write_bytes(b'unique')
        self.config['local_archive_mount'] = '/mnt/backup'
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection), contextlib.chdir(self.root), \
                patch.object(reclaim, 'check_nas', side_effect=[None, RuntimeError('archive drive is not mounted')]) as check:
            self.engine.worktrees()
        self.assertEqual(check.call_count, 2)
        self.assertTrue(evidence.exists())
        self.assertEqual(self.entry.actions[-1]['action'], 'error', self.entry.actions)

    def test_drive_unplugged_during_final_git_proof_keeps_the_worktree(self):
        repo, work = self.worktree()
        evidence = work / 'evidence/result.bin'; evidence.parent.mkdir(); evidence.write_bytes(b'unique')
        self.config['local_archive_mount'] = '/mnt/backup'
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection), contextlib.chdir(self.root), \
                patch.object(reclaim, 'check_nas', side_effect=[None, None, RuntimeError('archive drive is not mounted')]) as check:
            self.engine.worktrees()
        self.assertEqual(check.call_count, 3)
        self.assertTrue(evidence.exists())
        self.assertIn('not mounted', self.entry.actions[-1]['reason'])

    def test_drive_unplugged_after_the_source_scan_keeps_the_archive_source(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('keep')
        stamp = time.time() - 8 * 86400
        for path in [*source.rglob('*'), source]:
            os.utime(path, (stamp, stamp))
        self.config['hosts']['test']['archive'] = [str(source)]
        self.config['local_archive_mount'] = '/mnt/backup'
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection), contextlib.chdir(self.root), \
                patch.object(reclaim, 'check_nas', side_effect=[None, None, RuntimeError('archive drive is not mounted')]) as check:
            self.engine.archives()
        self.assertEqual(check.call_count, 3)
        self.assertEqual((source / 'unique').read_text(), 'keep')
        self.assertIn('not mounted', self.entry.actions[-1]['reason'])

    def test_local_drive_mode_refuses_remote_hosts(self):
        self.config['local_archive_mount'] = '/mnt/backup'
        self.engine.host = Mock(ssh='far.example')
        with patch.object(reclaim, 'check_nas') as check, self.assertRaisesRegex(RuntimeError, 'only supports data on the controller'):
            self.engine.archive_target('/remote/path')
        check.assert_not_called()

    def test_removal_probe_keeps_the_source_when_the_archive_vanished(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('keep')
        record, manifest, security = reclaim.preserve(self.host, str(source), self.root / 'nas', lambda: None)
        keep = dict(file=record.archive_path, bytes=record.archive_bytes, mount=None)
        Path(record.archive_path).unlink()
        with self.assertRaisesRegex(ValueError, 'verified archive is no longer present'):
            reclaim.probe(self.host, 'remove', path=str(source), manifest=manifest, security=security, keep=keep)
        self.assertEqual((source / 'unique').read_text(), 'keep')
        self.assertEqual([item.name for item in self.root.iterdir() if 'coldcleaner-removing' in item.name], [])

    def test_removal_probe_keeps_the_source_when_the_drive_is_not_mounted(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('keep')
        record, manifest, security = reclaim.preserve(self.host, str(source), self.root / 'nas', lambda: None)
        keep = dict(file=record.archive_path, bytes=record.archive_bytes, mount=str(self.root / 'nas'))
        with self.assertRaisesRegex(ValueError, 'verified archive is no longer present'):
            reclaim.probe(self.host, 'remove', path=str(source), manifest=manifest, security=security, keep=keep)
        self.assertEqual((source / 'unique').read_text(), 'keep')

    def test_removal_probe_removes_the_source_when_the_archive_is_present(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('keep')
        record, manifest, security = reclaim.preserve(self.host, str(source), self.root / 'nas', lambda: None)
        keep = dict(file=record.archive_path, bytes=record.archive_bytes, mount=None)
        reclaim.probe(self.host, 'remove', path=str(source), manifest=manifest, security=security, keep=keep)
        self.assertFalse(source.exists())

    def test_archive_missing_when_removal_is_about_to_start_keeps_the_source(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('keep')
        def lose_archive():
            for saved in (self.root / 'nas').rglob('*.tar.zst'):
                saved.unlink()
        with self.assertRaisesRegex(ValueError, 'verified archive is no longer present'):
            reclaim.preserve(self.host, str(source), self.root / 'nas', lose_archive)
        self.assertEqual((source / 'unique').read_text(), 'keep')

    def test_replacement_drive_after_the_copy_keeps_the_worktree(self):
        repo, work = self.worktree()
        evidence = work / 'evidence/result.bin'; evidence.parent.mkdir(); evidence.write_bytes(b'unique')
        self.config['local_archive_mount'] = '/mnt/backup'
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection), contextlib.chdir(self.root), \
                patch.object(reclaim, 'check_nas', side_effect=[111, 222]):
            self.engine.worktrees()
        self.assertTrue(evidence.exists())
        self.assertIn('archive drive changed', self.entry.actions[-1]['reason'])

    def test_ignored_worktree_evidence_is_preserved_and_hash_verified(self):
        repo, work = self.worktree()
        evidence = work / 'evidence/result.bin'; evidence.parent.mkdir(); evidence.write_bytes(b'unique\x00\xff')
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection), contextlib.chdir(self.root):
            self.engine.worktrees()
        self.assertFalse(work.exists(), self.entry.actions)
        saved = list((self.root / 'nas').rglob('*.tar.zst'))
        self.assertEqual(len(saved), 1)
        with tarfile.open(saved[0], 'r:zst') as archive:
            self.assertEqual(archive.extractfile('work/evidence/result.bin').read(), b'unique\x00\xff')
        self.assertIn('SHA-256 verified', self.entry.actions[-1]['reason'])
        restored = self.root / 'recovered-worktree'
        stored = store._read_index(self.root / 'nas')[0]
        store.restore(stored.id, self.root / 'nas', to=str(restored))
        self.assertEqual(self.git(restored, 'rev-parse', 'HEAD'), self.git(repo, 'rev-parse', 'main'))
        self.assertEqual(self.git(restored, 'symbolic-ref', '--short', 'HEAD'), 'done')
        self.assertEqual(self.git(restored, 'status', '--porcelain'), '')
        self.assertEqual((restored / 'evidence/result.bin').read_bytes(), b'unique\x00\xff')

    def test_discovery_never_admits_a_registered_ancestor_of_an_allowed_root(self):
        repo, work = self.worktree()
        nested = work / 'nested-root'; nested.mkdir()
        discovered = reclaim_probe.discover([str(repo), str(nested)])
        self.assertNotIn(str(work), discovered['paths'])
        self.assertTrue(work.exists())

    def test_excluded_package_cache_row_has_no_idle_window(self):
        cache = self.root / '.cache'; cache.mkdir(); (cache / 'package').write_text('leave alone')
        self.config['hosts']['test']['archive'] = [str(cache)]
        self.engine.archives()
        row = self.entry.actions[-1]
        self.assertEqual((row['action'], row['reason'], row['rule'], row['idle_days']),
                         ('skip', 'package caches are excluded', 'test.archive:' + str(cache), None))

    def test_nested_package_cache_retains_the_entire_candidate(self):
        source = self.root / 'evidence'; source.mkdir()
        cache = source / 'nested' / '.npm'; cache.mkdir(parents=True)
        (cache / 'package').write_text('leave package caches alone')
        self.config['hosts']['test']['archive'] = [str(source)]
        self.engine.apply = True
        self.engine.archives()
        self.assertEqual((cache / 'package').read_text(), 'leave package caches alone')
        self.assertIn('package caches', self.entry.actions[-1]['reason'])
        self.assertFalse((self.root / 'nas').exists())

    def test_package_cache_is_rejected_before_any_per_file_safety_check(self):
        source = self.root / 'prereqs'
        for index in range(20):
            (source / 'build' / str(index)).mkdir(parents=True)
        (source / '.cache' / 'uv').mkdir(parents=True)
        with patch.object(os, 'listxattr', wraps=os.listxattr) as safety:
            with self.assertRaisesRegex(ValueError, 'package caches are excluded'):
                reclaim_probe.tree(source)
        safety.assert_not_called()

    def test_archive_parent_retains_its_registered_worktree(self):
        repo, work = self.worktree()
        staging = self.root / 'staging'; staging.mkdir()
        nested = staging / 'work'
        self.git(repo, 'worktree', 'move', str(work), str(nested))
        stamp = time.time() - 8 * 86400
        for path in [*nested.rglob('*'), nested, staging]:
            os.utime(path, (stamp, stamp))
        self.config['hosts']['test']['archive'] = [str(staging)]
        self.engine.apply = True
        self.engine.archives()
        self.assertTrue(nested.exists())
        self.assertIn('Git retirement', self.entry.actions[-1]['reason'])
        self.assertIn('done', self.git(repo, 'branch', '--list', 'done'))
        self.assertFalse((self.root / 'nas').exists())

    def test_verified_archive_copy_and_manifest_protect_changed_source(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_bytes(b'unique\x00\xff')
        record, manifest, security = reclaim.preserve(self.host, str(source), self.root / 'nas', lambda: None)
        self.assertTrue(source.exists())
        with tarfile.open(record.archive_path, 'r:zst') as archive:
            self.assertEqual(archive.extractfile('evidence/unique').read(), b'unique\x00\xff')
        self.assertEqual(manifest['evidence/unique'], hashlib.sha256(b'unique\x00\xff').hexdigest())
        (source / 'unique').write_bytes(b'changed!')
        with self.assertRaisesRegex(ValueError, 'source changed'):
            reclaim.probe(self.host, 'remove', path=str(source), manifest=manifest)
        self.assertEqual((source / 'unique').read_bytes(), b'changed!')

    def test_write_after_manifest_check_retains_source(self):
        source = self.root / 'evidence'; source.mkdir()
        (source / 'unique').write_text('archived')
        record, manifest, security = reclaim.preserve(self.host, str(source), self.root / 'nas', lambda: None)
        original = reclaim_probe.tree
        def write_after_check(path, hashes=False):
            result = original(path, hashes)
            if hashes and Path(path) == source:
                (source / 'late-write').write_text('not archived')
            return result
        with patch.object(reclaim_probe, 'tree', side_effect=write_after_check):
            with self.assertRaisesRegex(ValueError, 'source changed after verified NAS copy'):
                reclaim.probe(self.host, 'remove', path=str(source), manifest=manifest)
        self.assertTrue(source.is_dir())
        self.assertEqual((source / 'unique').read_text(), 'archived')
        self.assertEqual((source / 'late-write').read_text(), 'not archived')
        self.assertTrue(Path(record.archive_path).is_file())

    def test_failed_git_restore_leaves_destination_absent_and_allows_retry(self):
        repo, work = self.worktree()
        evidence = work / 'evidence/result.bin'; evidence.parent.mkdir(); evidence.write_bytes(b'unique')
        record, manifest, security = reclaim.preserve(self.host, str(work), self.root / 'nas', lambda: None)
        receipt = Path(record.archive_path).with_suffix('.sha256.json')
        original = receipt.read_text()
        saved = json.loads(original)
        saved['git']['sha256'] = '0' * 64
        receipt.write_text(json.dumps(saved))
        destination = self.root / 'recovered-worktree'
        with self.assertRaisesRegex(RuntimeError, 'Git recovery bundle SHA-256 mismatch'):
            store.restore(record.id, self.root / 'nas', to=str(destination))
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob('.coldcleaner-restore-*')), [])
        receipt.write_text(original)
        store.restore(record.id, self.root / 'nas', to=str(destination))
        self.assertEqual(self.git(destination, 'rev-parse', 'HEAD'), self.git(repo, 'rev-parse', 'main'))
        self.assertEqual(self.git(destination, 'status', '--porcelain'), '')
        self.assertEqual((destination / 'evidence/result.bin').read_bytes(), b'unique')
        self.assertEqual(list(self.root.glob('.coldcleaner-restore-*')), [])

    def test_reclaim_archive_is_searchable_restorable_and_never_cap_expired(self):
        source = self.root / 'evidence'; source.mkdir()
        (source / 'unique').write_bytes(b'unique\x00\xff'); (source / 'unique').chmod(0o600)
        record, manifest, security = reclaim.preserve(self.host, str(source), self.root / 'nas', lambda: None)
        matches = store.find('unique', self.root / 'nas')
        self.assertEqual(matches[0].matches, ('evidence/unique',))
        restored = self.root / 'recovered'
        store.restore(record.id, self.root / 'nas', to=str(restored))
        self.assertEqual((restored / 'unique').read_bytes(), b'unique\x00\xff')
        self.assertEqual((restored / 'unique').stat().st_mode & 0o777, 0o600)
        with self.assertRaises(RuntimeError):
            store.restore(record.id, self.root / 'nas', to=str(restored))
        selected = self.root / 'member'
        store.restore(record.id, self.root / 'nas', to=str(selected), member='evidence/unique')
        self.assertEqual((selected / 'unique').read_bytes(), b'unique\x00\xff')
        self.assertTrue(Path(record.archive_path).exists())
        with tarfile.open(record.archive_path, 'r:zst') as archive:
            self.assertEqual(archive.extractfile('evidence/unique').read(), b'unique\x00\xff')

    def test_corrupt_or_incomplete_archive_never_reaches_removal(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('before')
        original = hosts.python_stream
        def change(*args, **kwargs):
            (source / 'unique').write_text('after!')
            return original(*args, **kwargs)
        removed = Mock()
        with patch.object(hosts, 'python_stream', side_effect=change), self.assertRaisesRegex(RuntimeError, 'SHA-256'):
            reclaim.preserve(self.host, str(source), self.root / 'nas', removed)
        removed.assert_not_called()
        self.assertEqual((source / 'unique').read_text(), 'after!')

    def test_new_live_protection_retains_source_after_verified_copy(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('keep')
        with self.assertRaisesRegex(ValueError, 'new activity'):
            reclaim.preserve(self.host, str(source), self.root / 'nas',
                             lambda: (_ for _ in ()).throw(ValueError('new activity')))
        self.assertEqual((source / 'unique').read_text(), 'keep')
        self.assertEqual(len(list((self.root / 'nas').rglob('*.tar.zst'))), 1)

    def test_copy_interrupted_before_indexing_is_retired_by_the_next_attempt(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('keep')
        legacy = self.root / 'nas/test/2026-01-01' / ('f' * 32); legacy.mkdir(parents=True)
        (legacy / 'old.tar.zst').write_bytes(b'unindexed, not ours')
        with patch.object(store, '_write_index', side_effect=OSError('NAS went away')), self.assertRaises(OSError):
            reclaim.preserve(self.host, str(source), self.root / 'nas', lambda: None)
        unlink = Path.unlink
        def stuck(path, *args, **kwargs):
            if path.name.endswith('.tar.zst'):
                raise OSError('NAS unlink failed')
            return unlink(path, *args, **kwargs)
        with patch.object(Path, 'unlink', autospec=True, side_effect=stuck), self.assertRaises(OSError):
            reclaim.preserve(self.host, str(source), self.root / 'nas', lambda: None)
        record, _, _ = reclaim.preserve(self.host, str(source), self.root / 'nas', lambda: None)
        archives = sorted((self.root / 'nas').rglob('*.tar.zst'))
        self.assertEqual(archives, sorted([Path(record.archive_path), legacy / 'old.tar.zst']))
        self.assertEqual(list((self.root / 'nas').rglob(reclaim.ATTEMPT)), [])
        self.assertEqual([item.id for item in store._read_index(self.root / 'nas')], [record.id])

    def test_preserve_does_not_visit_every_archive_already_on_the_nas(self):
        nas = self.root / 'nas'
        records = []
        for number in range(300):
            ident = f'{number:032x}'
            directory = nas / 'test/2026-01-01' / ident; directory.mkdir(parents=True)
            (directory / (ident + '.tar.zst')).write_bytes(b'old')
            records.append(store.Record(ident, '2026-01-01T00:00:00+00:00', 'test', f'/old/{number}',
                                        str(directory / (ident + '.tar.zst')), 3, 3, 1, 'stored'))
        store._write_index(nas, records)
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('keep')
        visited = []
        def counted(function):
            def wrapper(path, *args, **kwargs):
                if str(path).startswith(str(nas / 'test/2026-01-01')):
                    visited.append(path)
                return function(path, *args, **kwargs)
            return wrapper
        with patch.object(os, 'scandir', counted(os.scandir)), \
                patch.object(os.path, 'realpath', counted(os.path.realpath)), \
                patch.object(os.path, 'lexists', counted(os.path.lexists)):
            record, _, _ = reclaim.preserve(self.host, str(source), nas, lambda: None)
        self.assertEqual(record.source_path, str(source))
        self.assertLess(len(visited), 30)
        for name in ('..+2026-01-01+' + 'a' * 32, 'test+not-a-date+' + 'a' * 32, 'test+2026-01-01+x'):
            (nas / reclaim.PENDING / name).touch()
            with self.assertRaisesRegex(RuntimeError, 'unexpected NAS attempt entry'):
                reclaim.preserve(self.host, str(self.root / 'evidence'), nas, lambda: None)
            (nas / reclaim.PENDING / name).unlink()
        self.assertTrue((nas / 'test/2026-01-01' / f'{0:032x}').is_dir())

    def test_verified_copy_indexed_before_an_interrupted_removal_is_reused_on_retry(self):
        repo, work = self.worktree()
        evidence = work / 'evidence/result.bin'; evidence.parent.mkdir(); evidence.write_bytes(b'unique')
        abort = lambda: (_ for _ in ()).throw(ValueError('new activity'))
        with self.assertRaisesRegex(ValueError, 'new activity'):
            reclaim.preserve(self.host, str(work), self.root / 'nas', abort)
        first = store._read_index(self.root / 'nas')[0]
        store._manifest_path(Path(first.archive_path)).unlink()
        record, _, _ = reclaim.preserve(self.host, str(work), self.root / 'nas', lambda: None)
        self.assertEqual(record.id, first.id)
        self.assertEqual([item.matches for item in store.find('result.bin', self.root / 'nas')],
                         [('work/evidence/result.bin',)])
        self.assertEqual(len(list((self.root / 'nas').rglob('*.tar.zst'))), 1)
        bundle = Path(first.archive_path).parent / 'head.bundle'
        original = bundle.read_bytes()
        bundle.write_bytes(original + b'\0')
        with self.assertRaisesRegex(RuntimeError, 'bundle SHA-256'):
            reclaim.preserve(self.host, str(work), self.root / 'nas', lambda: None)
        bundle.write_bytes(original)
        receipt = Path(first.archive_path).with_suffix('.sha256.json')
        receipt.write_text(json.dumps(dict(json.loads(receipt.read_text()), source=str(self.root / 'elsewhere'))))
        swapped, _, _ = reclaim.preserve(self.host, str(work), self.root / 'nas', lambda: None)
        self.assertNotEqual(swapped.id, first.id)
        self.git(work, '-c', 'user.name=Test', '-c', 'user.email=test@localhost',
                 'commit', '--allow-empty', '-m', 'new head')
        moved, _, _ = reclaim.preserve(self.host, str(work), self.root / 'nas', lambda: None)
        evidence.write_bytes(b'changed')
        changed, _, _ = reclaim.preserve(self.host, str(work), self.root / 'nas', lambda: None)
        self.assertEqual(len({first.id, moved.id, changed.id}), 3)
        Path(changed.archive_path).write_bytes(b'x' * changed.archive_bytes)
        with self.assertRaisesRegex(RuntimeError, 'test-read'):
            reclaim.preserve(self.host, str(work), self.root / 'nas', lambda: None)
        Path(changed.archive_path).with_suffix('.sha256.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'unreadable archive receipt'):
            reclaim.preserve(self.host, str(work), self.root / 'nas', lambda: None)

    def test_real_archive_preview_and_apply_never_touch_other_data_or_nas_expiry(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('keep a copy')
        cache = self.root / 'package-cache'; cache.mkdir(); (cache / 'data').write_text('leave alone')
        stamp = time.time() - 8 * 86400
        for path in (source / 'unique', source):
            os.utime(path, (stamp, stamp))
        self.config['hosts']['test']['archive'] = [str(source)]
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.archives()
            self.assertTrue(source.exists())
            self.assertFalse((self.root / 'nas').exists())
            self.engine.apply = True
            self.engine.archives()
        self.assertFalse(source.exists(), self.entry.actions)
        self.assertEqual((cache / 'data').read_text(), 'leave alone')
        self.assertIn('SHA-256 verified', self.entry.actions[-1]['reason'])

    def aged(self, name, days):
        source = self.root / 'evidence' / name; source.mkdir(parents=True); (source / 'data').write_text(name)
        stamp = time.time() - days * 86400
        for path in (source / 'data', source):
            os.utime(path, (stamp, stamp))
        return source

    def archive_now(self):
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.archives()
        return {Path(row['path']).name: (row['action'], row['idle_days']) for row in self.entry.actions}

    def test_thirty_day_pattern_keeps_day_29_and_archives_day_31(self):
        young, old = self.aged('29-days', 29), self.aged('31-days', 31)
        self.config['hosts']['test']['archive'] = [dict(path=str(self.root / 'evidence' / '*'), days=30)]
        rows = self.archive_now()
        self.assertTrue(young.exists())
        self.assertFalse(old.exists(), rows)
        self.assertEqual(rows['31-days'], ('archive and remove', 30))
        self.assertEqual(rows['29-days'][1], 30)
        self.assertNotEqual(rows['29-days'][0], 'archive and remove')

    def test_plain_pattern_still_uses_archive_idle_days(self):
        self.config['archive_idle_days'] = 30
        young, old = self.aged('29-days', 29), self.aged('31-days', 31)
        self.config['hosts']['test']['archive'] = [str(self.root / 'evidence' / '*')]
        rows = self.archive_now()
        self.assertEqual((young.exists(), old.exists()), (True, False), rows)

    def test_host_and_entry_excludes_are_never_candidates(self):
        sources = [self.aged(name, 31) for name in ('host-kept', 'entry-kept', 'holds-kept', 'gone')]
        (sources[2] / 'inner').mkdir()
        self.config['hosts']['test'].update(
            exclude=[str(self.root / 'evidence' / 'host-*')],
            archive=[dict(path=str(self.root / 'evidence' / '*'), days=30,
                          exclude=[str(sources[1]), str(sources[2] / 'inner')])])
        rows = self.archive_now()
        self.assertEqual([source.exists() for source in sources], [True, True, True, False], rows)
        self.assertEqual(set(rows), {'gone'})

    def test_entry_exclude_holds_against_every_matching_pattern(self):
        kept = self.aged('keep-me', 31)
        self.config['hosts']['test']['archive'] = [
            dict(path=str(self.root / 'evidence' / '*'), exclude=[str(kept)]), str(self.root / 'evidence' / 'keep-*')]
        rows = self.archive_now()
        self.assertTrue(kept.exists(), rows)
        self.assertEqual(rows, {})

    def test_overlapping_patterns_use_the_longest_retention(self):
        young = self.aged('29-days', 29)
        self.config['hosts']['test']['archive'] = [
            dict(path=str(self.root / 'evidence' / '*'), days=4), dict(path=str(young), days=30)]
        rows = self.archive_now()
        self.assertTrue(young.exists(), rows)
        self.assertEqual(rows['29-days'][1], 30)

    def test_nested_entry_rules_hold_their_parent_match(self):
        parent = self.aged('proj', 31)
        kept = parent / 'keep'; kept.mkdir(); other = parent / 'other'; other.mkdir()
        stamp = time.time() - 31 * 86400
        for path in (kept, other, parent):
            os.utime(path, (stamp, stamp))
        self.config['hosts']['test']['archive'] = [
            dict(path=str(parent), days=4), dict(path=str(parent / '*'), exclude=[str(kept)])]
        rows = self.archive_now()
        self.assertEqual((parent.exists(), kept.exists(), other.exists()), (True, True, False), rows)

    def test_nested_entry_with_longer_days_holds_its_parent(self):
        parent = self.aged('proj', 10)
        self.config['hosts']['test']['archive'] = [
            dict(path=str(parent), days=4), dict(path=str(parent / 'data'), days=30)]
        rows = self.archive_now()
        self.assertTrue(parent.exists(), rows)
        self.assertEqual(rows['proj'][1], 30)

    def test_folder_moved_into_a_match_after_the_scan_keeps_it(self):
        parent = self.aged('proj', 31)
        moved = self.aged('young', 10)
        self.config['hosts']['test']['archive'] = [
            dict(path=str(parent), days=4), dict(path=str(parent / 'young'), days=30)]
        original = reclaim.preserve
        def move_then_copy(*args):
            moved.rename(parent / 'young')
            return original(*args)
        with patch.object(reclaim, 'preserve', move_then_copy):
            rows = self.archive_now()
        self.assertTrue((parent / 'young').exists(), rows)
        self.assertEqual(rows['proj'][0], 'skip')
        self.assertIn('recent', self.entry.actions[-1]['reason'])

    def test_exclude_reached_through_a_symlink_alias_holds(self):
        kept = self.aged('kept', 31)
        alias = self.root / 'alias'; alias.symlink_to(kept)
        self.config['hosts']['test']['exclude'] = [str(alias)]
        self.config['hosts']['test']['archive'] = [str(self.root / 'evidence' / '*')]
        rows = self.archive_now()
        self.assertTrue(kept.exists(), rows)

    def test_exclude_created_after_the_scan_stops_removal(self):
        source = self.aged('late', 31)
        self.config['hosts']['test']['archive'] = [dict(path=str(source), exclude=[str(source / 'keep')])]
        original = reclaim.preserve
        def copy_then_exclude(*args):
            saved = original(*args)
            (source / 'keep').mkdir()
            stamp = time.time() - 31 * 86400
            for path in (source / 'keep', source):
                os.utime(path, (stamp, stamp))
            return saved
        with patch.object(reclaim, 'preserve', copy_then_exclude):
            self.archive_now()
        self.assertTrue((source / 'keep').exists())
        self.assertEqual((self.entry.actions[-1]['action'], self.entry.actions[-1]['reason']), ('skip', 'excluded by rules'))

    def limited_archives(self, sizes, **limits):
        sources = []
        stamp = time.time() - 8 * 86400
        for index, size in enumerate(sizes):
            source = self.root / f'evidence-{index}'; source.mkdir(); (source / 'data').write_text('x' * size)
            for path in (source / 'data', source):
                os.utime(path, (stamp, stamp))
            sources.append(source)
        self.config['hosts']['test'].update(archive=[str(source) for source in sources], **limits)
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.archives()
        return sources, [(row['action'], row['reason']) for row in self.entry.actions]

    def planned(self, source, **entry):
        self.config['hosts']['test']['archive'] = [dict(path=str(source), **entry)]
        self.entry = self.engine.report = report.HostReport('test')
        self.engine.apply = False
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.archives()
        plan = Path(self.config['report_dir']) / 'one.plan.json'
        plan.parent.mkdir(parents=True, exist_ok=True)
        reclaim.write_plan(plan, [self.entry], self.config.get('rules_sha256'))
        self.entry = self.engine.report = report.HostReport('test')
        return plan, json.loads(plan.read_text())['items']

    def approve(self, *argv):
        stdout = io.StringIO()
        with patch.object(rules, 'load', return_value=self.config), contextlib.redirect_stdout(stdout):
            return cli.main(['approve', *map(str, argv)]), stdout.getvalue()

    def test_dry_run_plan_lists_candidates_with_stable_ids_and_reasons(self):
        source = self.aged('gated', 31)
        _, first = self.planned(source, approval=True)
        _, second = self.planned(source, approval=True)
        self.assertEqual(len(first), 1)
        self.assertEqual(first, second)
        item = first[0]
        self.assertRegex(item['id'], r'^[0-9a-f]{16}$')
        self.assertEqual((item['host'], item['tier'], item['path'], item['approval']), ('test', 'archive', str(source), True))
        self.assertIn('NAS', item['reason'])

    def test_unapproved_item_on_an_approval_rule_is_untouched(self):
        source = self.aged('gated', 31)
        self.planned(source, approval=True)
        rows = self.archive_now()
        self.assertTrue(source.exists(), rows)
        self.assertEqual(self.entry.actions[-1]['reason'], reclaim.APPROVAL_NEEDED)

    def test_approved_item_is_acted_on_once(self):
        source = self.aged('gated', 31)
        plan, items = self.planned(source, approval=True)
        self.assertEqual(self.approve(plan, items[0]['id'])[0], 0)
        rows = self.archive_now()
        self.assertFalse(source.exists(), rows)
        self.assertEqual(rows['gated'][0], 'archive and remove')
        self.assertNotIn(items[0]['id'], json.loads((Path(self.config['report_dir']) / reclaim.APPROVALS).read_text()))

    def test_removal_is_logged_even_if_the_approval_cannot_be_consumed(self):
        source = self.aged('gated', 31)
        plan, _ = self.planned(source, approval=True)
        self.approve(plan, 'all')
        with patch.object(reclaim.Reclaimer, 'consume', side_effect=OSError('read-only')):
            self.archive_now()
        self.assertFalse(source.exists())
        logged = [json.loads(line)['action'] for line in
                  (Path(self.config['report_dir']) / 'reclaim-actions.jsonl').read_text().splitlines()]
        self.assertEqual(logged[-2:], ['archive and remove', 'error'])

    def test_approved_item_that_changed_since_the_plan_is_skipped(self):
        source = self.aged('gated', 31)
        plan, _ = self.planned(source, approval=True)
        self.assertEqual(self.approve(plan, 'all')[0], 0)
        (source / 'data').write_text('changed after approval')
        stamp = time.time() - 31 * 86400
        for path in (source / 'data', source):
            os.utime(path, (stamp, stamp))
        rows = self.archive_now()
        self.assertTrue(source.exists(), rows)
        self.assertEqual((source / 'data').read_text(), 'changed after approval')
        self.assertEqual(self.entry.actions[-1]['reason'], reclaim.APPROVAL_STALE)

    def test_same_size_rewrite_with_an_old_mtime_is_stale(self):
        source = self.aged('gated', 31)
        (source / 'other').write_text('x')
        stamp = time.time() - 31 * 86400
        for path in (source / 'other', source):
            os.utime(path, (stamp, stamp))
        plan, _ = self.planned(source, approval=True)
        self.approve(plan, 'all')
        before = (source / 'data').stat()
        (source / 'data').write_text('GATED')
        os.utime(source / 'data', ns=(before.st_atime_ns, before.st_mtime_ns))
        self.archive_now()
        self.assertEqual((source / 'data').read_text(), 'GATED')
        self.assertEqual(self.entry.actions[-1]['reason'], reclaim.APPROVAL_STALE)

    def test_worktree_changed_at_the_removal_boundary_is_kept(self):
        _, work = self.worktree()
        self.config['approval'] = ['worktree']
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
        plan = Path(self.config['report_dir']) / 'one.plan.json'
        plan.parent.mkdir(parents=True)
        reclaim.write_plan(plan, [self.entry], None)
        self.approve(plan, 'all')
        self.entry = self.engine.report = report.HostReport('test')
        original = reclaim.probe
        def touch_then(host, operation, **request):
            if operation == 'remove':
                stamp = (work / 'tracked').stat().st_mtime_ns
                os.utime(work / 'tracked', ns=(stamp, stamp))
            return original(host, operation, **request)
        self.engine.apply = True
        with patch.object(reclaim, 'probe', side_effect=touch_then), \
             patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
        self.assertTrue(work.exists(), self.entry.actions)
        self.assertEqual(self.entry.actions[-1]['reason'], reclaim.APPROVAL_STALE)

    def test_item_changed_after_its_fresh_recheck_is_skipped(self):
        source = self.aged('gated', 31)
        plan, _ = self.planned(source, approval=True)
        self.approve(plan, 'all')
        original = reclaim.preserve
        def change_then_copy(host, path, root, before_remove, *rest):
            (source / 'late').write_text('new')
            stamp = time.time() - 31 * 86400
            for item in (source / 'late', source):
                os.utime(item, (stamp, stamp))
            return original(host, path, root, before_remove, *rest)
        with patch.object(reclaim, 'preserve', change_then_copy):
            self.archive_now()
        self.assertTrue((source / 'late').exists())
        self.assertEqual(self.entry.actions[-1]['reason'], reclaim.APPROVAL_STALE)

    def clones(self, *names):
        bare = self.root / 'remote.git'; seed = self.root / 'seed'
        self.git(self.root, 'init', '--bare', '-b', 'main', str(bare))
        seed.mkdir(); self.git(seed, 'init', '-b', 'main')
        for key, value in (('user.name', 'Test'), ('user.email', 'test@localhost'), ('commit.gpgsign', 'false')):
            self.git(seed, 'config', key, value)
        (seed / '.gitignore').write_text('evidence/\n'); self.git(seed, 'add', '.'); self.git(seed, 'commit', '-m', 'initial')
        self.git(seed, 'push', str(bare), 'main')
        projects = self.root / 'projects'; projects.mkdir()
        made = []
        for name in names:
            self.git(projects, 'clone', '-q', str(bare), name)
            for key, value in (('user.name', 'Test'), ('user.email', 'test@localhost'), ('commit.gpgsign', 'false')):
                self.git(projects / name, 'config', key, value)
            made.append(projects / name)
        self.config['hosts']['test']['roots'] = [str(projects)]
        def proof(path, fresh=False):
            listing = self.git(self.root, 'ls-remote', str(bare))
            return reclaim.probe(self.host, 'repo', path=path, listing=listing), [], listing
        self.engine.proof = proof
        mock = patch.object(reclaim, 'repository', return_value='test/tool')
        mock.start(); self.addCleanup(mock.stop)
        return made

    def clone_run(self, apply=False):
        self.entry = self.engine.report = report.HostReport('test')
        self.engine.apply = apply
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.clones()
        return {Path(row['path']).name: (row['action'], row['reason']) for row in self.entry.actions}

    def test_redundant_clone_is_removed_after_approval_and_a_verified_nas_copy(self):
        kept, extra = self.clones('tool', 'tool-copy')
        (extra / 'evidence').mkdir(); (extra / 'evidence' / 'log').write_text('ignored data')
        self.config['live'] = ['worktree', 'clone', 'archive']
        rows = self.clone_run()
        self.assertEqual(rows['tool-copy'][0], 'would remove clone', rows)
        self.assertTrue(rows['tool'][1].startswith('KEEP: only checkout of test/tool'), rows)
        plan = Path(self.config['report_dir']) / 'one.plan.json'
        plan.parent.mkdir(parents=True)
        reclaim.write_plan(plan, [self.entry], None)
        self.assertEqual(self.approve(plan, 'all')[0], 0)
        rows = self.clone_run(apply=True)
        self.assertEqual(rows['tool-copy'][0], 'remove clone', rows)
        self.assertFalse(extra.exists())
        self.assertTrue(kept.exists())
        [record] = store._read_index(Path(self.config['nas_root']))
        self.assertEqual(record.source_path, str(extra))
        listing = store._manifest_path(store._archive_path(Path(self.config['nas_root']), record)).read_text()
        self.assertIn('tool-copy/evidence/log\n', listing)

    def test_unapproved_redundant_clone_is_kept_even_when_live(self):
        _, extra = self.clones('tool', 'tool-copy')
        self.config['live'] = ['worktree', 'clone', 'archive']
        rows = self.clone_run(apply=True)
        self.assertEqual(rows['tool-copy'], ('skip', reclaim.APPROVAL_NEEDED), rows)
        self.assertTrue(extra.exists())

    def test_only_clone_of_a_repository_is_kept(self):
        [only] = self.clones('tool')
        self.config['live'] = ['worktree', 'clone', 'archive']
        rows = self.clone_run()
        self.assertEqual(rows['tool'], ('skip', 'KEEP: only checkout of test/tool on this host'), rows)
        self.assertNotIn('id', self.entry.actions[0])
        self.assertTrue(only.exists())

    def test_clone_with_unpushed_branch_or_unique_reflog_is_kept(self):
        _, branch, amended = self.clones('tool', 'tool-branch', 'tool-amended')
        self.git(branch, 'commit', '--allow-empty', '-qm', 'side')
        self.git(branch, 'branch', 'side'); self.git(branch, 'reset', '-q', '--hard', 'HEAD~1')
        self.git(amended, 'commit', '--allow-empty', '-qm', 'lost'); self.git(amended, 'reset', '-q', '--hard', 'HEAD~1')
        rows = self.clone_run()
        self.assertEqual(rows['tool-branch'], ('skip', 'UNIQUE: local refs not on GitHub origin: refs/heads/side'), rows)
        self.assertEqual(rows['tool-amended'], ('skip', 'UNIQUE: 1 reflog commits not on GitHub origin'), rows)
        self.assertEqual(rows['tool'][0], 'would remove clone', rows)

    def test_clone_whose_only_other_checkout_is_nested_inside_it_is_kept(self):
        [tool] = self.clones('tool')
        inner = tool / 'evidence' / 'inner'
        inner.parent.mkdir()
        self.git(inner.parent, 'clone', '-q', str(self.root / 'remote.git'), 'inner')
        self.git(inner, '-c', 'user.name=Test', '-c', 'user.email=test@localhost', '-c', 'commit.gpgsign=false',
                 'commit', '--allow-empty', '-qm', 'side')
        self.git(inner, 'branch', 'side'); self.git(inner, 'reset', '-q', '--hard', 'HEAD~1')
        self.config['hosts']['test']['roots'].append(str(inner.parent))
        rows = self.clone_run()
        self.assertEqual(rows['tool'], ('skip', 'KEEP: only checkout of test/tool on this host'), rows)
        self.assertEqual(rows['inner'][0], 'skip', rows)

    def test_clone_with_a_fetched_ref_deleted_from_github_is_kept(self):
        _, stale = self.clones('tool', 'tool-stale')
        bare = self.root / 'remote.git'
        self.git(stale, 'commit', '--allow-empty', '-qm', 'gone')
        self.git(stale, 'push', '-q', str(bare), 'HEAD:refs/heads/gone')
        self.git(stale, 'fetch', '-q', str(bare), '+refs/heads/gone:refs/remotes/origin/gone')
        self.git(stale, 'reset', '-q', '--hard', 'HEAD~1')
        self.git(stale, 'reflog', 'expire', '--expire=now', '--all')
        self.git(bare, 'update-ref', '-d', 'refs/heads/gone')
        rows = self.clone_run()
        self.assertEqual(rows['tool-stale'], ('skip', 'UNIQUE: local refs not on GitHub origin: refs/remotes/origin/gone'), rows)

    def test_clean_redundant_clone_is_copied_to_nas_before_removal(self):
        _, extra = self.clones('tool', 'tool-copy')
        (extra / '.git' / 'hooks' / 'pre-push').write_text('#!/bin/sh\n')
        self.config['live'] = ['worktree', 'clone', 'archive']
        self.clone_run()
        plan = Path(self.config['report_dir']) / 'one.plan.json'
        plan.parent.mkdir(parents=True)
        reclaim.write_plan(plan, [self.entry], None)
        self.approve(plan, 'all')
        rows = self.clone_run(apply=True)
        self.assertEqual(rows['tool-copy'][0], 'remove clone', rows)
        [record] = store._read_index(Path(self.config['nas_root']))
        listing = store._manifest_path(store._archive_path(Path(self.config['nas_root']), record)).read_text()
        self.assertIn('tool-copy/.git/hooks/pre-push\n', listing)

    def test_approved_clone_is_kept_when_the_other_checkout_is_gone_before_removal(self):
        kept, extra = self.clones('tool', 'tool-copy')
        self.config['live'] = ['worktree', 'clone', 'archive']
        self.clone_run()
        plan = Path(self.config['report_dir']) / 'one.plan.json'
        plan.parent.mkdir(parents=True)
        reclaim.write_plan(plan, [self.entry], None)
        self.approve(plan, 'all')
        approved = self.engine.check_approval
        def approve_then_lose_the_other(*args):
            approved(*args)
            shutil.rmtree(kept)
        with patch.object(self.engine, 'check_approval', side_effect=approve_then_lose_the_other):
            rows = self.clone_run(apply=True)
        self.assertEqual(rows['tool-copy'], ('skip', 'KEEP: only checkout of test/tool on this host'), rows)
        self.assertTrue(extra.exists())

    def test_tier_marked_for_approval_holds_unapproved_worktrees(self):
        _, work = self.worktree()
        self.config['approval'] = ['worktree']
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
        self.assertTrue(work.exists(), self.entry.actions)
        self.assertEqual(self.entry.actions[-1]['reason'], reclaim.APPROVAL_NEEDED)

    def test_approved_worktree_is_removed(self):
        _, work = self.worktree()
        self.config['approval'] = ['worktree']
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
        plan = Path(self.config['report_dir']) / 'one.plan.json'
        plan.parent.mkdir(parents=True)
        reclaim.write_plan(plan, [self.entry], None)
        self.approve(plan, 'all')
        self.entry = self.engine.report = report.HostReport('test')
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
        self.assertFalse(work.exists(), self.entry.actions)

    def test_approved_items_on_windows_hosts_are_never_acted_on(self):
        windows = reclaim.Reclaimer(hosts.Host('test', 'powershell', 'test'), self.config, True, self.protection, self.entry)
        with reclaim.approvals(self.config['report_dir']) as found:
            found['a' * 16] = dict(host='test', tier='archive', path=str(self.root / 'x'))
        error = self.failure(lambda: windows.check_approval('a' * 16, 'archive', str(self.root / 'x')))
        self.assertEqual((type(error), str(error)), (ValueError, reclaim.APPROVAL_WINDOWS))

    def test_rules_without_approval_act_without_a_plan(self):
        source = self.aged('automatic', 31)
        self.config['hosts']['test']['archive'] = [str(source)]
        rows = self.archive_now()
        self.assertFalse(source.exists(), rows)

    def test_approve_refuses_ids_not_in_the_plan_and_records_nothing(self):
        source = self.aged('gated', 31)
        plan, items = self.planned(source, approval=True)
        code, output = self.approve(plan, items[0]['id'], 'f' * 16)
        self.assertEqual(code, 2)
        self.assertIn('f' * 16, output)
        self.assertFalse((Path(self.config['report_dir']) / reclaim.APPROVALS).exists())
        self.assertEqual(self.approve(plan, 'all', items[0]['id'])[0], 2)
        partial = dict((key, items[0][key]) for key in ('id', 'host', 'tier', 'path'))
        plan.write_text(json.dumps(dict(items=[partial])))
        code, output = self.approve(plan, 'all')
        self.assertEqual(code, 2)
        self.assertIn('is not a reclaim dry-run plan', output)
        self.assertFalse((Path(self.config['report_dir']) / reclaim.APPROVALS).exists())

    def test_dry_run_writes_the_plan_next_to_the_report(self):
        code, summary, _ = self.reclaim_main()
        self.assertEqual(code, 0)
        self.assertEqual(Path(summary['plan']), Path(summary['report']).with_suffix('.plan.json'))
        self.assertEqual(json.loads(Path(summary['plan']).read_text())['items'], [])

    def test_item_limit_stops_acting_and_skips_the_rest(self):
        sources, rows = self.limited_archives([10, 10, 10], max_items_per_run=1)
        self.assertEqual([source.exists() for source in sources], [False, True, True], rows)
        self.assertEqual([action for action, _ in rows], ['archive and remove', 'skip', 'skip'])
        self.assertEqual([reason for _, reason in rows[1:]], [reclaim.LIMIT_REACHED] * 2)

    def test_run_deadline_finishes_the_item_in_flight_then_stops(self):
        original = reclaim.preserve
        def preserve_then_pass_deadline(*args, **kwargs):
            saved = original(*args, **kwargs)
            self.engine.deadline = time.monotonic() - 1
            return saved
        with patch.object(reclaim, 'preserve', side_effect=preserve_then_pass_deadline):
            with self.assertRaisesRegex(reclaim.DeadlineReached, 'after 1 of 3 items'):
                self.limited_archives([10, 10, 10])
        self.assertEqual(len(list(self.root.glob('evidence-*'))), 2)
        self.assertEqual([row['action'] for row in self.entry.actions], ['archive and remove'])

    def probes_after_deadline(self, run):
        operations = []
        original = reclaim.probe
        def recording(host, operation, *args, **kwargs):
            operations.append(operation)
            return original(host, operation, *args, **kwargs)
        self.engine.deadline = time.monotonic() - 1
        with patch.object(reclaim, 'probe', side_effect=recording), patch.object(protect, 'collect', return_value=self.protection):
            with self.assertRaisesRegex(reclaim.DeadlineReached, 'while preparing.*0 items done'):
                run()
        return operations

    def test_run_deadline_stops_archive_preparation_before_its_next_probe(self):
        first, second = self.aged('first', 8), self.aged('second', 8)
        self.config['hosts']['test']['archive'] = [dict(path=str(first), category='artifact'), dict(path=str(second), category='artifact')]
        loaded = []
        self.engine.load_activity = lambda: loaded.append(True)
        self.assertEqual(self.probes_after_deadline(self.engine.archives), ['expand'])
        self.assertEqual(loaded, [])
        self.assertTrue(first.exists() and second.exists())

    def test_run_deadline_stops_worktree_preparation_before_the_protection_check(self):
        with patch.object(self.protection, 'batch') as batch:
            self.assertEqual(self.probes_after_deadline(self.engine.worktrees), ['discover'])
        batch.assert_not_called()

    def test_run_deadline_stops_archive_prefetch_before_its_next_batch(self):
        source = self.aged('evidence', 8)
        self.config['hosts']['test']['archive'] = [str(source)]
        def activity():
            self.engine.activity = dict(blocked=False)
            self.engine.deadline = time.monotonic() - 1
        self.engine.load_activity = activity
        self.engine.deadline = None
        operations = []
        original = reclaim.probe
        def recording(host, operation, *args, **kwargs):
            operations.append(operation)
            return original(host, operation, *args, **kwargs)
        with patch.object(reclaim, 'probe', side_effect=recording), patch.object(protect, 'collect', return_value=self.protection):
            with self.assertRaisesRegex(reclaim.DeadlineReached, 'after 0 of 1 prefetch batches; 0 items done'):
                self.engine.archives()
        self.assertNotIn('batch', operations)
        self.assertTrue(source.exists())

    def test_run_deadline_stops_clone_preparation_before_its_next_probe(self):
        self.clones('a', 'b')
        self.assertNotIn('repo', self.probes_after_deadline(self.engine.clones))

    def test_volume_limit_stops_before_crossing_the_byte_cap(self):
        sources, rows = self.limited_archives([10, 500_000, 10], max_gib_per_run=100_000 / 1024**3)
        self.assertEqual([source.exists() for source in sources], [False, True, True], rows)
        self.assertEqual(rows[1:], [('skip', reclaim.LIMIT_REACHED)] * 2)

    def test_item_that_fails_its_fresh_recheck_does_not_use_the_budget(self):
        calls = []
        def reason(path, **kw):
            calls.append(path)
            return 'IN USE: opened after preview' if path.endswith('evidence-0') and calls.count(path) > 1 else ''
        self.protection.reason.side_effect = reason
        sources, rows = self.limited_archives([10, 10], max_items_per_run=1)
        self.assertEqual([source.exists() for source in sources], [True, False], rows)
        self.assertEqual(rows, [('skip', 'IN USE: opened after preview'), rows[1]])
        self.assertEqual(rows[1][0], 'archive and remove')

    def test_host_local_refusal_uses_no_budget_and_no_nas_copy(self):
        policy = self.root / '.config' / 'coldcleaner' / 'local.json'
        policy.write_text(json.dumps(dict(archive=[str(self.root / 'evidence-1')])))
        copies = []
        original = reclaim.preserve
        def counted(host, path, *args):
            copies.append(path)
            return original(host, path, *args)
        with patch.object(reclaim, 'preserve', counted):
            sources, rows = self.limited_archives([10, 10], max_items_per_run=1)
        self.assertEqual([source.exists() for source in sources], [True, False], rows)
        self.assertEqual(rows[0][0], 'skip')
        self.assertIn('outside host-local policy', rows[0][1])
        self.assertEqual(rows[1][0], 'archive and remove')
        self.assertEqual(copies, [str(sources[1])])

    def test_undecodable_installed_scan_is_a_sudo_skip(self):
        installed = self.root / 'coldcleaner-proc-scan.py'
        installed.write_bytes(b'\xff\xfe not utf-8')
        with patch.object(reclaim_probe, 'SCAN_PATH', str(installed)), patch.object(
                reclaim_probe.os, 'geteuid', return_value=1000), patch.object(reclaim_probe.subprocess, 'run') as run:
            error = self.failure(self.read_references)
        self.assertEqual((type(error), str(error)), (ValueError, reclaim_probe.NEEDS_SUDO))
        run.assert_not_called()

    def test_limit_is_checked_before_copying_to_the_nas(self):
        copies = []
        original = reclaim.preserve
        def counted(host, path, *args):
            copies.append(path)
            return original(host, path, *args)
        with patch.object(reclaim, 'preserve', counted):
            sources, rows = self.limited_archives([10, 10], max_items_per_run=1)
        self.assertEqual(copies, [str(sources[0])])
        self.assertEqual(rows[1], ('skip', reclaim.LIMIT_REACHED))

    def test_unmounted_nas_is_an_error_and_keeps_source(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('keep')
        stamp = time.time() - 8 * 86400
        for path in (source / 'unique', source):
            os.utime(path, (stamp, stamp))
        self.config['hosts']['test']['archive'] = [str(source)]
        self.engine.apply = True
        run = subprocess.run
        def findmnt(args, *rest, **kwargs):
            if args[0] == 'findmnt':
                return subprocess.CompletedProcess(args, 0, stdout='ext4\n', stderr='')
            return run(args, *rest, **kwargs)
        with patch.object(protect, 'collect', return_value=self.protection), \
                patch.object(reclaim, 'check_nas', self.real_check_nas), \
                patch.object(reclaim.subprocess, 'run', side_effect=findmnt):
            self.engine.archives()
        self.assertTrue(source.exists())
        self.assertEqual(self.entry.actions[-1]['action'], 'error', self.entry.actions)

    def test_mount_and_unrecoverable_access_metadata_retain_source(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('keep')
        original = Path.read_text
        def mounted(path, *args, **kwargs):
            return '1 0 0:1 / ' + str(source / 'nested') + ' rw - ext4 /dev/test rw' if str(path) == '/proc/self/mountinfo' else original(path, *args, **kwargs)
        with patch.object(Path, 'read_text', mounted):
            with self.assertRaisesRegex(ValueError, 'mounted filesystem'):
                reclaim_probe.tree(source)
        os.setxattr(source / 'unique', 'user.coldcleaner-test', b'private metadata')
        with self.assertRaisesRegex(ValueError, 'access metadata'):
            reclaim.preserve(self.host, str(source), self.root / 'nas', lambda: None)
        self.assertEqual(os.getxattr(source / 'unique', 'user.coldcleaner-test'), b'private metadata')
        self.assertFalse((self.root / 'nas').exists())

    def without_os_listxattr(self, platform):
        saved = os.listxattr
        del os.listxattr
        self.addCleanup(setattr, os, 'listxattr', saved)
        mock = patch.object(sys, 'platform', platform)
        mock.start(); self.addCleanup(mock.stop)

    def darwin_libc(self, attributes):
        self.without_os_listxattr('darwin')
        calls = []
        def listxattr(path, names, size, options):
            calls.append((names, size, options))
            listing = b''.join(name + b'\0' for name in attributes.get(Path(os.fsdecode(path)).name, []))
            if names is not None:
                ctypes.memmove(names, listing, len(listing))
            return len(listing)
        mock = patch.object(ctypes, 'CDLL', return_value=Mock(listxattr=listxattr))
        mock.start(); self.addCleanup(mock.stop)
        return calls

    def archive_rows(self, source):
        self.config['hosts']['test']['archive'] = [str(source)]
        self.engine.archives()
        return [row for row in self.entry.actions if row['path'] == str(source)]

    def test_macos_tree_without_os_listxattr_reads_attributes_through_libc(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'clean').write_text('keep')
        stamp = time.time() - 8 * 86400
        for path in (source / 'clean', source):
            os.utime(path, (stamp, stamp))
        calls = self.darwin_libc({})
        rows = self.archive_rows(source)
        self.assertEqual([row['action'] for row in rows], ['would archive and remove'], rows)
        self.assertEqual(set(calls), {(None, 0, 1)})

    def test_macos_attributes_read_through_libc_still_retain_the_source(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'tagged').write_text('keep')
        self.darwin_libc({'tagged': [b'com.apple.FinderInfo']})
        rows = self.archive_rows(source)
        self.assertEqual([row['action'] for row in rows], ['skip'], rows)
        self.assertIn('access metadata requires separate preservation', rows[0]['reason'])
        self.assertTrue((source / 'tagged').exists())

    def test_macos_libc_names_allow_only_provenance_and_quarantine_stamps(self):
        source = self.root / 'evidence'; source.mkdir()
        for name in ('stamped', 'tagged'):
            (source / name).write_text('keep')
        stamp = time.time() - 8 * 86400
        for path in (*source.iterdir(), source):
            os.utime(path, (stamp, stamp))
        stamps = [b'com.apple.provenance', b'com.apple.quarantine']
        attributes = {'evidence': stamps[:1], 'stamped': stamps, 'tagged': stamps[1:]}
        self.darwin_libc(attributes)
        self.assertEqual([row['action'] for row in self.archive_rows(source)], ['would archive and remove'])
        attributes['tagged'] = [*stamps, b'com.apple.metadata:kMDItemWhereFroms']
        rows = self.archive_rows(source)
        self.assertEqual([row['action'] for row in rows], ['would archive and remove', 'skip'], rows)
        self.assertIn('access metadata requires separate preservation: ' + str(source / 'tagged'), rows[-1]['reason'])

    def test_worktree_with_only_provenance_xattrs_passes_but_any_other_xattr_skips(self):
        repo, work = self.worktree()
        def provenance(extra):
            def listxattr(path, follow_symlinks=True):
                inside = Path(path) == work or work in Path(path).parents
                return ['com.apple.provenance', *extra.get(Path(path).name, [])] if inside else []
            return patch.object(os, 'listxattr', side_effect=listxattr)
        with patch.object(protect, 'collect', return_value=self.protection):
            with provenance({}):
                self.engine.worktrees()
            self.assertEqual(self.entry.actions[-1]['action'], 'would remove worktree', self.entry.actions[-1])
            with provenance({'tracked': ['user.private']}):
                self.engine.worktrees()
        self.assertEqual(self.entry.actions[-1]['action'], 'skip', self.entry.actions[-1])
        self.assertIn('access metadata requires separate preservation: ' + str(work / 'tracked'),
                      self.entry.actions[-1]['reason'])
        self.assertTrue((work / 'tracked').exists())

    def test_unreadable_attributes_skip_the_source_instead_of_guessing(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('keep')
        self.without_os_listxattr('sunos5')
        rows = self.archive_rows(source)
        self.assertEqual([row['action'] for row in rows], ['skip'], rows)
        self.assertIn('extended attributes cannot be read', rows[0]['reason'])
        self.assertTrue((source / 'unique').exists())

    def test_guard_rejects_filesystem_root_and_home(self):
        home = self.root / 'home'; home.mkdir()
        with patch.dict(os.environ, HOME=str(home)), patch.object(reclaim_probe, 'threads', return_value=[]), \
                patch.object(reclaim_probe, 'references', return_value=[]):
            for path in ('/', Path('/'), str(home), str(home) + '/', home, str(home / 'x' / '..'), 'relative/dir'):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'invalid cleanup root'):
                    reclaim_probe.guard(path)
        self.assertTrue(home.is_dir())

    def test_guard_refuses_os_and_personal_locations(self):
        home = self.root / 'home'
        for name in ('Documents', 'Desktop', 'Pictures', 'Library/Caches', 'iCloud Drive', 'Google Drive', 'OneDrive - Work'):
            (home / name / 'x').mkdir(parents=True)
        with patch.dict(os.environ, HOME=str(home)), patch.object(reclaim_probe, 'threads', return_value=[]), \
                patch.object(reclaim_probe, 'references', return_value=[]):
            for path in ('/etc/ssh', '/usr/share', '/System/Library', '/mnt/shared-memory/Agent-Space', '/mnt',
                         *(str(home / name / 'x') for name in ('Documents', 'Desktop', 'Pictures', 'Library/Caches',
                                                                'iCloud Drive', 'Google Drive', 'OneDrive - Work'))):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'protected location'):
                    reclaim_probe.guard(path)
            (home / 'projects' / 'scratch').mkdir(parents=True)
            reclaim_probe.guard(home / 'projects' / 'scratch')

    def test_guard_refuses_case_aliases_of_protected_locations_on_macos(self):
        home = self.root / 'home'
        with patch.dict(os.environ, HOME=str(home)), patch.object(reclaim_probe.sys, 'platform', 'darwin'):
            for path in ('/ETC/ssh', '/system/Library', str(home / 'documents' / 'x'), str(home / 'LIBRARY' / 'Caches')):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'protected location'):
                    reclaim_probe.guard(path)

    def test_guard_refuses_obsidian_vaults_and_folders_that_hold_one(self):
        vault = self.root / 'outer' / 'vault'; (vault / '.obsidian').mkdir(parents=True)
        (self.root / 'other' / 'vault' / '.Obsidian').mkdir(parents=True)
        (vault / 'notes').mkdir(); (vault / 'notes' / 'a.md').write_text('keep')
        with patch.object(reclaim_probe, 'threads', return_value=[]), patch.object(reclaim_probe, 'references', return_value=[]):
            for path in (vault, vault / 'notes', self.root / 'outer', self.root / 'other'):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'protected location: Obsidian vault'):
                    reclaim_probe.guard(path)
        self.assertTrue((vault / 'notes' / 'a.md').exists())

    def test_rules_protected_list_reaches_the_probe_guard(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'data').write_text('keep')
        self.config['hosts']['test']['protected'] = [str(source)]
        rows = self.archive_rows(source)
        self.assertEqual([row['action'] for row in rows], ['skip'], rows)
        self.assertIn('protected location: ' + str(source), rows[0]['reason'])
        self.assertTrue((source / 'data').exists())

    def test_guard_retains_process_thread_recent_symlink_and_keep_local(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'data').write_text('unique')
        alias = self.root / 'alias'; alias.symlink_to(source, target_is_directory=True)
        with patch.object(reclaim_probe, 'threads', return_value=[str(alias)]), patch.object(reclaim_probe, 'references', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'T3 thread'):
                reclaim_probe.guard(source)
        with patch.object(reclaim_probe, 'threads', return_value=[]), patch.object(reclaim_probe, 'references', return_value=[str(alias / 'data')]):
            with self.assertRaisesRegex(ValueError, 'running process'):
                reclaim_probe.guard(source)
        with patch.object(reclaim_probe, 'threads', return_value=[str(source)]), patch.object(reclaim_probe, 'references', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'T3 thread'):
                reclaim_probe.guard(source)
        with patch.object(reclaim_probe, 'threads', return_value=[]), patch.object(reclaim_probe, 'references', return_value=[str(source / 'data')]):
            with self.assertRaisesRegex(ValueError, 'running process'):
                reclaim_probe.guard(source)
        with patch.object(reclaim_probe, 'threads', return_value=[]), patch.object(reclaim_probe, 'references', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'recent'):
                reclaim_probe.guard(source, 7)
            (source / '.keep-local').touch()
            with self.assertRaisesRegex(ValueError, '.keep-local'):
                reclaim_probe.guard(source)
            (source / '.keep-local').unlink(); (source / 'link').symlink_to(self.root)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                reclaim_probe.guard(source)

    def test_t3_sqlite_tracks_running_archived_and_unsettled_threads(self):
        directory = self.root / '.t3/userdata'; directory.mkdir(parents=True)
        with sqlite3.connect(directory / 'statev2.sqlite') as db:
            db.executescript('''CREATE TABLE orchestration_v2_projection_threads(thread_id,deleted_at,archived_at,payload_json);
                CREATE TABLE orchestration_v2_projection_runs(thread_id,status);
                CREATE TABLE projection_projects(project_id,workspace_root);''')
            for ident, archived, settled, path in [('running', 'date', 'settled', '/active'), ('idle', None, None, '/waiting'), ('done', 'date', 'settled', '/finished')]:
                db.execute('INSERT INTO orchestration_v2_projection_threads VALUES(?,NULL,?,?)',
                    (ident, archived, json.dumps(dict(worktreePath=path, archivedAt=archived, settledOverride=settled))))
            db.execute("INSERT INTO orchestration_v2_projection_runs VALUES('running','running')")
            db.execute('INSERT INTO orchestration_v2_projection_threads VALUES(?,NULL,?,?)',
                ('pinned', 'date', json.dumps(dict(worktreePath='/pinned', pinnedAt='date', settledOverride='settled'))))
        self.assertEqual(set(self.read_threads()), {'/active', '/waiting', '/pinned'})
        db.close()
        (directory / 'statev2.sqlite').write_bytes(b'invalid')
        with self.assertRaises(sqlite3.DatabaseError):
            self.read_threads()

    def test_host_without_t3_notes_it_once(self):
        with patch.object(reclaim_probe, 'threads', self.read_threads):
            actions, _ = self.archive_preview()
        self.assertEqual([action for _, action, _ in actions], ['skip', 'would archive and remove', 'would archive and remove'])
        self.assertEqual(self.entry.notes.count('T3 not installed'), 1)
        self.assertEqual(report.render([self.entry]).count('T3 not installed'), 1)

    def test_renamed_t3_tables_protect_every_candidate_with_one_reason(self):
        directory = self.root / '.t3/userdata'; directory.mkdir(parents=True)
        with closing(sqlite3.connect(directory / 'statev2.sqlite')) as db:
            db.executescript('''CREATE TABLE orchestration_v3_projection_threads(thread_id,deleted_at,archived_at,payload_json);
                CREATE TABLE orchestration_v3_projection_runs(thread_id,status);
                CREATE TABLE projection_projects(project_id,workspace_root);''')
        with patch.object(reclaim_probe, 'threads', self.read_threads):
            actions, _ = self.archive_preview()
        self.assertEqual([action for _, action, _ in actions], ['skip'] * 3)
        reasons = {reason for _, _, reason in actions}
        self.assertEqual(len(reasons), 1, reasons)
        reason = reasons.pop()
        self.assertEqual(reason, 'IN USE: T3 state unreadable, protecting every candidate: '
                                 'OperationalError: no such table: orchestration_v2_projection_threads')
        self.assertEqual(self.entry.errors, [])
        self.assertEqual(self.entry.notes, [reason])
        self.assertTrue((self.root / 'old' / 'data').exists())

    def codex_state(self, rows, columns='id, cwd, archived, updated_at'):
        directory = self.root / '.codex'; directory.mkdir(exist_ok=True)
        (directory / 'state_4.sqlite').write_bytes(b'stale version is ignored')
        with closing(sqlite3.connect(directory / 'state_5.sqlite')) as db:
            db.execute(f'CREATE TABLE threads({columns})')
            db.executemany('INSERT INTO threads VALUES(?,?,?,?)', rows)
            db.commit()

    def test_codex_threads_protect_recent_unarchived_workspaces(self):
        now = int(time.time())
        recent, archived, idle, broad = (self.root / name for name in ('recent', 'archived', 'idle', 'broad'))
        for folder in (recent, archived, idle, broad):
            folder.mkdir(); (folder / 'data').write_text('x')
            os.utime(folder / 'data', (now - 30 * 86400,) * 2); os.utime(folder, (now - 30 * 86400,) * 2)
        self.codex_state([('a', str(recent / 'sub'), 0, now - 3600), ('b', str(archived), 1, now),
                          ('c', str(idle), 0, now - 10 * 86400), ('d', str(self.root), 0, now)])
        with patch.object(reclaim_probe, 'codex_threads', self.read_codex), patch.object(reclaim_probe, 'threads', self.read_threads):
            with self.assertRaisesRegex(ValueError, '^Codex thread uses ' + re.escape(str(recent / 'sub')) + '$'):
                reclaim_probe.main(dict(operation='guard', path=str(recent), days=7))
            for folder in (archived, idle, broad):
                with self.subTest(folder=folder.name):
                    self.assertEqual(reclaim_probe.main(dict(operation='guard', path=str(folder), days=7))['files'], 1)

    def test_codex_schema_change_protects_every_candidate(self):
        self.codex_state([('a', str(self.root / 'elsewhere'), 0, 0)], columns='id, working_dir, archived, updated_at')
        (self.root / 'old').mkdir()
        with patch.object(reclaim_probe, 'codex_threads', self.read_codex):
            with self.assertRaisesRegex(ValueError, '^IN USE: Codex state unreadable, protecting every candidate: '
                                                    'OperationalError: no such column: cwd$'):
                reclaim_probe.main(dict(operation='guard', path=str(self.root / 'old')))

    def claude_session(self, name, cwds, age):
        session = self.root / '.claude' / 'projects' / name
        session.parent.mkdir(parents=True, exist_ok=True)
        session.write_text(''.join(json.dumps(dict(type='user', cwd=cwd)) + '\n' for cwd in cwds))
        os.utime(session, (time.time() - age,) * 2)

    def test_claude_code_sessions_protect_recent_workspaces(self):
        now = int(time.time())
        recent, moved, idle, broad = (self.root / name for name in ('recent', 'moved', 'idle', 'broad'))
        for folder in (recent, moved, idle, broad):
            folder.mkdir(); (folder / 'data').write_text('x')
            os.utime(folder / 'data', (now - 30 * 86400,) * 2); os.utime(folder, (now - 30 * 86400,) * 2)
        self.claude_session('-recent/a.jsonl', [str(recent / 'sub')], 3600)
        self.claude_session('-start/b/subagents/agent-1.jsonl', ['/elsewhere', str(moved), '/elsewhere'], 3600)
        self.claude_session('-idle/c.jsonl', [str(idle)], 10 * 86400)
        self.claude_session('-home/d.jsonl', [str(self.root)], 0)
        (self.root / '.claude' / 'projects' / '-empty.jsonl').write_text('')
        with patch.object(reclaim_probe, 'claude_threads', self.read_claude):
            for folder, reference in ((recent, recent / 'sub'), (moved, moved)):
                with self.subTest(folder=folder.name):
                    with self.assertRaisesRegex(ValueError, '^Claude Code thread uses ' + re.escape(str(reference)) + '$'):
                        reclaim_probe.main(dict(operation='guard', path=str(folder), days=7))
            for folder in (idle, broad):
                with self.subTest(folder=folder.name):
                    self.assertEqual(reclaim_probe.main(dict(operation='guard', path=str(folder), days=7))['files'], 1)
            activity = reclaim_probe.main(dict(operation='activity'))
            self.assertIn(str(idle), [path for name, path, _ in activity['threads'] if name == 'Claude Code'])
            with self.assertRaisesRegex(ValueError, '^Claude Code thread uses ' + re.escape(str(idle)) + '$'):
                reclaim_probe.main(dict(operation='guard', path=str(idle), days=14, activity=activity))

    def test_unreadable_claude_sessions_protect_every_candidate(self):
        (self.root / 'old').mkdir()
        with patch.object(reclaim_probe, 'claude_threads', self.read_claude):
            self.assertEqual(reclaim_probe.main(dict(operation='activity'))['notes'], ['Claude Code not installed'])
            (self.root / '.claude').mkdir(); (self.root / '.claude' / 'projects').write_text('not a folder')
            with self.assertRaisesRegex(ValueError, '^IN USE: Claude Code state unreadable, protecting every candidate: '
                                                    'NotADirectoryError: '):
                reclaim_probe.main(dict(operation='guard', path=str(self.root / 'old')))
            (self.root / '.claude' / 'projects').unlink()
            self.claude_session('-x/a.jsonl', [str(self.root / 'old')], 0)
            for link in (self.root / '.claude' / 'projects' / '-x' / 'linked', self.root / '.claude' / 'projects' / '-x' / 'b.jsonl'):
                with self.subTest(link=link.name):
                    link.symlink_to(self.root / 'missing')
                    with self.assertRaisesRegex(ValueError, '^IN USE: Claude Code state unreadable, protecting every candidate: '
                                                            'ValueError: symlink in Claude Code sessions: '):
                        reclaim_probe.main(dict(operation='guard', path=str(self.root / 'old'), days=1))
                    link.unlink()
            session = self.root / '.claude' / 'projects' / '-x' / 'a.jsonl'
            for text in (json.dumps(dict(cwd='relative/path')), '{"cwd": null}', '{"cwd":"' + str(self.root / 'old')):
                with self.subTest(text=text):
                    session.write_text('{"cwd":"/elsewhere"}\n' + text)
                    with self.assertRaisesRegex(ValueError, '^IN USE: Claude Code state unreadable, protecting every candidate: '
                                                            'ValueError: unexpected cwd'):
                        reclaim_probe.main(dict(operation='guard', path=str(self.root / 'old'), days=1))

    def test_unexpired_lease_protects_its_folder_parents_and_contents(self):
        parent = self.root / 'claimed'; source = parent / 'evidence'; source.mkdir(parents=True)
        (source / 'data').write_text('x')
        future = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 3600))
        past = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - 60))
        for holder in (parent, source, source / 'nested'):
            with self.subTest(holder=holder.name):
                holder.mkdir(exist_ok=True)
                lease = holder / ('.coldcleaner-lease' if holder == source else '.COLDCLEANER-LEASE')
                lease.write_text(future + '\n')
                with self.assertRaisesRegex(ValueError, '^leased until ' + future + ': ' + re.escape(str(lease)) + '$'):
                    reclaim_probe.guard(source)
                for text in ('2026-11-12', 'tomorrow', future + ' extra', '', '2026-1-1T0:0:0Z', '2099-1-1T00:00:00Z'):
                    lease.write_text(text)
                    with self.assertRaisesRegex(ValueError, '^unreadable .coldcleaner-lease, protecting: '):
                        reclaim_probe.guard(source)
                lease.write_text(past)
                self.assertGreaterEqual(reclaim_probe.guard(source)['files'], 1)
                lease.unlink()

    def artifact_marker(self, policy='temporary', expires_in=None, **retention):
        created = time.time() - 86400
        marker = dict(schema_version=1, retention=dict(owner='coldcontribute', policy=policy, **retention),
                      provenance=dict(producer='coldcontribute 0dc52a571f09',
                                      created_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(created))))
        if expires_in is not None:
            marker['retention']['expires'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + expires_in))
        return json.dumps(marker)

    def test_artifact_marker_holds_kept_owned_and_invalid_artifacts_until_they_expire(self):
        parent = self.root / 'fix'; receipt = parent / 'owner' / 'repo' / '7'; receipt.mkdir(parents=True)
        (receipt / 'fix.json').write_text('{}')
        receipt_file = parent / 'owner' / 'repo' / 'note.txt'; receipt_file.write_text('x')
        keep = self.artifact_marker('keep')
        owned = self.artifact_marker(expires_in=3600, preserved_at='/evidence/7.tar.gz')
        expired = self.artifact_marker(expires_in=-60, preserved_at='/evidence/7.tar.gz')
        def broken(change):
            marker = json.loads(keep); change(marker); return json.dumps(marker).encode()
        invalid = [b'', b'not json', b'[]', self.artifact_marker('keep', expires_in=3600).encode(),
                   self.artifact_marker(expires_in=None).encode(), self.artifact_marker(expires_in=-2 * 86400).encode(),
                   self.artifact_marker('forever').encode(), self.artifact_marker(expires_in=-60, extra=1).encode(),
                   broken(lambda m: m.update(schema_version=2)), broken(lambda m: m.update(schema_version=True)),
                   broken(lambda m: m['retention'].update(owner='')),
                   broken(lambda m: m['provenance'].update(created_at='2026-11-12')),
                   broken(lambda m: m['provenance'].update(created_at='2026-02-30T00:00:00Z')),
                   broken(lambda m: m['provenance'].update(repo=dict(name='owner/repo', commit='abc'))),
                   broken(lambda m: m.pop('provenance'))]
        for source, marker in ((receipt, receipt / '.cold-artifact.json'), (receipt, parent / '.COLD-ARTIFACT.json'),
                               (receipt, receipt / 'sub' / '.cold-artifact.json'),
                               (receipt, receipt / 'fix.json.cold-artifact.json'),
                               (receipt_file, receipt_file.with_name('note.txt.cold-artifact.json'))):
            with self.subTest(source=source.name, marker=str(marker.relative_to(self.root))):
                marker.parent.mkdir(exist_ok=True)
                marker.write_text(keep)
                with self.assertRaisesRegex(ValueError, '^artifact marker says keep \\(owner coldcontribute\\): '
                                                        + re.escape(str(marker)) + '$'):
                    reclaim_probe.guard(source)
                marker.write_text(owned)
                with self.assertRaisesRegex(ValueError, '^artifact marker owned by coldcontribute until .*Z: '
                                                        + re.escape(str(marker)) + '$'):
                    reclaim_probe.guard(source)
                for text in invalid:
                    marker.write_bytes(text)
                    with self.assertRaisesRegex(ValueError, '^invalid artifact marker, protecting: '):
                        reclaim_probe.guard(source)
                marker.unlink(); marker.mkdir()
                with self.assertRaisesRegex(ValueError, '^invalid artifact marker, protecting: '):
                    reclaim_probe.guard(source)
                marker.rmdir()
                marker.write_text(expired)
                with patch.object(reclaim_probe, 'running_programs', return_value=set()):
                    self.assertGreaterEqual(reclaim_probe.guard(source)['files'], 1)
                marker.unlink()
                self.assertGreaterEqual(reclaim_probe.guard(source)['files'], 1)

    def test_expired_artifact_marker_holds_while_its_owner_is_running(self):
        receipt = self.root / 'fix' / 'owner' / 'repo' / '7'; receipt.mkdir(parents=True)
        (receipt / 'fix.json').write_text('{}')
        marker = receipt / '.cold-artifact.json'
        marker.write_text(self.artifact_marker(expires_in=-60))
        real = subprocess.run
        def processes(listing):
            def run(command, *args, **kwargs):
                if command[0] != 'ps':
                    return real(command, *args, **kwargs)
                if listing is None:
                    raise subprocess.CalledProcessError(1, command)
                width = None if '-ww' in command else 30
                return subprocess.CompletedProcess(command, 0, '\n'.join(line[:width] for line in listing.split('\n')), '')
            return patch.object(reclaim_probe.subprocess, 'run', run)
        idle = '    1 /sbin/init\n  %d python3 -m coldcontribute\n 42 python3 %s/run.py\n' % (os.getpid(), receipt)
        for command in ('/home/user/.local/bin/coldcontribute fix 7', 'ColdContribute --serve',
                        '/usr/bin/python3 /opt/coldcontribute.py', 'python3 -m coldcontribute.fix',
                        '/usr/local/bin/python3 /srv/products/release/current/coldcontribute.py'):
            with self.subTest(command=command), processes(idle + ' 77 ' + command + '\n'), \
                    self.assertRaisesRegex(ValueError, '^artifact marker owner coldcontribute is running: '
                                                       + re.escape(str(marker)) + '$'):
                reclaim_probe.guard(receipt)
        with processes(None), self.assertRaisesRegex(ValueError, '^artifact marker owner check incomplete, protecting: '):
            reclaim_probe.guard(receipt)
        with processes(idle + ' 77 coldcontributor\n'):
            self.assertGreaterEqual(reclaim_probe.guard(receipt)['files'], 1)

    def test_owner_check_protects_when_proc_hides_other_users(self):
        row = '23 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw,%s\n'
        sys_row = '22 1 0:20 / /sys rw shared:7 - sysfs sysfs rw,hidepid=2\n'
        for options, hidden in (('', False), ('hidepid=0', False), ('hidepid=off', False), ('hidepid=1', True),
                                ('hidepid=2', True), ('hidepid=invisible', True), ('hidepid=ptraceable', True),
                                ('gid=4,hidepid=noaccess', True)):
            with self.subTest(options=options):
                self.assertIs(reclaim_probe.hides_processes(sys_row + row % options), hidden)
        if os.name == 'nt' or sys.platform == 'darwin':
            return
        with patch.object(reclaim_probe.os, 'geteuid', return_value=1000), \
                patch.object(reclaim_probe, 'hides_processes', return_value=True), \
                self.assertRaisesRegex(ValueError, "^artifact marker owner check incomplete, protecting: "
                                                   "/proc hides other users' processes$"):
            reclaim_probe.running_programs()

    def test_macos_owner_check_reads_every_process_through_sudo(self):
        calls = []
        def sudo(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, ' 7 /usr/bin/python3 /opt/coldcontribute.py\n', '')
        with patch.object(reclaim_probe.sys, 'platform', 'darwin'), patch.object(reclaim_probe, 'sudo_run', sudo):
            self.assertIn('coldcontribute', reclaim_probe.running_programs())
        self.assertEqual(calls, [['ps', '-A', '-ww', '-o', 'pid=,args=']])
        refused = lambda command, **kwargs: subprocess.CompletedProcess(command, 1, '', 'ps: not permitted')
        with patch.object(reclaim_probe.sys, 'platform', 'darwin'), patch.object(reclaim_probe, 'sudo_run', refused), \
                self.assertRaisesRegex(ValueError, '^artifact marker owner check incomplete, protecting: ps: not permitted$'):
            reclaim_probe.running_programs()

    def test_windows_owner_check_protects_when_a_command_line_is_unreadable(self):
        def inventory(*rows):
            listing = json.dumps([dict(ProcessId=pid, Name=name, ExecutablePath=exe, CommandLine=line)
                                  for pid, name, exe, line in rows])
            return patch.object(reclaim_probe.subprocess, 'run',
                                return_value=subprocess.CompletedProcess([], 0, listing, ''))
        idle = [(0, 'System Idle Process', None, None), (4, 'System', None, None),
                (9, 'vmmemWSL', None, None), (10, 'csrss.exe', None, None),
                (11, 'python.exe', 'C:\\py\\python.exe', 'python.exe C:\\tools\\coldcontribute.py')]
        protected = lambda pid: pid == 10
        with patch.object(reclaim_probe.os, 'name', 'nt'), \
                patch.object(reclaim_probe, 'windows_arguments', lambda line: line.split()), \
                patch.object(reclaim_probe, 'protected_process', protected), \
                patch.object(reclaim_probe, 'exited', lambda pid: pid == 12):
            with inventory(*idle):
                self.assertIn('coldcontribute', reclaim_probe.running_programs())
            with inventory(*idle, (12, 'python.exe', 'C:\\py\\python.exe', None)):
                self.assertIn('coldcontribute', reclaim_probe.running_programs())
            for unreadable in ((13, 'python.exe', 'C:\\py\\python.exe', None), (14, 'svc.exe', None, None)):
                with self.subTest(process=unreadable), inventory(*idle, unreadable), \
                        self.assertRaisesRegex(ValueError, '^artifact marker owner check incomplete, protecting: '
                                                           'CommandLine unreadable for process ' + str(unreadable[0])):
                    reclaim_probe.running_programs()

    def test_remove_rechecks_outside_markers_after_verifying_the_copy(self):
        receipt = self.root / 'fix' / 'owner' / 'repo' / '7'; receipt.mkdir(parents=True)
        (receipt / 'fix.json').write_text('{}')
        manifest = reclaim_probe.tree(receipt, True)['manifest']
        for marker in (self.root / 'fix' / '.cold-artifact.json', receipt.parent / '7.cold-artifact.json'):
            with self.subTest(marker=marker.name):
                real = reclaim_probe.tree
                def marked_during_verify(path, hashes=False):
                    if hashes:
                        marker.write_text(self.artifact_marker('keep'))
                    return real(path, hashes)
                with patch.object(reclaim_probe, 'tree', marked_during_verify):
                    with self.assertRaisesRegex(ValueError, '^artifact marker says keep'):
                        reclaim_probe.main(dict(operation='remove', path=str(receipt), manifest=manifest))
                self.assertTrue((receipt / 'fix.json').exists())
                marker.unlink()

    def test_worktree_remove_rechecks_markers_inside_after_the_git_proof(self):
        repo, work = self.worktree()
        head = self.git(work, 'rev-parse', 'HEAD')
        bare = str(self.root / 'remote.git')
        listing = self.git(repo, 'ls-remote', bare)
        marker = work / 'evidence' / '.cold-artifact.json'
        real = reclaim_probe.repo
        def marked_after_proof(*args, **kwargs):
            state = real(*args, **kwargs)
            marker.parent.mkdir(exist_ok=True); marker.write_text(self.artifact_marker('keep'))
            return state
        with patch.object(reclaim_probe, 'repo', marked_after_proof), \
                self.assertRaisesRegex(ValueError, '^artifact marker says keep'):
            reclaim_probe.main(dict(operation='remove', path=str(work), head=head, branch='done',
                                    remote=bare, listing=listing))
        self.assertTrue(marker.exists())

    def run_json(self, apply=False):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(disk, 'measure', return_value=disk.Usage(100, 20, 20)), \
                patch.object(protect, 'collect', return_value=protect.Protection(self.host, str(self.root), set(), [])), \
                patch.object(reclaim.Reclaimer, 'worktrees'), patch.object(reclaim.Reclaimer, 'archives'), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.run(self.config, [self.host], apply, as_json=True)
        return code, stdout.getvalue(), stderr.getvalue()

    def check_drive(self, mounted=True, drive=2, archive=2, root=1, source=None, source_device=1, kind='ext4'):
        mount = self.root / 'drive'
        (mount / 'archive').mkdir(parents=True, exist_ok=True)
        devices = {str(mount): drive, str((mount / 'archive').resolve()): archive, '/': root}
        if source:
            devices[source] = source_device
        real = os.stat
        def stat(path, *args, **kwargs):
            return Mock(st_dev=devices[str(path)]) if str(path) in devices else real(path, *args, **kwargs)
        with patch.object(reclaim.os, 'stat', stat), patch.object(reclaim.os.path, 'ismount', return_value=mounted), \
                patch.object(reclaim.subprocess, 'run', return_value=Mock(stdout=kind + '\n')):
            self.real_check_nas(str(mount / 'archive' / 'not-created-yet'), str(mount), source)

    def test_local_archive_requires_the_drive_to_be_mounted(self):
        with self.assertRaisesRegex(RuntimeError, 'not mounted at'):
            self.check_drive(mounted=False)

    def test_local_archive_folder_must_be_on_the_named_drive(self):
        with self.assertRaisesRegex(RuntimeError, 'is not on the drive mounted at'):
            self.check_drive(archive=3)

    def test_local_archive_on_the_root_filesystem_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'same filesystem as /$'):
            self.check_drive(drive=1, archive=1)

    def test_local_archive_on_the_filesystem_being_cleaned_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'same filesystem as the data being removed'):
            self.check_drive(source='/srv/work', source_device=2)

    def test_local_archive_on_a_memory_backed_filesystem_is_refused(self):
        for kind in ('tmpfs', 'ramfs'):
            with self.subTest(kind=kind), self.assertRaisesRegex(RuntimeError, 'memory-backed'):
                self.check_drive(kind=kind)

    def test_local_archive_on_a_separate_mounted_drive_is_accepted_without_a_network_mount(self):
        self.check_drive(source='/srv/work', source_device=1)

    def test_local_archive_setting_reaches_the_archive_check(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('keep')
        stamp = time.time() - 8 * 86400
        for path in (source / 'unique', source):
            os.utime(path, (stamp, stamp))
        self.config['hosts']['test']['archive'] = [str(source)]
        self.config['local_archive_mount'] = '/mnt/backup'
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection), \
                patch.object(reclaim, 'check_nas', side_effect=RuntimeError('stop')) as check:
            self.engine.archives()
        check.assert_called_once_with(self.config['nas_root'], '/mnt/backup', str(source))

        self.assertTrue(source.exists())

    def test_category_totals_match_in_report_header_and_json(self):
        self.worktree()
        for name in ('scratch-a', 'bench-a', 'bench-b', 'transcripts'):
            self.aged(name, 31)
        evidence = self.root / 'evidence'
        self.config['hosts']['test']['archive'] = [
            str(evidence / 'scratch-*'),
            dict(path=str(evidence / 'bench-*'), category='test-output'),
            dict(path=str(evidence / 'transcripts'), category='artifact', preservation='summary')]
        store = self.root / 'memory'; store.mkdir()
        self.config['memory_store'] = str(store)
        (store / (hashlib.sha256(f"test:{evidence / 'transcripts'}".encode()).hexdigest() + '.json')).write_text(
            json.dumps(dict(schema_version=1, host='test', path=str(evidence / 'transcripts'), summary='note')))
        self.config['live'] = ['archive']
        self.engine.apply = True
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
            self.engine.archives()
        summary = json.loads(json.dumps(cli.summary([self.entry], True, None, 'code', 'ok', []), default=str))
        sizes = {Path(row['path']).name: row['bytes'] for row in self.entry_rows(summary)}
        expected = {
            'worktree': dict(items=1, reclaimable_bytes=sizes['work'], acted_bytes=0),
            'clone': dict(items=0, reclaimable_bytes=0, acted_bytes=0),
            'scratch': dict(items=1, reclaimable_bytes=sizes['scratch-a'], acted_bytes=sizes['scratch-a']),
            'test-output': dict(items=2, reclaimable_bytes=sizes['bench-a'] + sizes['bench-b'],
                                acted_bytes=sizes['bench-a'] + sizes['bench-b']),
            'artifact': dict(items=1, reclaimable_bytes=sizes['transcripts'], acted_bytes=sizes['transcripts'])}
        self.assertEqual(summary['categories'], expected)
        self.assertGreater(min(sizes.values()), 0, sizes)
        header = report.render([self.entry], True, reclaim=True).split('\n## test', 1)[0]
        for label, key in (('Completed worktrees', 'worktree'), ('Scratch and temp', 'scratch'),
                           ('Test and benchmark outputs', 'test-output'), ('Archived agent artifacts', 'artifact')):
            values = expected[key]
            self.assertIn(f"| {label} | {values['items']} | {values['reclaimable_bytes']} | {values['acted_bytes']} |", header)

    def test_tagged_pattern_sets_the_category_when_an_untagged_one_also_matches(self):
        self.aged('bench-a', 31)
        evidence = self.root / 'evidence'
        self.config['hosts']['test']['archive'] = [
            str(evidence / '*'), dict(path=str(evidence / 'bench-*'), category='test-output')]
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.archives()
        self.assertEqual([row['category'] for row in self.entry.actions], ['test-output'], self.entry.actions)
        self.assertEqual(report.categories([self.entry])['test-output']['items'], 1)
        self.config['hosts']['test']['archive'][1]['days'] = 60
        self.entry.actions.clear()
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.archives()
        self.assertEqual([(row['action'], row['category']) for row in self.entry.actions], [('skip', 'test-output')])

    def test_tagged_pattern_matching_only_a_child_leaves_the_parent_untagged(self):
        outer = self.aged('outer', 31)
        (outer / 'bench-x').mkdir()
        stamp = time.time() - 31 * 86400
        for path in (outer / 'bench-x', outer):
            os.utime(path, (stamp, stamp))
        evidence = self.root / 'evidence'
        self.config['hosts']['test']['archive'] = [
            str(evidence / '*'), dict(path=str(evidence / 'outer' / 'bench-*'), category='test-output')]
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.archives()
        categories = {Path(row['path']).name: row['category'] for row in self.entry.actions}
        self.assertEqual(categories, {'outer': 'scratch', 'bench-x': 'test-output'}, self.entry.actions)

    def entry_rows(self, summary):
        return [row for host in summary['hosts'] for row in host['actions']]

    def test_json_summary_is_one_object_on_stdout_with_progress_on_stderr(self):
        code, out, err = self.run_json()
        summary = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual((summary['status'], summary['mode']), ('ok', 'dry-run'))
        self.assertTrue(Path(summary['report']).is_file())
        self.assertEqual([host['name'] for host in summary['hosts']], [self.host.name])
        self.assertEqual(summary['hosts'][0]['disk_after_percent'], 20.0)
        self.assertEqual(summary['categories']['worktree'], dict(items=0, reclaimable_bytes=0, acted_bytes=0))
        self.assertIn('inspect', err)
        self.assertNotIn('inspect', out)

    def test_json_summary_reports_incomplete_run_with_exit_one(self):
        with patch.object(disk, 'measure', side_effect=OSError('offline')):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                code = cli.run(self.config, [self.host], as_json=True)
        self.assertEqual(code, 1)
        summary = json.loads(stdout.getvalue())
        self.assertEqual(summary['status'], 'incomplete')
        self.assertIn('offline', summary['hosts'][0]['errors'][0])

    def test_apply_without_a_live_reclaim_tier_is_refused_with_json_and_exit_two(self):
        self.config['live'] = ['project']
        stdout = io.StringIO()
        with patch.object(rules, 'load', return_value=self.config), patch.object(cli, 'run') as run, \
                contextlib.redirect_stdout(stdout):
            code = cli.main(['reclaim', '--apply', '--json'])
        run.assert_not_called()
        self.assertEqual(code, 2)
        refused = json.loads(stdout.getvalue())
        self.assertEqual(refused['status'], 'refused')
        self.assertIn('none of worktree, clone or archive is listed in live', refused['reason'])

    def test_apply_with_only_the_clone_tier_live_is_not_refused(self):
        self.config['live'] = ['clone']
        stdout = io.StringIO()
        with patch.object(rules, 'load', return_value=self.config), patch.object(cli, 'run', return_value=0), \
                contextlib.redirect_stdout(stdout):
            cli.main(['reclaim', '--apply', '--json'])
        self.assertNotIn('listed in live', stdout.getvalue())

    def test_apply_with_a_missing_nas_root_is_refused_with_exit_two(self):
        self.config['nas_root'] = str(self.root / 'absent' / 'archive')
        stdout = io.StringIO()
        with patch.object(rules, 'load', return_value=self.config), patch.object(cli, 'run') as run, \
                contextlib.redirect_stdout(stdout):
            code = cli.main(['reclaim', '--apply', '--json'])
        run.assert_not_called()
        self.assertEqual(code, 2)
        refused = json.loads(stdout.getvalue())
        self.assertEqual(refused['status'], 'refused')
        self.assertIn(self.config['nas_root'] + ' does not exist', refused['reason'])
        self.assertIn('local_archive_mount', refused['reason'])

    def reclaim_main(self, *argv, measure=None):
        Path(self.config['nas_root']).mkdir(parents=True, exist_ok=True)
        stdout = io.StringIO()
        with patch.object(rules, 'load', return_value=self.config), \
                patch.object(disk, 'measure', return_value=disk.Usage(100, 20, 20), side_effect=measure), \
                patch.object(protect, 'collect', return_value=protect.Protection(self.host, str(self.root), set(), [])), \
                patch.object(reclaim.Reclaimer, 'worktrees') as worktrees, patch.object(reclaim.Reclaimer, 'archives'), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(['reclaim', '--host', 'test', '--json', *argv])
        return code, json.loads(stdout.getvalue().splitlines()[-1]), worktrees.called

    def test_apply_is_refused_until_a_dry_run_report_with_the_same_rules_exists(self):
        code, refused, ran = self.reclaim_main('--apply')
        self.assertEqual((code, refused['status'], ran), (2, 'refused', False))
        self.assertIn('no complete reclaim dry-run report', refused['reason'])
        self.assertIn(' for test;', refused['reason'])
        self.assertEqual(self.reclaim_main()[0], 0)
        code, summary, ran = self.reclaim_main('--apply')
        self.assertEqual((code, summary['mode'], ran), (0, 'apply', True))

    def test_apply_is_refused_when_rules_changed_since_the_dry_run(self):
        self.reclaim_main()
        self.config['rules_sha256'] = 'f' * 64
        code, refused, ran = self.reclaim_main('--apply')
        self.assertEqual((code, ran), (2, False))
        self.assertIn('f' * 64, refused['reason'])

    def test_apply_needs_a_dry_run_not_an_apply_report_for_every_selected_host(self):
        other = hosts.Host('other', 'posix')
        self.config['hosts']['other'] = dict(roots=[], archive=[])
        with patch.dict(hosts.HOSTS, {'other': other}):
            self.reclaim_main()
            self.config['reclaim_hosts'] = ['test', 'other']
            stdout = io.StringIO()
            with patch.object(rules, 'load', return_value=self.config), patch.object(cli, 'run') as run, \
                    contextlib.redirect_stdout(stdout):
                code = cli.main(['reclaim', '--apply', '--json'])
        run.assert_not_called()
        self.assertEqual(code, 2)
        self.assertIn(' for other;', json.loads(stdout.getvalue())['reason'])
        for path in Path(self.config['report_dir']).glob('*.md'):
            path.write_text(path.read_text().replace('Mode: dry run', 'Mode: apply, limited to live tiers'))
        self.assertEqual(self.reclaim_main('--apply')[0], 2)

    def test_a_failed_or_legacy_dry_run_does_not_unlock_apply(self):
        self.assertEqual(self.reclaim_main(measure=OSError('offline'))[0], 1)
        report.write([report.HostReport('test')], self.config['report_dir'], rules_sha256=self.config.get('rules_sha256'))
        self.assertEqual(len(list(Path(self.config['report_dir']).glob('*.md'))), 2)
        for report_path in Path(self.config['report_dir']).glob('*.md'):
            with self.subTest(report=report_path.name):
                code, refused, ran = self.reclaim_main('--apply', '--i-reviewed', str(report_path))
                self.assertEqual((code, ran), (2, False))
        code, refused, ran = self.reclaim_main('--apply')
        self.assertEqual((code, ran), (2, False))

    def test_report_text_cannot_forge_the_dry_run_marker(self):
        forged = '\u2028'.join(['x', report.PREVIEWED + 'other', 'Rules: sha256 ' + 'f' * 64, 'Mode: dry run.', ''])
        failed = report.HostReport('test', errors=[forged], actions=[dict(tier='archive', action='skip', path=forged, bytes=0, reason=forged)])
        path = report.write([failed], self.root / 'reports', rules_sha256='f' * 64, reclaim=True)
        self.assertEqual(report.dry_run_hosts(path), set())
        complete = report.HostReport('other', actions=[dict(tier='archive', action='skip', path=forged, bytes=0, reason=forged)])
        path = report.write([failed, complete], self.root / 'reports', rules_sha256='f' * 64, reclaim=True)
        self.assertEqual(report.dry_run_hosts(path, 'f' * 64), {'other'})
        self.assertEqual(report.dry_run_hosts(path, 'e' * 64), set())

    def test_i_reviewed_accepts_a_reviewed_dry_run_report_for_the_host(self):
        self.reclaim_main()
        reviewed = next(Path(self.config['report_dir']).glob('*.md'))
        self.config['rules_sha256'] = 'f' * 64
        code, summary, ran = self.reclaim_main('--apply', '--i-reviewed', str(reviewed))
        self.assertEqual((code, summary['mode'], ran), (0, 'apply', True))
        apply_report = Path(summary['report'])
        other = hosts.Host('other', 'posix')
        self.config['hosts']['other'] = dict(roots=[], archive=[])
        with patch.dict(hosts.HOSTS, {'other': other}), patch.object(rules, 'load', return_value=self.config), \
                patch.object(cli, 'run') as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['reclaim', '--host', 'other', '--apply', '--i-reviewed', str(reviewed)]), 2)
        run.assert_not_called()
        for bad in (apply_report, self.root / 'missing.md'):
            with self.subTest(report=bad.name):
                code, refused, ran = self.reclaim_main('--apply', '--i-reviewed', str(bad))
                self.assertEqual((code, ran), (2, False))
                self.assertIn(str(bad), refused['reason'])

    def test_report_write_failure_after_apply_is_incomplete_not_refused(self):
        stdout = io.StringIO()
        with patch.object(report, 'write', side_effect=OSError('disk full')):
            with patch.object(disk, 'measure', return_value=disk.Usage(100, 20, 20)), \
                    patch.object(protect, 'collect', return_value=protect.Protection(self.host, str(self.root), set(), [])), \
                    patch.object(reclaim.Reclaimer, 'worktrees'), patch.object(reclaim.Reclaimer, 'archives'), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                code = cli.run(self.config, [self.host], True, as_json=True)
        summary = json.loads(stdout.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual((summary['status'], summary['report']), ('incomplete', None))
        self.assertIn('Report not written: disk full', summary['hosts'][0]['errors'])

    def test_report_write_failure_with_no_selected_hosts_is_incomplete(self):
        stdout = io.StringIO()
        with patch.object(report, 'write', side_effect=OSError('disk full')), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = cli.run(self.config, [], True, as_json=True)
        summary = json.loads(stdout.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual((summary['status'], summary['report'], summary['hosts']), ('incomplete', None, []))
        self.assertIn('Report not written: disk full', summary['errors'])

    def test_invalid_arguments_with_json_still_print_one_refusal_object(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(['reclaim', '--json', '--host', 'invalid'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout.getvalue())['status'], 'refused')

    def test_bad_rules_file_is_refused_with_json_and_exit_two(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = cli.main(['reclaim', '--json', '--rules', str(self.root / 'missing.toml')])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout.getvalue())['status'], 'refused')

    def test_cli_reclaim_selects_only_new_policy_and_default_two_hosts(self):
        with patch.object(rules, 'load', return_value=self.config), patch.object(cli, 'run', return_value=0) as run:
            self.assertEqual(cli.main(['reclaim']), 0)
        self.assertEqual([host.name for host in run.call_args.args[1]], ['server-a', 'winhost'])
        self.assertEqual(run.call_args.kwargs, dict(as_json=False))
        with patch.object(disk, 'measure', return_value=disk.Usage(100, 20, 20)), \
                patch.object(protect, 'collect', return_value=protect.Protection(self.host, str(self.root), set(), [])), \
                patch.object(reclaim.Reclaimer, 'worktrees') as worktrees, patch.object(reclaim.Reclaimer, 'archives') as archives, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.run(self.config, [self.host]), 0)
        worktrees.assert_called_once(); archives.assert_called_once()
