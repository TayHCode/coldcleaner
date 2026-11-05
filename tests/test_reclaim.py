import contextlib
import ctypes
import hashlib
import io
import json
import shutil
import os
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
        self.entry = report.HostReport('test')
        self.protection = Mock()
        self.protection.reason.return_value = ''
        self.protection.batch.side_effect = lambda paths, **kw: dict.fromkeys(paths, '')
        self.engine = reclaim.Reclaimer(self.host, self.config, False, self.protection, self.entry)
        self.env = patch.dict(os.environ, HOME=str(self.root), GIT_ALLOW_PROTOCOL='file',
                              GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
        self.env.start(); self.addCleanup(self.env.stop)
        original = reclaim_probe.main
        self.read_threads = reclaim_probe.threads
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
        for target, value in ((reclaim_probe, 'references'), (reclaim_probe, 'threads')):
            mock = patch.object(target, value, return_value=[])
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

    def worktree(self):
        repo = self.root / 'repo'; remote = self.root / 'remote.git'; work = self.root / 'work'
        repo.mkdir()
        self.git(repo, 'init', '-b', 'main')
        self.git(repo, 'config', 'user.name', 'Test')
        self.git(repo, 'config', 'user.email', 'test@localhost')
        self.git(repo, 'config', 'commit.gpgsign', 'false')
        (repo / 'tracked').write_text('durable')
        (repo / '.gitignore').write_text('evidence/\n')
        self.git(repo, 'add', '.')
        self.git(repo, 'commit', '-m', 'initial')
        self.git(self.root, 'init', '--bare', str(remote))
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

    def test_unique_head_and_branch_reflogs_retain_worktrees(self):
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
                with patch.object(protect, 'collect', return_value=self.protection):
                    self.engine.worktrees()
                self.assertTrue(candidate.is_dir(), self.entry.actions)
                ref = 'HEAD' if name == 'head-history' else 'refs/heads/' + name
                self.assertIn(unique, self.git(candidate, 'reflog', 'show', '--format=%H', ref))
                action = next(row for row in self.entry.actions if row['path'] == str(candidate))
                self.assertIn('reflog', action['reason'])

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

    def test_worktree_with_missing_gitdir_stays_an_error(self):
        orphan = self.root / 'orphan'; orphan.mkdir()
        (orphan / '.git').write_text(f'gitdir: {self.root}/gone/.git/worktrees/orphan\n')
        found = reclaim_probe.discover([str(self.root)])
        self.assertEqual(found['notes'], [])
        self.assertEqual(len(found['errors']), 1)
        self.assertIn(str(orphan), found['errors'][0])

    def test_temp_retention_cache_exclusion_and_vm_disks_are_retained(self):
        self.assertEqual(reclaim.retention('/tmp/test-output', 4), 7)
        self.assertEqual(reclaim.retention('C:\\Users\\name\\AppData\\Local\\Temp\\job', 4), 7)
        self.assertEqual(reclaim.retention('/evidence', 14), 14)
        for path in ('/tmp/node-compile-cache', '/home/name/.cache/uv', 'C:\\Users\\name\\npm-cache'):
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
        self.assertEqual(store.enforce_cap(self.root / 'nas', 0, apply=True), [])
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

    def test_real_archive_preview_and_apply_never_touch_cache_or_nas_expiry(self):
        source = self.root / 'evidence'; source.mkdir(); (source / 'unique').write_text('keep a copy')
        cache = self.root / 'package-cache'; cache.mkdir(); (cache / 'data').write_text('leave alone')
        stamp = time.time() - 8 * 86400
        for path in (source / 'unique', source):
            os.utime(path, (stamp, stamp))
        self.config['hosts']['test']['archive'] = [str(source)]
        self.config['hosts']['test']['cache'] = [dict(path=str(cache))]
        with patch.object(protect, 'collect', return_value=self.protection):
            self.engine.archives()
            self.assertTrue(source.exists())
            self.assertFalse((self.root / 'nas').exists())
            self.engine.apply = True
            self.engine.archives()
        self.assertFalse(source.exists(), self.entry.actions)
        self.assertEqual((cache / 'data').read_text(), 'leave alone')
        self.assertIn('SHA-256 verified', self.entry.actions[-1]['reason'])

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

    def test_guard_rejects_filesystem_root_and_home(self):
        home = self.root / 'home'; home.mkdir()
        with patch.dict(os.environ, HOME=str(home)), patch.object(reclaim_probe, 'threads', return_value=[]), \
                patch.object(reclaim_probe, 'references', return_value=[]):
            for path in ('/', Path('/'), str(home), str(home) + '/', home, str(home / 'x' / '..'), 'relative/dir'):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'invalid cleanup root'):
                    reclaim_probe.guard(path)
        self.assertTrue(home.is_dir())

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

    def run_json(self, apply=False):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(disk, 'measure', return_value=disk.Usage(100, 20, 20)), \
                patch.object(protect, 'collect', return_value=protect.Protection(self.host, str(self.root), set(), [])), \
                patch.object(reclaim.Reclaimer, 'worktrees'), patch.object(reclaim.Reclaimer, 'archives'), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.run(self.config, [self.host], apply, reclaim_only=True, as_json=True)
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
            self.check_drive(source='/home/work', source_device=2)

    def test_local_archive_on_a_memory_backed_filesystem_is_refused(self):
        for kind in ('tmpfs', 'ramfs'):
            with self.subTest(kind=kind), self.assertRaisesRegex(RuntimeError, 'memory-backed'):
                self.check_drive(kind=kind)

    def test_local_archive_on_a_separate_mounted_drive_is_accepted_without_a_network_mount(self):
        self.check_drive(source='/home/work', source_device=1)

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

    def test_json_summary_is_one_object_on_stdout_with_progress_on_stderr(self):
        code, out, err = self.run_json()
        summary = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual((summary['status'], summary['mode']), ('ok', 'dry-run'))
        self.assertTrue(Path(summary['report']).is_file())
        self.assertEqual([host['name'] for host in summary['hosts']], [self.host.name])
        self.assertEqual(summary['hosts'][0]['disk_after_percent'], 20.0)
        self.assertIn('inspect', err)
        self.assertNotIn('inspect', out)

    def test_json_summary_reports_incomplete_run_with_exit_one(self):
        with patch.object(disk, 'measure', side_effect=OSError('offline')):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                code = cli.run(self.config, [self.host], reclaim_only=True, as_json=True)
        self.assertEqual(code, 1)
        summary = json.loads(stdout.getvalue())
        self.assertEqual(summary['status'], 'incomplete')
        self.assertIn('offline', summary['hosts'][0]['errors'][0])

    def test_apply_without_a_live_reclaim_tier_is_refused_with_json_and_exit_two(self):
        self.config['live'] = ['cache']
        stdout = io.StringIO()
        with patch.object(rules, 'load', return_value=self.config), patch.object(cli, 'run') as run, \
                contextlib.redirect_stdout(stdout):
            code = cli.main(['reclaim', '--apply', '--json'])
        run.assert_not_called()
        self.assertEqual(code, 2)
        refused = json.loads(stdout.getvalue())
        self.assertEqual(refused['status'], 'refused')
        self.assertIn('neither worktree nor archive is listed in live', refused['reason'])

    def test_report_write_failure_after_apply_is_incomplete_not_refused(self):
        stdout = io.StringIO()
        with patch.object(report, 'write', side_effect=OSError('disk full')):
            with patch.object(disk, 'measure', return_value=disk.Usage(100, 20, 20)), \
                    patch.object(protect, 'collect', return_value=protect.Protection(self.host, str(self.root), set(), [])), \
                    patch.object(reclaim.Reclaimer, 'worktrees'), patch.object(reclaim.Reclaimer, 'archives'), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                code = cli.run(self.config, [self.host], True, reclaim_only=True, as_json=True)
        summary = json.loads(stdout.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual((summary['status'], summary['report']), ('incomplete', None))
        self.assertIn('Report not written: disk full', summary['hosts'][0]['errors'])

    def test_report_write_failure_with_no_selected_hosts_is_incomplete(self):
        stdout = io.StringIO()
        with patch.object(report, 'write', side_effect=OSError('disk full')), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = cli.run(self.config, [], True, reclaim_only=True, as_json=True)
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
        self.assertEqual(run.call_args.kwargs, dict(reclaim_only=True, as_json=False))
        with patch.object(disk, 'measure', return_value=disk.Usage(100, 20, 20)), \
                patch.object(protect, 'collect', return_value=protect.Protection(self.host, str(self.root), set(), [])), \
                patch.object(reclaim.Reclaimer, 'worktrees') as worktrees, patch.object(reclaim.Reclaimer, 'archives') as archives, \
                patch.object(cli.store, 'enforce_cap', side_effect=AssertionError('NAS expiry')), \
                patch.object(cli.tiers.Cleaner, 'cache', side_effect=AssertionError('cache action')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.run(self.config, [self.host], reclaim_only=True), 0)
        worktrees.assert_called_once(); archives.assert_called_once()
