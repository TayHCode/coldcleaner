import contextlib
import io
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from coldcleaner import cli, disk, hosts, protect, reclaim, report, rules
from coldcleaner import store as storage
from tests import outside_git

outside_git.use()

TIERS = ('worktrees', 'clones', 'archives', 'unlisted')


class CoreCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = rules.load(Path(__file__).parent / 'fixtures' / 'rules.toml')
        self.host = hosts.Host('test', 'posix')
        host_patch = patch.dict(hosts.HOSTS, {'test': self.host})
        host_patch.start()
        self.addCleanup(host_patch.stop)
        self.config['live'] = ['worktree', 'archive']
        self.config['nas_root'] = str(self.root / 'nas')
        self.config['report_dir'] = str(self.root / 'reports')
        self.config['hosts']['test'] = {'roots': [], 'archive': []}
        self.entry = report.HostReport('test')
        self.protection = protect.Protection(self.host, str(self.root), set(), [])
        self.collect_schedulers = protect.collect
        collector = patch.object(protect, 'collect', return_value=self.protection)
        collector.start()
        self.addCleanup(collector.stop)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.lsof('')
        env = patch.dict(os.environ, {'PATH': str(self.bin) + os.pathsep + os.environ['PATH'], 'GIT_ALLOW_PROTOCOL': 'file'})
        env.start()
        self.addCleanup(env.stop)

    def lsof(self, text):
        command = self.bin / 'lsof'
        command.write_text('#!/bin/sh\n' + (f"echo 'n{self.root}/cache/data'; exit 0\n" if text else 'exit 1\n'))
        command.chmod(0o755)

    def candidate(self, name='cache'):
        path = self.root / name
        path.mkdir()
        (path / 'data').write_text('payload')
        stamp = time.time() - 60
        os.utime(path / 'data', (stamp, stamp))
        os.utime(path, (stamp, stamp))
        return SimpleNamespace(path=str(path))



class RulesTests(CoreCase):
    def test_invalid_rules_rejected(self):
        original = (Path(__file__).parent / 'fixtures/rules.toml').read_text()
        for old, new in [('alert_pct = 80', 'alert_pct = true'), ('alert_pct = 80', 'alert_pct = 0'),
                         ('live = ["worktree", "archive"]', 'live = ["oops"]'),
                         ('archive_idle_days = 4', 'archive_idle_days = -1')]:
            with self.subTest(new=new):
                path = self.root / 'rules.toml'
                path.write_text(original.replace(old, new))
                with self.assertRaises(ValueError):
                    rules.load(path)


class DiskTests(CoreCase):
    def test_linux_mount_and_bytes(self):
        result = SimpleNamespace(stdout=b'Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x 1000 700 300 70% /\n')
        with patch.object(hosts, 'run', return_value=result) as run:
            value = disk.measure(self.host)
        self.assertEqual(value, disk.Usage(1024000, 716800, 70))
        self.assertIn('else df -Pk /;', run.call_args.args[1])

    def test_df_capacity_includes_unavailable_space(self):
        result = SimpleNamespace(stdout=b'header\n/dev/x 1000 844 90 91% /\n')
        with patch.object(hosts, 'run', return_value=result):
            value = disk.measure(self.host)
        self.assertEqual(value.percent, 91)
        self.assertEqual(value.used, 864256)

    def test_mac_mount(self):
        result = SimpleNamespace(stdout=b'header\n/dev/x 100 75 25 75% /System/Volumes/Data\n')
        with patch.object(hosts, 'run', return_value=result) as run:
            self.assertEqual(disk.measure(hosts.HOSTS['machost']).percent, 75)
        self.assertIn('Darwin ]; then df -Pk /System/Volumes/Data;', run.call_args.args[1])

    def test_wsl_uses_windows_disk(self):
        with patch.object(hosts, 'run', return_value=SimpleNamespace(stdout=b'{"total":1000,"used":850}')) as run:
            self.assertEqual(disk.measure(hosts.HOSTS['winhost-wsl']).percent, 85)
        self.assertEqual(run.call_args.args[0], hosts.Host('winhost-wsl', 'powershell', 'winhost'))
        self.assertIn('Get-PSDrive C', run.call_args.args[1])

    def test_invalid_usage_rejected(self):
        with patch.object(hosts, 'run', return_value=SimpleNamespace(stdout=b'{"total":0,"used":0}')):
            with self.assertRaises(ValueError):
                disk.measure(hosts.HOSTS['winhost'])


class ProtectionTests(CoreCase):
    def scheduler_inventory(self, root, load_state='', entries=None):
        walk = os.walk
        def unit_walk(path):
            if path != '/etc/systemd/system':
                return []
            return [(str(root), [], entries)] if entries else walk(root)
        def run(command, **kwargs):
            state = load_state.get(command[-1], 'not-found') if isinstance(load_state, dict) else load_state
            return SimpleNamespace(stdout=state if 'show' in command else '', stderr='', returncode=0)
        output = io.StringIO()
        with patch('os.walk', side_effect=unit_walk), patch('glob.glob', return_value=[]), \
             patch('subprocess.run', side_effect=run), \
             contextlib.redirect_stdout(output):
            exec(protect.SCHEDULERS, {})
        return json.loads(output.getvalue())

    def test_linked_systemd_units_protect_references_and_deduplicate_targets(self):
        units = self.root / 'units'
        units.mkdir()
        item = self.candidate()
        target = self.root / 'linked.service'
        target.write_text('[Service]\nWorkingDirectory=' + item.path + '\n')
        for name in ('linked.service', 'alias.service'):
            (units / name).symlink_to(target)
        with patch('builtins.open', wraps=open) as opened:
            obj = self.scheduler_inventory(units)
        self.assertEqual(obj['errors'], [])
        protection = protect.Protection(self.host, obj['home'], protect.extract_paths(obj['text'], obj['home']), [])
        self.assertIn('scheduler references', protection.reason(item.path))
        self.assertEqual(opened.call_count, 1)

    def test_dangling_systemd_unit_link_is_ignored_as_a_reference(self):
        units = self.root / 'units'
        units.mkdir()
        item = self.candidate()
        (units / 'missing.service').symlink_to(self.root / 'absent.service')
        (units / 'live.service').write_text('[Service]\nWorkingDirectory=' + item.path + '\n')
        obj = self.scheduler_inventory(units, load_state='not-found')
        self.assertEqual(obj['errors'], [])
        protection = protect.Protection(self.host, obj['home'], protect.extract_paths(obj['text'], obj['home']), obj['errors'])
        self.assertIn('scheduler references', protection.reason(item.path))

    def test_dangling_link_to_a_still_loaded_unit_makes_inventory_incomplete(self):
        units = self.root / 'units'
        units.mkdir()
        (units / 'deleted.service').symlink_to(self.root / 'absent.service')
        obj = self.scheduler_inventory(units, load_state='loaded')
        self.assertEqual(len(obj['errors']), 1)
        protection = protect.Protection(self.host, obj['home'], set(), obj['errors'])
        self.assertIn('protection inventory incomplete', protection.reason(self.candidate().path))

    def test_dangling_alias_to_a_still_loaded_target_unit_makes_inventory_incomplete(self):
        units = self.root / 'units'
        units.mkdir()
        (units / 'alias.service').symlink_to(self.root / 'real.service')
        obj = self.scheduler_inventory(units, load_state={'alias.service': 'not-found', 'real.service': 'loaded'})
        self.assertEqual(len(obj['errors']), 1)

    def test_skipped_dangling_link_does_not_hide_its_vanished_regular_target(self):
        units = self.root / 'units'
        units.mkdir()
        target = units / 'real.service'
        target.write_text('[Service]\n')
        (units / 'alias.service').symlink_to(target)
        with patch('builtins.open', side_effect=FileNotFoundError('unit vanished')):
            obj = self.scheduler_inventory(units, load_state='not-found', entries=['alias.service', 'real.service'])
        self.assertEqual(obj['errors'], ['unit vanished'])

    def test_vanished_regular_systemd_unit_makes_inventory_incomplete(self):
        units = self.root / 'units'
        units.mkdir()
        (units / 'gone.service').write_text('[Service]\n')
        with patch('builtins.open', side_effect=FileNotFoundError('unit vanished')):
            obj = self.scheduler_inventory(units)
        self.assertEqual(obj['errors'], ['unit vanished'])
        protection = protect.Protection(self.host, obj['home'], set(), obj['errors'])
        self.assertIn('protection inventory incomplete', protection.reason(self.candidate().path))

    def test_unreadable_linked_systemd_unit_makes_inventory_incomplete(self):
        units = self.root / 'units'
        units.mkdir()
        target = self.root / 'private.service'
        target.write_text('[Service]\nExecStart=/private/task\n')
        (units / 'private.service').symlink_to(target)
        with patch('builtins.open', side_effect=PermissionError('unit unreadable')):
            obj = self.scheduler_inventory(units)
        self.assertEqual(obj['errors'], ['unit unreadable'])

    def test_unit_cron_and_home_paths(self):
        text = '[Service]\nWorkingDirectory=%h/projects/app\nExecStart=/usr/bin/python3 /home/user/jobs/daily.py\n0 1 * * * ~/jobs/cleanup.sh'
        paths = protect.extract_paths(text, '/home/user')
        self.assertTrue({'/home/user/projects/app', '/usr/bin/python3', '/home/user/jobs/daily.py', '/home/user/jobs/cleanup.sh'} <= paths)

    def test_shell_home_scheduler_references_protect_real_project(self):
        for variable in ('$HOME', '${HOME}'):
            with self.subTest(variable=variable):
                text = '0 1 * * * /usr/bin/python3 "' + variable + '/projects/app/local/task.py"'
                paths = protect.extract_paths(text, str(self.root))
                expected = str(self.root / 'projects/app/local/task.py')
                self.assertIn(expected, paths)
                protection = protect.Protection(self.host, str(self.root), paths, [])
                self.assertIn('scheduler references', protection.reason(str(self.root / 'projects/app/local')))

    def test_plist_quoted_space(self):
        paths = protect.extract_paths('<key>WorkingDirectory</key><string>/Users/user/Library/Work App</string>', '/Users/user')
        self.assertIn('/Users/user/Library/Work App', paths)
        obj = json.dumps({'WorkingDirectory': '/Users/user/Library/Work App', 'ProgramArguments': ['/usr/bin/python3', '/Users/user/app.py']})
        self.assertIn('/Users/user/Library/Work App', protect.extract_paths(obj, '/Users/user'))

    def test_windows_tasks_expand_environment(self):
        text = json.dumps({'Execute': 'C:\\tools\\task.exe', 'WorkingDirectory': '%USERPROFILE%\\REPOS\\Task App'})
        paths = protect.extract_paths(text, 'C:\\Users\\user', True, {'USERPROFILE': 'C:\\Users\\user'})
        self.assertIn('C:\\tools\\task.exe', paths)
        self.assertIn('C:\\Users\\user\\REPOS\\Task App', paths)

    def test_overlap_both_directions_and_component_boundary(self):
        self.assertTrue(protect.overlaps('/repos/app', '/repos/app/run.py'))
        self.assertTrue(protect.overlaps('/repos/app/data', '/repos/app'))
        self.assertFalse(protect.overlaps('/repos/apple', '/repos/app'))
        self.assertTrue(protect.overlaps('c:\\Repos\\App', 'C:\\repos\\app\\run.ps1', True))

    def test_scheduler_reference_blocks_parent(self):
        item = self.candidate()
        self.protection.paths.add(item.path + '/daily.py')
        self.assertIn('scheduler', self.protection.reason(item.path))

    def test_incomplete_scheduler_inventory_blocks(self):
        self.protection.errors.append('permission denied')
        self.assertIn('incomplete', self.protection.reason(str(self.root)))

    def test_keep_local_ancestor(self):
        item = self.candidate()
        (self.root / '.keep-local').touch()
        self.assertEqual(self.protection.reason(item.path), '.keep-local')

    def test_keep_local_descendant(self):
        item = self.candidate()
        (Path(item.path) / 'nested').mkdir()
        (Path(item.path) / 'nested' / '.keep-local').touch()
        self.assertEqual(self.protection.reason(item.path), '.keep-local')

    def test_open_file_blocks(self):
        item = self.candidate()
        self.lsof('open')
        self.assertEqual(self.protection.reason(item.path), 'open files')

    def test_posix_batch_takes_one_lsof_snapshot(self):
        items = [self.candidate(name) for name in ('open', 'open-prefix', 'closed')]
        paths = [item.path for item in items]
        log = self.root / 'lsof-calls'
        command = self.bin / 'lsof'
        command.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$LSOF_LOG"\n'
                           'printf "n%s\\n" "$OPEN_FILE"\n')
        with patch.dict(os.environ, {'LSOF_LOG': str(log), 'OPEN_FILE': paths[0] + '/data'}):
            result = subprocess.run(['python3', '-c', protect.POSIX_BATCH],
                input=json.dumps([paths, False, True]), text=True, capture_output=True, check=True)
        self.assertEqual(log.read_text().splitlines(), ['-nP -Fn'])
        self.assertEqual(json.loads(result.stdout), {paths[0]: 'open files', paths[1]: '', paths[2]: ''})

    def test_posix_mount_warnings_only_protect_overlapping_paths(self):
        paths = [self.candidate(name).path for name in ('closed', 'open')]
        mounts = ['/var/snap/lxd/common/ns/shmounts',
                  '/var/lib/incus/storage-pools/asb-build-pool/custom/default_asb-images',
                  '/sys/kernel/debug/tracing', '/var/snap/lxd/common/ns/mntns']
        warnings = """lsof: WARNING: can't stat() nsfs file system /var/snap/lxd/common/ns/shmounts
lsof: WARNING: can't stat() ext4 file system /var/lib/incus/storage-pools/asb-build-pool/custom/default_asb-images
lsof: WARNING: can't stat() tracefs file system /sys/kernel/debug/tracing
lsof: WARNING: can't stat() nsfs file system /var/snap/lxd/common/ns/mntns
      Output information may be incomplete.
"""
        overlapping = [mounts[0], mounts[1] + '/child', '/sys/kernel/debug']
        paths += overlapping + ['/var/snap/lxd/common/ns/shmounts-prefix']
        command = self.bin / 'lsof'
        command.write_text('#!/bin/sh\nprintf "%s" "$LSOF_ERROR" >&2\nprintf "n%s\\n" "$OPEN_FILE"\n')
        source = protect.POSIX_BATCH.replace('reasons = {}', "check = lambda path: ''\nreasons = {}")
        with patch.dict(os.environ, {'LSOF_ERROR': warnings, 'OPEN_FILE': paths[1] + '/data'}):
            result = subprocess.run(['python3', '-c', source], input=json.dumps([paths, False, True]),
                text=True, capture_output=True, check=True, timeout=5)
        expected = dict.fromkeys(paths, '')
        expected.update(dict.fromkeys(overlapping, 'lsof check incomplete'))
        expected[paths[1]] = 'open files'
        self.assertEqual(json.loads(result.stdout), expected)

    def test_posix_unknown_warning_or_exit_retains_unrelated_paths(self):
        paths = [self.candidate(name).path for name in ('closed-one', 'closed-two')]
        warning = "lsof: WARNING: can't stat() nsfs file system /unavailable/mount\n      Output information may be incomplete.\n"
        command = self.bin / 'lsof'
        command.write_text('#!/bin/sh\nprintf "%s" "$LSOF_ERROR" >&2\nexit "$LSOF_CODE"\n')
        for error, code in ((warning + 'unknown diagnostic\n', 0),
                            ('      Output information may be incomplete.\n', 0),
                            ('      assuming "dev=36000073" from mount table\n', 0),
                            (warning + '      assuming "dev=36000073" from mount table\nunknown diagnostic\n', 0),
                            (warning, 2)):
            with self.subTest(error=error, code=code):
                with patch.dict(os.environ, {'LSOF_ERROR': error, 'LSOF_CODE': str(code)}):
                    self.assertEqual(self.protection.batch(paths), dict.fromkeys(paths, 'lsof check incomplete'))

    def test_mac_mount_warning_continuation_only_protects_overlapping_paths(self):
        mount = self.root / 'TimeMachine-machost'
        mount.mkdir()
        (mount / 'child').mkdir()
        unrelated = self.candidate('TimeMachine-machost-prefix')
        paths = [str(mount), str(mount / 'child'), unrelated.path]
        warning = "lsof: WARNING: can't stat() smbfs file system " + str(mount) + '\n'
        warning += '      Output information may be incomplete.\n      assuming "dev=36000073" from mount table\n'
        command = self.bin / 'lsof'
        command.write_text('#!/bin/sh\nprintf "%s" "$LSOF_ERROR" >&2\nexit 1\n')
        with patch.dict(os.environ, {'LSOF_ERROR': warning}):
            self.assertEqual(self.protection.batch(paths), {paths[0]: 'lsof check incomplete',
                paths[1]: 'lsof check incomplete', paths[2]: ''})

    def test_posix_deadline_preserves_finished_reasons(self):
        items = [self.candidate(f'partial-{i}') for i in range(3)]
        paths = [item.path for item in items]
        (Path(paths[0]) / '.keep-local').touch()
        source = protect.POSIX_BATCH.replace('from pathlib import Path',
            'from pathlib import Path\nclock = iter([0, 0, 0, 841])\ntime.monotonic = lambda: next(clock, 841)')
        result = subprocess.run(['python3', '-c', source], input=json.dumps([paths, False, True]),
            text=True, capture_output=True, check=True, timeout=5)
        self.assertEqual(json.loads(result.stdout), {paths[0]: '.keep-local',
            paths[1]: 'protection check timed out', paths[2]: 'protection check timed out'})

    def test_posix_snapshot_failure_retains_all_remaining_candidates(self):
        items = [self.candidate(name) for name in ('one', 'two', 'kept')]
        paths = [item.path for item in items]
        (Path(paths[2]) / '.keep-local').touch()
        command = self.bin / 'lsof'
        for output, error, code in (('', 'warning: cannot stat mount', 0),
                                   ('', '', 2), ('n' + paths[0] + '/data', '', 1)):
            with self.subTest(output=output, error=error, code=code):
                command.write_text('#!/bin/sh\nprintf "%s" "$LSOF_OUTPUT"\n'
                                   'printf "%s" "$LSOF_ERROR" >&2\nexit "$LSOF_CODE"\n')
                with patch.dict(os.environ, {'LSOF_OUTPUT': output, 'LSOF_ERROR': error, 'LSOF_CODE': str(code)}):
                    self.assertEqual(self.protection.batch(paths), {paths[0]: 'lsof check incomplete',
                        paths[1]: 'lsof check incomplete', paths[2]: '.keep-local'})

    def test_posix_deadline_interrupts_blocking_walk_and_prints_partial_results(self):
        items = [self.candidate(f'interrupt-{i}') for i in range(3)]
        paths = [item.path for item in items]
        (Path(paths[0]) / '.keep-local').touch()
        source = protect.POSIX_BATCH.replace('from pathlib import Path', '''from pathlib import Path
time.monotonic = lambda: 0
def blocked_walk(*args, **kwargs):
    time.monotonic = lambda: 841
    signal.setitimer(signal.ITIMER_REAL, 0.01)
    time.sleep(4)
os.walk = blocked_walk''')
        result = subprocess.run(['python3', '-c', source], input=json.dumps([paths, False, True]),
            text=True, capture_output=True, check=True, timeout=5)
        self.assertEqual(json.loads(result.stdout), {paths[0]: '.keep-local',
            paths[1]: 'protection check timed out', paths[2]: 'protection check timed out'})

    def test_symlink_ancestor_blocks(self):
        item = self.candidate()
        (self.root / 'alias').symlink_to(item.path, target_is_directory=True)
        self.assertEqual(self.protection.reason(str(self.root / 'alias' / 'data')), 'symlink')

    def test_root_and_bare_home_scheduler_references(self):
        self.assertIn('/', protect.extract_paths('WorkingDirectory=/\n', str(self.root)))
        self.assertIn(str(self.root), protect.extract_paths('WorkingDirectory=~\n', str(self.root)))

    def test_git_data_in_candidate_is_protected(self):
        item = self.candidate()
        (Path(item.path) / '.git').mkdir()
        self.assertEqual(self.protection.reason(item.path), 'git metadata requires GitHub safety review')
        self.assertEqual(self.protection.reason(item.path, allow_git=True), '')

    def test_native_windows_protection_failure_is_closed(self):
        self.protection.host = hosts.HOSTS['winhost']
        with patch.object(hosts, 'run', return_value=SimpleNamespace(returncode=1, stderr=b'')):
            self.assertEqual(self.protection.reason('C:\\cache'), 'protection check failed')

    def test_scheduler_collection_single_call(self):
        sample = dict(home='/srv/test', text='WorkingDirectory=/srv/test/project', errors=[])
        with patch.object(hosts, 'run', return_value=SimpleNamespace(stdout=json.dumps(sample).encode())) as run:
            result = self.collect_schedulers(self.host)
        self.assertEqual(run.call_count, 1)
        self.assertIn('/srv/test/project', result.paths)


class BatchProtectionTests(CoreCase):
    def test_batch_isolates_errors_and_preserves_protection_reasons(self):
        safe = self.candidate('safe')
        kept = self.candidate('kept')
        linked = self.candidate('linked')
        git = self.candidate('git')
        (Path(kept.path) / '.keep-local').touch()
        (Path(linked.path) / 'alias').symlink_to(safe.path, target_is_directory=True)
        (Path(git.path) / '.git').mkdir()
        missing = str(self.root / 'missing')
        paths = [missing, safe.path, kept.path, linked.path, git.path]
        with patch.object(hosts, 'run', wraps=hosts.run) as run:
            reasons = self.protection.batch(paths)
        self.assertEqual(run.call_count, 1)
        self.assertIn('protection check incomplete:', reasons.pop(missing))
        self.assertEqual(reasons, {safe.path: '', kept.path: '.keep-local',
            linked.path: 'symlink descendant', git.path: 'git metadata requires GitHub safety review'})

    def test_large_posix_batch_uses_stdin_without_argument_limits(self):
        safe = self.candidate('safe-large-batch')
        missing = [str(self.root / ('missing-' + 'long' * 30 + str(i))) for i in range(1500)]
        paths = [safe.path, *missing]
        self.assertGreater(len(json.dumps(paths)), 128 * 1024)
        with patch.object(hosts, 'run', wraps=hosts.run) as run:
            reasons = self.protection.batch(paths)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(reasons[safe.path], '')
        self.assertTrue(all('No such file or directory' in reasons[path] for path in missing))
        self.assertEqual(json.loads(run.call_args.kwargs['stdin_bytes']), [paths, False, True])

    def test_windows_batch_timeout_is_closed(self):
        self.protection.host = hosts.HOSTS['winhost']
        paths = [r'C:\cache-one', r'C:\cache-two']
        with patch.object(hosts, 'run', side_effect=subprocess.TimeoutExpired('powershell', 900)) as run:
            self.assertEqual(self.protection.batch(paths), dict.fromkeys(paths, 'protection check timed out'))
        self.assertEqual(run.call_args.kwargs['timeout'], 900)

    def test_remote_deadline_marks_remaining_paths_timed_out(self):
        items = [self.candidate(f'deadline-{i}') for i in range(2)]
        paths = [item.path for item in items]
        with patch.object(protect, 'POSIX_BATCH', protect.POSIX_BATCH.replace('+ 840', '+ 0')):
            self.assertEqual(self.protection.batch(paths), dict.fromkeys(paths, 'protection check timed out'))

    def test_invalid_or_missing_batch_results_fail_closed(self):
        paths = ['/safe', '/missing', '/invalid']
        with patch.object(disk, 'python', return_value={'/safe': '', '/invalid': False}):
            reasons = self.protection.batch(paths)
        self.assertEqual(reasons, {'/safe': '', '/missing': 'protection check incomplete: missing or invalid result',
            '/invalid': 'protection check incomplete: missing or invalid result'})

    def test_windows_batch_encodes_paths_and_uses_one_call(self):
        import base64
        import re
        self.protection.host = hosts.HOSTS['winhost']
        paths = ["C:\\cache\\'quoted' $name `value` [x]", 'C:\\cache\\unicode-雪']
        expected = {path: '' for path in paths}
        def response(host, script, **kwargs):
            encoded = re.search(r"FromBase64String\('([^']+)'\)", script)[1]
            self.assertEqual(json.loads(base64.b64decode(encoded)), paths)
            self.assertNotIn(paths[0], script)
            self.assertEqual(kwargs['timeout'], 900)
            return SimpleNamespace(returncode=0, stdout=json.dumps(expected).encode())
        with patch.object(hosts, 'run', side_effect=response) as run:
            self.assertEqual(self.protection.batch(paths), expected)
        self.assertEqual(run.call_count, 1)

    def test_posix_batch_preserves_special_path_characters(self):
        items = [self.candidate(name) for name in ("quote' $name `value` [x]", 'unicode-雪\nline')]
        self.assertEqual(self.protection.batch([item.path for item in items]), {item.path: '' for item in items})

class CliReportTests(CoreCase):
    def test_reclaim_logs_the_retired_wsl_skip_with_its_policy(self):
        retired = hosts.Host('winhost-wsl', 'wsl', 'bridge.example.invalid')
        self.config['nas_root'] = str(self.root)
        with patch.dict(hosts.HOSTS, {'test': self.host, retired.name: retired}, clear=True), \
             patch.object(rules, 'load', return_value=self.config), \
             patch.object(disk, 'measure', return_value=disk.Usage(100, 20, 20)), \
             patch.object(protect, 'collect') as protection, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['reclaim', '--host', retired.name]), 0)
            self.assertFalse((Path(self.config['report_dir']) / 'reclaim-actions.jsonl').exists())
            self.assertEqual(cli.main(['reclaim', '--host', retired.name, '--apply']), 0)
        protection.assert_not_called()
        row = json.loads((Path(self.config['report_dir']) / 'reclaim-actions.jsonl').read_text())
        self.assertEqual({key: row.get(key) for key in ('host', 'tier', 'action', 'rule', 'idle_days', 'rules_sha256')},
                         dict(host=retired.name, tier='execution', action='skip', rule=retired.name + '.kind:wsl',
                              idle_days=None, rules_sha256=self.config.get('rules_sha256')))
        self.assertIn('code', row)

    def invoke(self, usages, host_list=None, apply=False, **overrides):
        output = io.StringIO()
        steps = {name: overrides.get(name, Mock()) for name in TIERS}
        with patch.object(disk, 'measure', side_effect=usages), \
             patch.object(protect, 'collect', return_value=self.protection), \
             patch.multiple(reclaim.Reclaimer, **steps), contextlib.redirect_stdout(output):
            code = cli.run(self.config, host_list or [self.host], apply)
        return code, output.getvalue()

    def test_progress_line_per_tier_start_and_done(self):
        _, output = self.invoke([disk.Usage(100, 20, 20), disk.Usage(100, 20, 20)])
        lines = output.splitlines()
        for tier in TIERS:
            start = lines.index(f'test: {tier} start')
            self.assertRegex(lines[start + 1], rf'^test: {tier} done, \d+ items, \d+s$')

    def test_exit_alert_after_run(self):
        code, _ = self.invoke([disk.Usage(100, 90, 90), disk.Usage(100, 80, 80)])
        self.assertEqual(code, 3)
        path = next((self.root / 'reports').glob('*.md'))
        text = path.read_text()
        self.assertIn('Before: 90.00%', text)
        self.assertIn('After: 80.00%', text)
        self.assertIn('- ATTENTION: disk 80.00% is at or above alert_pct 80%', text)
        self.assertNotIn('incomplete', text)

    def test_low_disk_runs_every_reclaim_step_in_order(self):
        called = []
        steps = {name: lambda self, name=name: called.append(name) for name in TIERS}
        code, _ = self.invoke([disk.Usage(100, 1, 1)] * 2, **steps)
        self.assertEqual(code, 0)
        self.assertEqual(called, list(TIERS))

    def test_unreachable_host_does_not_stop_next_host(self):
        second = hosts.Host('second', 'posix')
        with patch.object(cli, 'RETRY_SECONDS', 0):
            code, output = self.invoke([OSError('offline'), OSError('offline'), disk.Usage(100, 20, 20), disk.Usage(100, 20, 20)],
                                       [self.host, second])
        self.assertEqual(code, 1)
        self.assertIn('second: 20.00%', output)
        text = next((self.root / 'reports').glob('*.md')).read_text()
        self.assertIn('offline', text)
        self.assertIn('## second', text)

    def test_host_is_retried_once_after_a_backoff_before_it_is_unreachable(self):
        sleep = Mock()
        with patch.object(cli, 'time', SimpleNamespace(sleep=sleep, monotonic=time.monotonic)):
            code, output = self.invoke([OSError('ssh exit 255'), disk.Usage(100, 20, 20), disk.Usage(100, 20, 20)])
        self.assertEqual(code, 0)
        sleep.assert_called_once_with(cli.RETRY_SECONDS)
        self.assertGreater(cli.RETRY_SECONDS, 0)
        self.assertIn('test: unreachable (ssh exit 255); retrying in', output)
        self.assertNotIn('unreachable', next((self.root / 'reports').glob('*.md')).read_text())

    def test_step_error_does_not_abort_other_steps_or_measurement(self):
        archives = Mock()
        code, _ = self.invoke([disk.Usage(100, 75, 75)] * 2,
                              worktrees=Mock(side_effect=RuntimeError('worktree error')), archives=archives)
        self.assertEqual(code, 1)
        archives.assert_called_once()
        text = next((self.root / 'reports').glob('*.md')).read_text()
        self.assertIn('worktrees incomplete: worktree error', text)
        self.assertIn('After: 75.00%', text)

    def test_step_failure_reports_only_three_stderr_lines(self):
        error = subprocess.CalledProcessError(1, ['bash', '-c', 'whole script must stay out'],
            stderr=b'Cannot read directory: /one\nCannot read directory: /two\nCannot read directory: /three\nhidden fourth line')
        code, _ = self.invoke([disk.Usage(100, 75, 75)] * 2, worktrees=Mock(side_effect=error))
        self.assertEqual(code, 1)
        text = next((self.root / 'reports').glob('*.md')).read_text()
        self.assertIn('worktrees incomplete: Cannot read directory: /one', text)
        self.assertIn('Cannot read directory: /three', text)
        self.assertNotIn('hidden fourth line', text)
        self.assertNotIn('whole script must stay out', text)

    def test_report_escapes_tables_and_counts_only_proposals(self):
        self.entry.actions = [dict(tier='archive', path='/a|b', action='would archive and verify then remove', bytes=123, reason=''),
                              dict(tier='archive', path='/blocked', action='skip', bytes=456, reason='open\nfile')]
        self.assertEqual(self.entry.would_free, 123)
        self.assertNotIn('Google DriveFS', report.render([self.entry]))
        text = report.render([self.entry], manual_notes=['Review Google DriveFS offline files.'])
        self.assertIn('/a\\|b', text)
        self.assertIn('open file', text)
        self.assertIn('123 bytes', text)
        self.assertIn('Google DriveFS', text)

    def test_skips_are_counted_per_reason_with_only_the_largest_listed(self):
        self.entry.actions = [dict(tier='worktree', path=f'/skip{index}', action='skip', bytes=index, reason='recent' if index % 2 else 'open files')
                              for index in range(30)]
        actions = [dict(tier='archive', path=f'/action{index}',
                        action='would archive' if index % 2 else 'archived',
                        bytes=100 + index, reason='') for index in range(25)]
        self.entry.actions.extend(actions)
        text = report.render([self.entry])
        action_section, skipped_section = text.split('### Skipped: 30', 1)
        summary, largest = skipped_section.split('Largest 20 skipped:', 1)
        self.assertIn('| recent | 15 | 225 |', summary)
        self.assertIn('| open files | 15 | 210 |', summary)
        self.assertEqual(
            [line for line in action_section.splitlines() if line.startswith('| archive |')],
            [f"| archive | {row['action']} | /action{index} | {100 + index} |  |"
             for index, row in enumerate(actions)])
        self.assertNotIn('| worktree | skip |', action_section)
        self.assertEqual(
            [line for line in largest.splitlines() if line.startswith('| worktree |')],
            [f"| worktree | skip | /skip{index} | {index} | {'recent' if index % 2 else 'open files'} |"
             for index in range(29, 9, -1)])

    def test_find_and_restore_pass_through(self):
        store = Mock()
        store.find.return_value = [storage.Record(
            '123', 'when', 'h', '/source', 'h/d/source.tar.zst', 1, 1, 1, 'stored')]
        with patch.object(cli, 'store', store), patch.object(rules, 'load', return_value=self.config), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['find', 'needle']), 0)
            self.assertEqual(cli.main(['restore', '123', '--to', '/destination', '--member', 'file']), 0)
        store.find.assert_called_once_with('needle', self.config['nas_root'])
        store.restore.assert_called_once_with('123', self.config['nas_root'], to='/destination', member='file', to_host=None)

    def test_find_refuses_an_empty_search_term(self):
        store = Mock()
        with patch.object(cli, 'store', store), patch.object(rules, 'load', return_value=self.config), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(['find', '']), 2)
        self.assertEqual(output.getvalue(), 'coldcleaner: search term is empty\n')
        store.find.assert_not_called()

    def test_store_error_returns_error(self):
        with patch.object(storage, 'find', side_effect=ValueError('unexpected INDEX.csv columns')), \
             patch.object(rules, 'load', return_value=self.config), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(['find', 'needle']), 2)
        self.assertIn('unexpected INDEX.csv columns', output.getvalue())

    def test_status_last_report(self):
        saved = report.write([self.entry], self.config['report_dir'])
        output = io.StringIO()
        with patch.object(disk, 'measure', return_value=disk.Usage(100, 20, 20)), \
             patch.object(rules, 'load', return_value=self.config), contextlib.redirect_stdout(output):
            code = cli.main(['status', '--host', 'server-a', '--report-dir', self.config['report_dir']])
        self.assertEqual(code, 0)
        self.assertIn(str(saved), output.getvalue())

    def test_reclaim_real_entrypoint_with_fake_host(self):
        with patch.dict(hosts.HOSTS, {'test': self.host}), patch.object(disk, 'measure', return_value=disk.Usage(100, 20, 20)), \
             patch.object(rules, 'load', return_value=self.config), \
             patch.object(protect, 'collect', return_value=self.protection), contextlib.redirect_stdout(io.StringIO()), \
             patch.multiple(reclaim.Reclaimer, **{name: Mock() for name in TIERS}):
            code = cli.main(['reclaim', '--host', 'test', '--report-dir', self.config['report_dir']])
        self.assertEqual(code, 0)
        self.assertTrue(any((self.root / 'reports').glob('*.md')))


if __name__ == '__main__':
    unittest.main()
