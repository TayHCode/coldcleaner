import contextlib
import io
import json
import os
import re
import subprocess
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from coldcleaner import cli, disk, gitsafe, hosts, protect, report, rules, tiers
from coldcleaner import store as storage
from tests import outside_git

outside_git.use()


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
        self.config['live'] = ['cache', 'worktree', 'archive']
        self.config['nas_root'] = str(self.root / 'nas')
        self.config['report_dir'] = str(self.root / 'reports')
        self.config['hosts']['test'] = {'roots': [], 'cache': [], 'archive': []}
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

    def cleaner(self, apply=False, git=None, store=None):
        return tiers.Cleaner(self.host, self.config, apply, self.protection, self.entry,
                             gitsafe if git is None else git, storage if store is None else store)

    def candidate(self, name='cache', tier='cache', days=0):
        path = self.root / name
        path.mkdir()
        (path / 'data').write_text('payload')
        stamp = time.time() - 60
        os.utime(path / 'data', (stamp, stamp))
        os.utime(path, (stamp, stamp))
        return tiers.Candidate(str(path), 7, time.time() - 40 * 86400, tier, days=days)

    def state(self, path, verdict='on_github', worktree=False):
        return SimpleNamespace(path=str(path), verdict=verdict, is_worktree=worktree, dirty_files=[],
                               untracked_files=[], unpushed_branches=[], stash_count=0,
                               remote_url='git@github.com:owner/repo.git')

    def git(self, *args):
        stamp = f'{int(time.time()) - 3 * 86400} +0000'
        return subprocess.run(['git', *args], check=True, capture_output=True,
                              env={**os.environ, 'GIT_COMMITTER_DATE': stamp})

    def worktree_repo(self, *branches):
        repo = self.root / 'repo'
        self.git('init', '-b', 'main', str(repo))
        (repo / 'file').write_text('original')
        self.git('-C', str(repo), 'add', '.')
        self.git('-C', str(repo), '-c', 'user.name=Test', '-c', 'user.email=test@localhost', 'commit', '-m', 'init')
        paths = []
        for branch in branches:
            path = self.root / branch
            self.git('-C', str(repo), 'worktree', 'add', '-b', branch, str(path))
            paths.append(path)
        return repo, paths

    def age(self, *paths):
        stamp = time.time() - 2 * 86400
        for path in paths:
            for child in [*path.rglob('*'), path]:
                os.utime(child, (stamp, stamp))


class RulesTests(CoreCase):
    def test_cache_globs_cannot_disguise_temporary_directories(self):
        source = (Path(__file__).parent / 'fixtures' / 'rules.toml').read_text()
        for pattern in ('/t?p', '/t?p/*', '/[t]mp', '/*/tmp', '/var/t*', '/var/t*/child'):
            with self.subTest(path=pattern):
                path = self.root / 'rules.toml'
                path.write_text(source.replace('{ path = "/tmp", days = 7, owner = "alice" }',
                    '{ path = ' + json.dumps(pattern) + ' }'))
                with self.assertRaises(ValueError):
                    rules.load(path)

    def test_threshold_boundaries_and_order(self):
        daily = ('cache', 'github', 'worktree', 'archive', 'compact')
        self.assertEqual(rules.selected(0, self.config), daily)
        self.assertEqual(rules.selected(84.99, self.config), daily)
        self.assertEqual(rules.selected(85, self.config), rules.TIERS)

    def test_two_switches_required(self):
        self.config['live'] = []
        for apply in (False, True):
            self.assertFalse(rules.enabled(self.config, 'cache', apply))
        self.config['live'] = ['cache']
        self.assertFalse(rules.enabled(self.config, 'cache', False))
        self.assertTrue(rules.enabled(self.config, 'cache', True))
        self.assertFalse(rules.enabled(self.config, 'project', True))

    def test_regenerable_paths_reject_escape_and_globs(self):
        import re
        source = (Path(__file__).parent / 'fixtures/rules.toml').read_text()
        for invalid in ('../outside', '/outside', '.', 'local/*', 'local/../build'):
            with self.subTest(path=invalid):
                path = self.root / 'rules.toml'
                path.write_text(re.sub(r'^regenerable_paths = .*$', 'regenerable_paths = [' + json.dumps(invalid) + ']', source, flags=re.M))
                with self.assertRaisesRegex(ValueError, 'project-relative'):
                    rules.load(path)

    def test_invalid_rules_rejected(self):
        original = (Path(__file__).parent / 'fixtures/rules.toml').read_text()
        for old, new in [('hard_pct = 85', 'hard_pct = true'), ('hard_pct = 85', 'hard_pct = 0'),
                         ('live = ["worktree", "archive"]', 'live = ["oops"]'), ('compact_weekday = "sun"', 'compact_weekday = "sunday"'),
                         ('archive_idle_days = 4', 'archive_idle_days = -1'), ('days = 7', 'days = -1')]:
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
    def scheduler_inventory(self, root):
        walk = os.walk
        def unit_walk(path):
            return walk(root) if path == '/etc/systemd/system' else []
        output = io.StringIO()
        with patch('os.walk', side_effect=unit_walk), patch('glob.glob', return_value=[]), \
             patch('subprocess.run', return_value=SimpleNamespace(stdout='', stderr='', returncode=0)), \
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

    def test_dangling_systemd_unit_makes_inventory_incomplete(self):
        units = self.root / 'units'
        units.mkdir()
        (units / 'missing.service').symlink_to(self.root / 'absent.service')
        obj = self.scheduler_inventory(units)
        self.assertEqual(len(obj['errors']), 1)
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
        text = '[Service]\nWorkingDirectory=%h/projects/app\nExecStart=/usr/bin/python3 /home/alice/jobs/daily.py\n0 1 * * * ~/jobs/cleanup.sh'
        paths = protect.extract_paths(text, '/home/alice')
        self.assertTrue({'/home/alice/projects/app', '/usr/bin/python3', '/home/alice/jobs/daily.py', '/home/alice/jobs/cleanup.sh'} <= paths)

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
        paths = protect.extract_paths('<key>WorkingDirectory</key><string>/Users/alice/Library/Work App</string>', '/Users/alice')
        self.assertIn('/Users/alice/Library/Work App', paths)
        obj = json.dumps({'WorkingDirectory': '/Users/alice/Library/Work App', 'ProgramArguments': ['/usr/bin/python3', '/Users/alice/app.py']})
        self.assertIn('/Users/alice/Library/Work App', protect.extract_paths(obj, '/Users/alice'))

    def test_windows_tasks_expand_environment(self):
        text = json.dumps({'Execute': 'C:\\tools\\task.exe', 'WorkingDirectory': '%USERPROFILE%\\REPOS\\Task App'})
        paths = protect.extract_paths(text, 'C:\\Users\\alice', True, {'USERPROFILE': 'C:\\Users\\alice'})
        self.assertIn('C:\\tools\\task.exe', paths)
        self.assertIn('C:\\Users\\alice\\REPOS\\Task App', paths)

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
    signal.raise_signal(signal.SIGALRM)
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

    def test_git_data_in_cache_is_protected(self):
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
    def test_candidates_use_one_protection_call_per_tier(self):
        for tier in ('cache', 'archive', 'worktree', 'project', 'compact'):
            with self.subTest(tier=tier):
                items = [tiers.Candidate(str(self.root / f'{tier}-{i}'), 7, 1, tier) for i in range(4)]
                for item in items:
                    Path(item.path).mkdir()
                self.config['hosts']['test'].update(cache=[{'path': '*'}], archive=['*'], roots=[str(self.root)])
                self.config['compact_weekday'] = datetime.now(timezone.utc).strftime('%a').lower()
                cleaner = self.cleaner()
                cleaner.repos = [self.state(item.path, worktree=tier == 'worktree') for item in items]
                if tier == 'compact':
                    cleaner.host = hosts.Host('server-a', 'posix')
                    items = [tiers.replace(item, path=str(self.root / f'bin.1.0.{i}')) for i, item in enumerate(items)]
                    for item in items:
                        Path(item.path).mkdir()
                with patch.object(tiers, 'inventory', return_value=(items, [])), \
                     patch.object(gitsafe, 'worktree_check', return_value=gitsafe.WorktreeCheck(True, '', 0)), \
                     patch.object(cleaner, 'regenerable', return_value=[]), \
                     patch.object(hosts, 'run', wraps=hosts.run) as run:
                    getattr(cleaner, tier)()
                self.assertEqual(run.call_count, 1)
                self.assertEqual(sum(row['action'].startswith('would ') for row in self.entry.actions), 4)
                self.entry.actions.clear()

    def test_accounting_preserves_overlap_and_component_boundaries(self):
        for windows, paths in ((False, ['/app', '/app/data', '/apple']),
                               (False, ['/app/data', '/app', '/apple']),
                               (True, [r'C:\APP', r'c:\app\data', r'C:\apple']),
                               (True, [r'C:\App\data', r'c:\APP', r'C:\apple'])):
            with self.subTest(windows=windows, paths=paths):
                cleaner = self.cleaner()
                if windows:
                    cleaner.host = hosts.HOSTS['winhost']
                cleaner.checked = dict.fromkeys(paths, '')
                self.entry.actions.clear()
                for path in paths:
                    cleaner.act(tiers.Candidate(path, 7, 0, 'cache'), 'clean cache', Mock())
                self.assertEqual([row['bytes'] for row in self.entry.actions], [7, 0, 7])
                self.assertEqual(self.entry.would_free, 14)

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

    def test_batch_timeout_skips_every_unresolved_candidate(self):
        items = [self.candidate(f'cache-{i}') for i in range(3)]
        referenced = self.candidate('scheduled')
        self.protection.paths = {referenced.path}
        self.config['hosts']['test']['cache'] = [{'path': item.path} for item in [*items, referenced]]
        run = hosts.run
        def timeout(host, script, **kwargs):
            if kwargs.get('stdin_bytes') is not None and isinstance(json.loads(kwargs['stdin_bytes']), list):
                self.assertEqual(kwargs['timeout'], 900)
                raise subprocess.TimeoutExpired('protection', 900)
            return run(host, script, **kwargs)
        with patch.object(hosts, 'run', side_effect=timeout):
            self.cleaner().cache()
        reasons = {row['path']: row['reason'] for row in self.entry.actions}
        self.assertEqual({path: reasons[path] for path in [item.path for item in items]},
            {item.path: 'protection check timed out' for item in items})
        self.assertIn('scheduler references', reasons[referenced.path])
        self.assertEqual([row['action'] for row in self.entry.actions], ['skip'] * 4)
        self.assertEqual(self.entry.would_free, 0)

    def test_batch_excludes_recent_and_already_blocked_candidates(self):
        safe = self.candidate('eligible')
        blocked = tiers.replace(self.candidate('blocked'), blocked='not entirely owned by test')
        recent = tiers.replace(self.candidate('recent'), newest=time.time(), days=7)
        with patch.object(tiers, 'inventory', return_value=([safe, blocked, recent], [])), \
             patch.object(self.protection, 'batch', wraps=self.protection.batch) as batch:
            self.cleaner().cache()
        batch.assert_called_once_with([safe.path], allow_git=False)
        self.assertEqual([(row['action'], row['reason']) for row in self.entry.actions],
            [('would clean cache', ''), ('skip', 'not entirely owned by test'), ('skip', 'active within 7 days')])

    def test_candidates_aging_during_batch_are_retained_without_extra_calls(self):
        item = tiers.replace(self.candidate('aging'), newest=100000, days=7)
        clock = [item.newest + 7 * 86400 - 1]
        cleaner = self.cleaner()
        check_batch = cleaner.check_batch
        def advance(items):
            check_batch(items)
            clock[0] += 2
        with patch.object(tiers, 'inventory', return_value=([item], [])), \
             patch.object(tiers.time, 'time', side_effect=lambda: clock[0]), \
             patch.object(cleaner, 'check_batch', side_effect=advance), \
             patch.object(hosts, 'run') as run:
            cleaner.cache()
        run.assert_not_called()
        self.assertEqual(self.entry.actions[0]['action'], 'skip')
        self.assertEqual(self.entry.actions[0]['reason'], 'protection check incomplete: missing or invalid result')
        self.assertEqual((Path(item.path) / 'data').read_text(), 'payload')

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

    def test_live_operation_rechecks_after_batch(self):
        item = self.candidate()
        self.config['hosts']['test']['cache'] = [{'path': item.path}]
        self.config['live'] = ['cache']
        batch = self.protection.batch
        calls = []
        def check(paths, **kwargs):
            reasons = batch(paths, **kwargs)
            calls.append(paths)
            (Path(item.path) / '.keep-local').touch()
            self.age(Path(item.path))
            return reasons
        with patch.object(self.protection, 'batch', side_effect=check):
            self.cleaner(True).cache()
        self.assertEqual(calls, [[item.path], [item.path]])
        self.assertEqual(self.entry.actions[0]['reason'], '.keep-local')
        self.assertEqual((Path(item.path) / 'data').read_text(), 'payload')

    def test_file_opened_after_initial_batch_retains_live_candidate(self):
        item = self.candidate()
        self.config['hosts']['test']['cache'] = [{'path': item.path}]
        self.config['live'] = ['cache']
        batch = self.protection.batch
        calls = 0

        def open_after_check(paths, **kwargs):
            nonlocal calls
            reasons = batch(paths, **kwargs)
            calls += 1
            if calls == 1:
                self.lsof('opened')
            return reasons

        with patch.object(self.protection, 'batch', side_effect=open_after_check):
            self.cleaner(True).cache()
        self.assertEqual((Path(item.path) / 'data').read_text(), 'payload')
        self.assertEqual(self.entry.actions[0]['action'], 'skip')
        self.assertEqual(self.entry.actions[0]['reason'], 'open files')

    def test_later_tier_refreshes_scheduler_references(self):
        cache = self.candidate()
        archive = self.candidate('archive', tier='archive')
        self.config['hosts']['test'].update(cache=[{'path': cache.path}], archive=[archive.path])
        self.config['live'] = ['cache', 'archive']
        self.config['archive_idle_days'] = 0
        cleaner = self.cleaner(True)
        cleaner.cache()
        current = protect.Protection(self.host, str(self.root), {archive.path}, [])
        with patch.object(protect, 'collect', return_value=current):
            cleaner.archive()
        self.assertEqual(list(Path(cache.path).iterdir()), [])
        self.assertEqual((Path(archive.path) / 'data').read_text(), 'payload')
        self.assertEqual(self.entry.actions[-1]['action'], 'skip')
        self.assertIn('scheduler references', self.entry.actions[-1]['reason'])


class TierTests(CoreCase):
    def test_slow_inventory_entry_preserves_other_entries(self):
        slow = self.candidate('slow')
        fast = self.candidate('fast')
        earlier = self.candidate('earlier')
        original = disk.python
        def probe(host, source, **kwargs):
            config = json.loads(kwargs['stdin_bytes'])
            if config['cache'][0]['path'] == slow.path:
                raise TimeoutError('remote probe exceeded 900 seconds')
            return original(host, source, **kwargs)
        with patch.object(disk, 'python', side_effect=probe):
            items, errors = tiers.inventory(self.host,
                {'cache': [{'path': earlier.path}, {'path': slow.path}, {'path': fast.path}]})
        self.assertEqual([(item.path, item.bytes) for item in items], [(earlier.path, 7), (fast.path, 7)])
        self.assertEqual(errors, [{'path': slow.path, 'reason': 'remote probe exceeded 900 seconds'}])

    def test_newest_file_blocks_old_folder(self):
        item = self.candidate()
        os.utime(item.path, (1, 1))
        items, errors = tiers.inventory(self.host, {'archive': [{'path': item.path}]})
        self.assertEqual(errors, [])
        self.assertEqual(items[0].bytes, 7)
        self.assertFalse(tiers.idle(items[0], 14))

    def test_idle_boundary(self):
        item = tiers.Candidate('/x', 0, 100, 'archive')
        self.assertTrue(tiers.idle(item, 1, now=86500))
        self.assertFalse(tiers.idle(item, 1, now=86499))

    def test_git_metadata_ignored_but_last_commit_counts(self):
        item = self.candidate(tier='worktree')
        self.git('init', item.path)
        self.git('-C', item.path, 'add', 'data')
        self.git('-C', item.path, '-c', 'user.name=Test', '-c', 'user.email=test@localhost', 'commit', '-m', 'init')
        os.utime(Path(item.path) / 'data', (1, 1))
        os.utime(item.path, (1, 1))
        items, errors = tiers.inventory(self.host, {'worktree': [{'path': item.path}]})
        self.assertEqual(errors, [])
        self.assertFalse(tiers.idle(items[0], 7))

    def test_cache_dry_run_preserves_contents(self):
        item = self.candidate()
        self.config['hosts']['test']['cache'] = [{'path': item.path}]
        self.config['live'] = ['cache']
        self.cleaner().cache()
        self.assertEqual((Path(item.path) / 'data').read_text(), 'payload')
        self.assertEqual(self.entry.would_free, 7)
        self.assertEqual(self.entry.actions[0]['action'], 'would clean cache')

    def test_listed_cache_file_is_removed_only_in_live_apply(self):
        path = self.root / 'cache-file'
        path.write_text('cached')
        self.config['hosts']['test']['cache'] = [{'path': str(path)}]
        self.config['live'] = ['cache']
        self.cleaner().cache()
        self.assertEqual(path.read_text(), 'cached')
        self.cleaner(True).cache()
        self.assertFalse(path.exists())

    def test_cache_command_is_bound_to_candidate_path(self):
        import shlex
        item = self.candidate(name='cache with spaces')
        receipt = self.root / 'command-receipt'
        tool = self.bin / 'cache-tool'
        tool.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > ' + shlex.quote(str(receipt)) + '\n')
        tool.chmod(0o755)
        self.config['hosts']['test']['cache'] = [{'path': item.path, 'command': 'cache-tool --cache-dir {path}'}]
        self.config['live'] = ['cache']
        self.cleaner().cache()
        self.assertFalse(receipt.exists())
        self.cleaner(True).cache()
        self.assertEqual(receipt.read_text(), '--cache-dir\n' + item.path + '\n')

    def test_apply_without_live_preserves_contents(self):
        item = self.candidate()
        self.config['live'] = []
        self.config['hosts']['test']['cache'] = [{'path': item.path}]
        self.cleaner(True).cache()
        self.assertTrue((Path(item.path) / 'data').exists())

    def test_live_apply_cleans_contents_and_preserves_root(self):
        item = self.candidate()
        self.config['hosts']['test']['cache'] = [{'path': item.path}]
        self.config['live'] = ['cache']
        self.cleaner(True).cache()
        self.assertTrue(Path(item.path).is_dir())
        self.assertEqual(list(Path(item.path).iterdir()), [])
        self.assertEqual(self.entry.actions[0]['action'], 'clean cache')

    def test_protection_blocks_live_cache(self):
        item = self.candidate()
        (Path(item.path) / '.keep-local').touch()
        self.config['hosts']['test']['cache'] = [{'path': item.path}]
        self.config['live'] = ['cache']
        self.cleaner(True).cache()
        self.assertTrue((Path(item.path) / 'data').exists())
        self.assertEqual(self.entry.would_free, 0)
        self.assertEqual(self.entry.actions[0]['reason'], '.keep-local')

    def test_protection_timeout_retains_candidate_and_reports_reason(self):
        item = self.candidate()
        self.config['hosts']['test']['cache'] = [{'path': item.path}]
        self.config['live'] = ['cache']
        batch = self.protection.batch
        calls = 0
        def check(paths, *, open_files=True, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise TimeoutError('remote probe exceeded 60 seconds')
            return batch(paths, open_files=open_files, **kwargs)
        with patch.object(self.protection, 'batch', side_effect=check):
            self.cleaner(True).cache()
        self.assertEqual((Path(item.path) / 'data').read_text(), 'payload')
        self.assertEqual(self.entry.actions[0]['reason'], 'protection check incomplete: remote probe exceeded 60 seconds')
        self.assertEqual(self.entry.would_free, 0)

    def test_temp_only_old_entries(self):
        item = self.candidate()
        old = Path(item.path) / 'old'
        old.write_text('old')
        os.utime(old, (1, 1))
        self.config['hosts']['test']['cache'] = [{'path': item.path, 'days': 7}]
        self.config['live'] = ['cache']
        self.cleaner(True).cache()
        self.assertFalse(old.exists())
        self.assertTrue((Path(item.path) / 'data').exists())

    def test_live_temp_sweep_cost_is_flat_in_entry_count(self):
        item = self.candidate()
        old = [Path(item.path) / f'old{index}' for index in range(40)]
        for path in old:
            path.write_text('old')
            os.utime(path, (1, 1))
        log = self.root / 'lsof.log'
        command = self.bin / 'lsof'
        command.write_text('#!/bin/sh\necho run >> "$LSOF_LOG"\nexit 1\n')
        self.config['hosts']['test']['cache'] = [{'path': item.path, 'days': 7}]
        self.config['live'] = ['cache']
        with patch.dict(os.environ, {'LSOF_LOG': str(log)}), \
             patch.object(tiers, 'inventory_entry', wraps=tiers.inventory_entry) as inventory, \
             patch.object(hosts, 'run', wraps=hosts.run) as run:
            self.cleaner(True).cache()
        self.assertEqual([path for path in old if path.exists()], [])
        self.assertTrue((Path(item.path) / 'data').exists())
        self.assertEqual(log.read_text().splitlines(), ['run', 'run'])
        self.assertEqual(inventory.call_count, 2)
        self.assertLessEqual(run.call_count, 6)
        self.assertEqual(len([action for action in self.entry.actions if action['action'] == 'clean cache']), 40)

    def test_cache_sweep_records_only_removed_paths_when_one_removal_fails(self):
        item = self.candidate()
        stuck, gone = Path(item.path) / 'stuck', Path(item.path) / 'gone'
        for path in (stuck, gone):
            path.write_text('old')
            os.utime(path, (1, 1))
        rm = self.bin / 'rm'
        rm.write_text('#!/bin/sh\nstatus=0\nfor arg in "$@"; do\n'
                      'case "$arg" in -*) continue;; */stuck) status=1;; *) /bin/rm -rf -- "$arg";; esac\n'
                      'done\nexit $status\n')
        rm.chmod(0o755)
        self.config['hosts']['test']['cache'] = [{'path': item.path, 'days': 7}]
        self.config['live'] = ['cache']
        with self.assertRaises(subprocess.CalledProcessError):
            self.cleaner(True).cache()
        self.assertTrue(stuck.exists())
        self.assertFalse(gone.exists())
        self.assertEqual([row['path'] for row in self.entry.actions if row['action'] == 'clean cache'], [str(gone)])

    def candidates_in_tmp(self, count):
        return [tiers.Candidate(f'/tmp/cc-{index}', 1, 1, 'cache', days=7) for index in range(count)]

    def test_thousands_of_tmp_candidates_use_one_dry_run_protection_batch(self):
        items = self.candidates_in_tmp(6801)
        with patch.object(tiers, 'inventory', return_value=(items, [])), \
             patch.object(self.protection, 'batch', side_effect=lambda paths, **kwargs: dict.fromkeys(paths, '')) as batch, \
             patch.object(hosts, 'run') as run:
            self.cleaner().cache()
        batch.assert_called_once()
        self.assertEqual(len(batch.call_args.args[0]), 6801)
        run.assert_not_called()
        self.assertEqual(len(self.entry.actions), 6801)

    def test_thousands_of_tmp_candidates_use_one_live_sweep(self):
        items = self.candidates_in_tmp(6801)
        self.config['live'] = ['cache']
        with patch.object(tiers, 'inventory', return_value=(items, [])), \
             patch.object(tiers, 'inventory_entry', return_value=(items, [])) as inventory, \
             patch.object(tiers.Cleaner, 'in_use', return_value=set()) as in_use, \
             patch.object(self.protection, 'batch', side_effect=lambda paths, **kwargs: dict.fromkeys(paths, '')) as batch, \
             patch.object(hosts, 'run') as run:
            self.cleaner(True).cache()
        self.assertEqual(batch.call_count, 2)
        self.assertEqual(inventory.call_count, 1)
        in_use.assert_called_once()
        run.assert_called_once()
        self.assertEqual(len(self.entry.actions), 6801)

    def test_candidate_recently_modified_is_retained(self):
        item = self.candidate(days=7)
        cleaner = self.cleaner(True)
        self.config['live'] = ['cache']
        operation = Mock()
        cleaner.act(item, 'delete old cache entry', operation)
        self.assertTrue((Path(item.path) / 'data').exists())
        self.assertEqual(self.entry.actions[0]['reason'], 'candidate changed or could not be revalidated')
        operation.assert_not_called()

    def test_temp_ownership_is_checked_for_every_descendant(self):
        import pwd
        item = self.candidate()
        owner = next(entry.pw_name for entry in pwd.getpwall() if entry.pw_uid != os.getuid())
        items, errors = tiers.inventory(self.host, {'cache': [{'path': item.path, 'owner': owner}]})
        self.assertEqual(errors, [])
        self.assertEqual(items[0].blocked, 'not entirely owned by ' + owner)
        self.assertNotEqual(pwd.getpwnam(owner).pw_uid, os.getuid())

    def test_runner_busy_prevents_live_cleanup(self):
        item = self.candidate()
        self.config['hosts']['test']['cache'] = [{'path': item.path, 'runner': True}]
        self.config['live'] = ['cache']
        with patch.object(tiers, 'runner_busy', return_value=True):
            self.cleaner(True).cache()
        self.assertTrue((Path(item.path) / 'data').exists())
        self.assertIn('Runner.Worker', self.entry.actions[0]['reason'])

    def test_backup_requires_github_live_and_reinspects_after_apply(self):
        item = self.candidate()
        state = self.state(item.path, 'backup_needed')
        git = Mock()
        git.find_repos.return_value = [item.path]
        git.inspect.side_effect = [state, self.state(item.path)]
        git.backup.return_value = ['pushed backup']
        self.config['live'] = ['github']
        self.cleaner(True, git).github()
        git.backup.assert_called_once_with(self.host, item.path, apply=True)
        self.assertEqual(git.inspect.call_count, 2)
        self.assertEqual(self.entry.repos[0].verdict, 'on_github')

    def test_backup_dry_does_not_reinspect(self):
        git = Mock()
        git.find_repos.return_value = ['/repo']
        git.inspect.return_value = self.state('/repo', 'backup_needed')
        git.backup.return_value = []
        self.cleaner(True, git).github()
        git.backup.assert_called_once_with(self.host, '/repo', apply=False)
        self.assertEqual(git.inspect.call_count, 1)

    def test_git_discovery_error_is_not_silently_ignored(self):
        with patch.object(gitsafe, 'find_repos', side_effect=RuntimeError('discovery failed')):
            with self.assertRaisesRegex(RuntimeError, 'discovery failed'):
                self.cleaner().github()

    def test_unsafe_worktree_reported_without_removal(self):
        self.config['hosts']['test']['roots'] = ['/repo']
        git = Mock()
        git.worktree_check.return_value = gitsafe.WorktreeCheck(True, '', 0)
        cleaner = self.cleaner(True, git)
        cleaner.repos = [self.state('/repo', 'backup_needed', True)]
        with patch.object(hosts, 'run') as run:
            cleaner.worktree()
        run.assert_not_called()
        self.assertIn('needs attention', self.entry.actions[0]['reason'])

    def worktree_cleaner(self, paths, check, verdict='backup_needed', newest=None):
        self.config['hosts']['test']['roots'] = [str(self.root)]
        self.config['live'] = ['worktree']
        git = Mock()
        git.inspect.side_effect = lambda host, path: self.state(path, verdict, True)
        git.worktree_check.return_value = check
        cleaner = self.cleaner(True, git)
        cleaner.repos = [self.state(path, verdict, True) for path in paths]
        newest = time.time() - 2 * 86400 if newest is None else newest
        items = [tiers.Candidate(str(path), 7, newest, 'worktree') for path in paths]
        return cleaner, patch.object(tiers, 'inventory', return_value=(items, []))

    def test_squash_merged_worktree_removed_after_one_day_and_branch_kept(self):
        repo, (worktree,) = self.worktree_repo('squashed')
        (worktree / 'file').write_text('feature')
        self.git('-C', str(worktree), '-c', 'user.name=Test', '-c', 'user.email=test@localhost', 'commit', '-am', 'feature')
        self.git('-C', str(repo), 'remote', 'add', 'origin', str(self.root / 'unused-remote'))
        self.git('-C', str(repo), 'update-ref', 'refs/remotes/origin/squashed', 'squashed')
        self.git('-C', str(repo), 'branch', '--set-upstream-to=origin/squashed', 'squashed')
        self.age(worktree)
        cleaner, inventory = self.worktree_cleaner([worktree], gitsafe.WorktreeCheck(True, 'squash', 0))
        with inventory:
            cleaner.worktree()
        self.assertFalse(worktree.exists())
        self.assertEqual(self.entry.actions[-1]['action'], 'remove worktree')
        self.assertNotEqual(self.git('-C', str(repo), 'branch', '--list', 'squashed').stdout, b'')

    def test_unmerged_worktree_needs_seven_idle_days_on_github(self):
        repo, (worktree,) = self.worktree_repo('pushed')
        cleaner, inventory = self.worktree_cleaner([worktree], gitsafe.WorktreeCheck(True, '', 0), 'on_github')
        with inventory:
            cleaner.worktree()
        self.assertTrue(worktree.exists())
        self.assertEqual(self.entry.actions[-1]['reason'], 'recent worktree activity')

    def test_worktree_with_large_ignored_files_is_skipped(self):
        repo, (worktree,) = self.worktree_repo('ignored')
        cleaner, inventory = self.worktree_cleaner([worktree], gitsafe.WorktreeCheck(True, 'ancestor', 5000))
        with inventory, patch.object(hosts, 'run') as run:
            cleaner.worktree()
        run.assert_not_called()
        self.assertTrue(worktree.exists())
        self.assertEqual(self.entry.actions[-1]['action'], 'skip')
        self.assertIn('ignored files over 1024 KB', self.entry.actions[-1]['reason'])

    def test_worktree_failure_is_logged_and_next_worktree_removed(self):
        repo, (first, second) = self.worktree_repo('first', 'second')
        (first / 'file').write_text('uncommitted')
        self.age(first, second)
        cleaner, inventory = self.worktree_cleaner([first, second], gitsafe.WorktreeCheck(True, 'ancestor', 0))
        with inventory:
            cleaner.worktree()
        self.assertEqual((first / 'file').read_text(), 'uncommitted')
        self.assertFalse(second.exists())
        actions = {row['path']: row for row in self.entry.actions}
        self.assertEqual(actions[str(first)]['action'], 'error')
        self.assertIn('contains modified or untracked files', actions[str(first)]['reason'])
        self.assertEqual(actions[str(second)]['action'], 'remove worktree')

    def test_worktree_removal_uses_nonforce_and_deletes_merged_branch(self):
        repo, (worktree,) = self.worktree_repo('merged')
        cleaner, _ = self.worktree_cleaner([worktree], gitsafe.WorktreeCheck(True, 'ancestor', 0), 'on_github')
        cleaner.remove_worktree(tiers.Candidate(str(worktree), 0, 0, 'worktree', days=1))
        self.assertFalse(worktree.exists())
        self.assertEqual(self.git('-C', str(repo), 'branch', '--list', 'merged').stdout, b'')

    def test_small_ignored_files_retain_worktree(self):
        repo, (worktree,) = self.worktree_repo('ignored')
        cleaner, inventory = self.worktree_cleaner([worktree], gitsafe.WorktreeCheck(True, 'squash', 4))
        with inventory:
            cleaner.worktree()
        self.assertTrue(worktree.is_dir())
        self.assertEqual(self.entry.actions[-1]['reason'], 'ignored files require a verified archive; retained')

    def test_worktree_no_longer_merged_is_retained(self):
        repo, (worktree,) = self.worktree_repo('moved')
        cleaner, _ = self.worktree_cleaner([worktree], gitsafe.WorktreeCheck(True, '', 0), 'on_github')
        with self.assertRaisesRegex(RuntimeError, 'no longer merged'):
            cleaner.remove_worktree(tiers.Candidate(str(worktree), 0, 0, 'worktree', days=1))
        self.assertTrue(worktree.exists())

    def test_archive_live_delegates_to_store_after_protection(self):
        item = self.candidate(tier='archive')
        os.utime(Path(item.path) / 'data', (1, 1))
        os.utime(item.path, (1, 1))
        self.config['hosts']['test']['archive'] = [item.path]
        self.config['live'] = ['archive']
        store = Mock()
        store.compression_level.return_value = 10
        self.cleaner(True, store=store).archive()
        store.archive.assert_called_once_with(self.host, item.path, apply=True, nas_root=self.config['nas_root'], level=10)

    def test_archive_retains_open_paths_with_lsof_escaped_names(self):
        names = [('ordinary', b'ordinary'),
                 ('back\\slash', b'back\\\\slash'),
                 ('literal\\n', b'literal\\\\n'),
                 ('raw\\n', b'raw\\n'),
                 ('mixed\\n-\n', b'mixed\\n-\\n'),
                 ('raw\\xword', b'raw\\xword'),
                 ('slash-control-' + chr(92) + chr(10), b'slash-control-' + bytes([92, 92, 110])),
                 ('line\nbreak', b'line\\nbreak'),
                 ('control-\x01', b'control-^A'),
                 ('literal-^A', b'literal-^A'),
                 ('mixed-\x01-^B', b'mixed-^A-^B'),
                 ('delete-\x7f', b'delete-\\x7f'),
                 ('unicode-雪', b'unicode-\\xe9\\x9b\\xaa')]
        opened = [self.candidate(name, tier='archive') for name, _ in names]
        closed = self.candidate('closed', tier='archive')
        for item in [*opened, closed]:
            for path in [Path(item.path) / 'data', Path(item.path)]:
                os.utime(path, (1, 1))
        output = b'p123\n' + b''.join(
            b'n' + os.fsencode(str(self.root)) + b'/' + escaped + b'/data\n'
            for _, escaped in names) + b'n/tmp/unrelated-trailing-backslash' + bytes([92, 10])
        command = self.bin / 'lsof'
        command.write_text('#!/usr/bin/env python3\nimport sys\nsys.stdout.buffer.write(' + repr(output) + ')\n')
        self.config['hosts']['test']['archive'] = [item.path for item in [*opened, closed]]
        self.config['live'] = ['archive']

        self.cleaner(True).archive()

        self.assertEqual([(row['path'], row['action'], row['reason']) for row in self.entry.actions],
                         [(item.path, 'skip', 'open files') for item in opened] +
                         [(closed.path, 'archive and verify then remove', '')])
        for item in opened:
            self.assertEqual((Path(item.path) / 'data').read_text(), 'payload')
        self.assertFalse(Path(closed.path).exists())
        self.assertEqual([record.source_path for record in storage.find('', self.config['nas_root'])],
                         [closed.path])

    def test_recent_archive_not_called(self):
        item = self.candidate(tier='archive')
        self.config['hosts']['test']['archive'] = [item.path]
        store = Mock()
        self.cleaner(True, store=store).archive()
        store.archive.assert_not_called()
        self.assertEqual(self.entry.actions[0]['reason'], 'recent archive activity')

    def test_project_refuses_unproven_repo(self):
        projects = self.root / 'projects'
        projects.mkdir()
        project = projects / 'app'
        project.mkdir()
        os.utime(project, (1, 1))
        self.config['hosts']['test']['roots'] = [str(projects)]
        cleaner = self.cleaner(True)
        cleaner.project()
        self.assertTrue(project.exists())
        self.assertIn('unproven', self.entry.actions[0]['reason'])

    def test_project_archives_whole_folder_after_removing_regenerable(self):
        project = self.root / 'project'
        self.git('init', str(project))
        (project / '.gitignore').write_text('evidence.txt\nnode_modules/\n')
        (project / 'evidence.txt').write_text('precious')
        (project / 'node_modules').mkdir()
        (project / 'node_modules' / 'package').write_text('regenerable')
        git = Mock()
        git.inspect.return_value = self.state(project)
        store = Mock(wraps=storage)
        self.cleaner(True, git, store).remove_project(tiers.Candidate(str(project), 0, 0, 'project'))
        self.assertFalse(project.exists())
        store.archive.assert_called_once_with(self.host, str(project), apply=True, nas_root=self.config['nas_root'], level=10)
        self.assertEqual(len(storage.find('evidence.txt', self.config['nas_root'])), 1)
        self.assertEqual(storage.find('node_modules/package', self.config['nas_root']), [])

    def test_nested_build_evidence_is_archived_before_project_removal(self):
        project = self.root / 'project'
        self.git('init', str(project))
        (project / '.gitignore').write_text('local/\n')
        evidence = project / 'local/build/evidence.json'
        evidence.parent.mkdir(parents=True)
        evidence.write_text('{"result":"unique"}')
        git = Mock()
        git.inspect.return_value = self.state(project)
        store = Mock(wraps=storage)
        self.cleaner(True, git, store).remove_project(tiers.Candidate(str(project), 0, 0, 'project'))
        self.assertFalse(project.exists())
        record = storage.find('evidence.json', self.config['nas_root'])[0]
        saved = self.root / 'restored'
        storage.restore(record.id, self.config['nas_root'], to=str(saved))
        self.assertEqual((saved / 'local/build/evidence.json').read_text(), '{"result":"unique"}')

    def test_failed_ignored_archive_retains_project(self):
        project = self.root / 'project'
        self.git('init', str(project))
        (project / '.gitignore').write_text('evidence.txt\n')
        (project / 'evidence.txt').write_text('precious')
        git = Mock()
        git.inspect.return_value = self.state(project)
        store = Mock()
        store.archive.return_value = None
        with self.assertRaisesRegex(RuntimeError, 'not verified'):
            self.cleaner(True, git, store).remove_project(tiers.Candidate(str(project), 0, 0, 'project'))
        self.assertTrue(project.exists())

    def test_compact_respects_weekday(self):
        today = datetime.now(timezone.utc).strftime('%a').lower()
        self.config['compact_weekday'] = 'mon' if today != 'mon' else 'tue'
        with patch.object(hosts, 'run') as run:
            self.cleaner(True).compact()
        run.assert_not_called()
        self.assertIn('weekly', self.entry.actions[0]['reason'])

    def test_wsl_running_prevents_compaction(self):
        cleaner = self.cleaner(True)
        cleaner.host = hosts.HOSTS['winhost']
        cleaner.host_rules = {'compact': ['%LOCALAPPDATA%\\wsl\\*\\ext4.vhdx']}
        with patch.object(hosts, 'run', return_value=SimpleNamespace(stdout=b'{"running":["Ubuntu"],"files":["C:\\\\wsl\\\\ext4.vhdx"]}')) as run:
            cleaner.compact_wsl()
        self.assertEqual(run.call_count, 1)
        self.assertIn('running', self.entry.actions[0]['reason'])

class CliReportTests(CoreCase):
    def test_default_run_skips_retired_wsl_execution_and_keeps_pressure_alerts(self):
        retired = hosts.Host('winhost-wsl', 'wsl', 'bridge.example.invalid')

        def collect(host):
            if host.kind == 'wsl':
                raise ValueError('Windows WSL execution is retired')
            return self.protection

        for apply in (False, True):
            for percent in (20, 80):
                def measure(host):
                    used = percent if host.kind == 'wsl' else 20
                    return disk.Usage(100, used, used)

                with self.subTest(apply=apply, percent=percent), \
                     patch.dict(hosts.HOSTS, {'test': self.host, retired.name: retired}, clear=True), \
                     patch.object(rules, 'load', return_value=self.config), \
                     patch.object(disk, 'measure', side_effect=measure) as measured, \
                     patch.object(protect, 'collect', side_effect=collect) as protection, \
                     patch.object(tiers, 'Cleaner') as cleaner, \
                     patch.object(storage, 'enforce_cap', return_value=[]), \
                     contextlib.redirect_stdout(io.StringIO()):
                    code = cli.main(['run'] + (['--apply'] if apply else []))
                if apply:
                    self.assertEqual(code, 2)
                    measured.assert_not_called(); protection.assert_not_called(); cleaner.assert_not_called()
                    continue
                self.assertEqual(code, int(percent >= 80))
                protection.assert_called_once_with(self.host)
                self.assertEqual(cleaner.call_count, 1)
                self.assertEqual([call.args[0] for call in measured.call_args_list],
                                 [self.host, self.host, retired, retired])
        text = sorted((self.root / 'reports').glob('*.md'))[-1].read_text()
        self.assertIn('## winhost-wsl', text)
        self.assertIn('Before: 80.00%', text)
        self.assertIn('After: 80.00%', text)
        self.assertIn('Windows WSL execution is retired', text)
        self.assertNotIn('Protection inventory unavailable', text)

    def test_default_github_skips_retired_wsl_without_execution_or_measurement(self):
        retired = hosts.Host('winhost-wsl', 'wsl', 'bridge.example.invalid')
        with patch.dict(hosts.HOSTS, {'test': self.host, retired.name: retired}, clear=True), \
             patch.object(rules, 'load', return_value=self.config), \
             patch.object(disk, 'measure') as measure, \
             patch.object(protect, 'collect') as protection, \
             patch.object(tiers, 'Cleaner') as cleaner, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(['github'])
        self.assertEqual(code, 0)
        measure.assert_not_called()
        protection.assert_not_called()
        self.assertEqual(cleaner.call_count, 1)
        self.assertIn('Windows WSL execution is retired', output.getvalue())

    def scheduler_refresh_run(self, apply, live, refreshed):
        items = [self.candidate(name) for name in ('refresh-one', 'refresh-two')]
        self.config['hosts']['test']['cache'] = [{'path': item.path} for item in items]
        self.config['live'] = live
        with patch.object(disk, 'measure', return_value=disk.Usage(100, 75, 75)), \
             patch.object(gitsafe, 'find_repos', return_value=[]), \
             patch.object(tiers, 'remove') as remove, \
             patch.object(protect, 'collect', side_effect=[self.protection, refreshed]) as collect, \
             patch.object(self.protection, 'batch', wraps=self.protection.batch) as batch, \
             contextlib.redirect_stdout(io.StringIO()):
            cli.run(self.config, [self.host], apply)
        return items, collect.call_count, remove.call_count, batch.call_count

    def test_live_scheduler_refresh_sees_new_reference_once(self):
        refreshed = protect.Protection(self.host, str(self.root),
            {str(self.root / name) for name in ('refresh-one', 'refresh-two')}, [])
        items, collections, removals, batches = self.scheduler_refresh_run(True, ['cache'], refreshed)
        self.assertEqual((collections, removals, batches), (2, 0, 1))
        for item in items:
            self.assertEqual((Path(item.path) / 'data').read_text(), 'payload')
        text = next((self.root / 'reports').glob('*.md')).read_text()
        self.assertEqual(len(re.findall(r'\| cache \| skip \| .* \| scheduler references ', text)), 2)

    def test_live_scheduler_refresh_failure_retains_all_candidates(self):
        for refreshed in (RuntimeError('refresh failed'),
                          protect.Protection(self.host, str(self.root), set(), ['refresh failed'])):
            with self.subTest(refreshed=refreshed), tempfile.TemporaryDirectory() as directory:
                self.root = Path(directory)
                self.config['report_dir'] = str(self.root / 'reports')
                items, collections, removals, _ = self.scheduler_refresh_run(True, ['cache'], refreshed)
                self.assertEqual((collections, removals), (2, 0))
                for item in items:
                    self.assertEqual((Path(item.path) / 'data').read_text(), 'payload')
                text = next((self.root / 'reports').glob('*.md')).read_text()
                self.assertEqual(len(re.findall(r'\| cache \| skip \| .* \| .*refresh failed', text)), 2)

    def test_live_scheduler_refresh_is_reused_for_multiple_actions(self):
        refreshed = protect.Protection(self.host, str(self.root), set(), [])
        _, collections, removals, batches = self.scheduler_refresh_run(True, ['cache'], refreshed)
        self.assertEqual((collections, removals, batches), (2, 2, 1))

    def test_dry_run_and_disabled_live_tiers_do_not_refresh_schedulers(self):
        for apply, live in ((False, ['cache']), (True, [])):
            with self.subTest(apply=apply), tempfile.TemporaryDirectory() as directory:
                self.root = Path(directory)
                self.config['report_dir'] = str(self.root / 'reports')
                _, collections, removals, batches = self.scheduler_refresh_run(apply, live, RuntimeError('must not refresh'))
                self.assertEqual((collections, removals, batches), (1, 0, 1))

    def test_worktree_check_failure_returns_failure(self):
        self.config['hosts']['test']['roots'] = [str(self.root)]
        path = str(self.root / 'worktree')
        with patch.object(disk, 'measure', return_value=disk.Usage(100, 75, 75)), \
             patch.object(gitsafe, 'find_repos', return_value=[path]), \
             patch.object(gitsafe, 'inspect', return_value=self.state(path, worktree=True)), \
             patch.object(gitsafe, 'summary', return_value=''), \
             patch.object(gitsafe, 'worktree_check', side_effect=TimeoutError('remote timeout')), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.run(self.config, [self.host]), 1)
        text = next((self.root / 'reports').glob('*.md')).read_text()
        self.assertIn('worktree check failed: remote timeout', text)

    def test_unreadable_discovery_returns_failure_and_reports_path(self):
        def discover(host, roots, unreadable):
            unreadable.append('/unreadable')
            return []

        with patch.object(gitsafe, 'find_repos', side_effect=discover), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.run(self.config, [self.host], github_only=True), 1)
        self.assertIn('Git discovery incomplete: cannot read directory /unreadable', output.getvalue())

    def test_action_error_returns_failure_and_continues(self):
        items = [self.candidate(name) for name in ('one', 'two')]
        self.config['hosts']['test']['cache'] = [{'path': item.path, 'contents': True} for item in items]
        with patch.object(disk, 'measure', return_value=disk.Usage(100, 75, 75)), \
             patch.object(gitsafe, 'find_repos', return_value=[]), \
             patch.object(tiers, 'remove', side_effect=[RuntimeError('cleanup failed'), None]) as remove, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.run(self.config, [self.host], apply=True), 1)
        self.assertEqual(remove.call_count, 2)
        text = next((self.root / 'reports').glob('*.md')).read_text()
        self.assertIn('cleanup failed', text)
        self.assertIn('clean cache', text)

    def test_github_failure_reports_only_three_stderr_lines(self):
        error = subprocess.CalledProcessError(1, ['bash', '-c', 'whole script must stay out'],
            stderr=b'Cannot read directory: /one\nCannot read directory: /two\nCannot read directory: /three\nhidden fourth line')
        with patch.object(disk, 'measure', return_value=disk.Usage(100, 75, 75)), \
             patch.object(protect, 'collect', return_value=self.protection), \
             patch.object(gitsafe, 'find_repos', side_effect=error), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.run(self.config, [self.host]), 1)
        text = next((self.root / 'reports').glob('*.md')).read_text()
        self.assertIn('github incomplete: Cannot read directory: /one', text)
        self.assertIn('Cannot read directory: /three', text)
        self.assertNotIn('hidden fourth line', text)
        self.assertNotIn('whole script must stay out', text)

    def invoke(self, usages, host_list=None, apply=False):
        output = io.StringIO()
        with patch.object(disk, 'measure', side_effect=usages), \
             patch.object(protect, 'collect', return_value=self.protection), \
             patch.object(gitsafe, 'find_repos', return_value=[]), contextlib.redirect_stdout(output):
            code = cli.run(self.config, host_list or [self.host], apply)
        return code, output.getvalue()

    def test_progress_line_per_tier_start_and_done(self):
        _, output = self.invoke([disk.Usage(100, 20, 20), disk.Usage(100, 20, 20)])
        lines = output.splitlines()
        for tier in ('cache', 'github', 'worktree', 'archive', 'compact'):
            start = lines.index(f'test: {tier} start')
            self.assertRegex(lines[start + 1], rf'^test: {tier} done, \d+ items, \d+s$')

    def test_exit_alert_after_run(self):
        code, _ = self.invoke([disk.Usage(100, 90, 90), disk.Usage(100, 80, 80)])
        self.assertEqual(code, 1)
        path = next((self.root / 'reports').glob('*.md'))
        text = path.read_text()
        self.assertIn('Before: 90.00%', text)
        self.assertIn('After: 80.00%', text)
        self.assertNotIn('incomplete', text)

    def test_low_disk_runs_daily_tiers_but_not_project(self):
        called = []
        with patch.multiple(tiers.Cleaner, **{tier: lambda self, tier=tier: called.append(tier) for tier in rules.TIERS}):
            code, _ = self.invoke([disk.Usage(100, 1, 1)] * 2)
        self.assertEqual(code, 0)
        self.assertEqual(called, ['cache', 'github', 'worktree', 'archive', 'compact'])

    def test_unreachable_host_does_not_stop_next_host(self):
        second = hosts.Host('second', 'posix')
        code, output = self.invoke([OSError('offline'), disk.Usage(100, 20, 20), disk.Usage(100, 20, 20)], [self.host, second])
        self.assertEqual(code, 1)
        self.assertIn('second: 20.00%', output)
        text = next((self.root / 'reports').glob('*.md')).read_text()
        self.assertIn('offline', text)
        self.assertIn('## second', text)

    def test_tier_error_does_not_abort_other_tiers_or_measurement(self):
        with patch.object(tiers.Cleaner, 'cache', side_effect=RuntimeError('cache error')), patch.object(tiers.Cleaner, 'worktree') as worktree:
            code, _ = self.invoke([disk.Usage(100, 75, 75)] * 2)
        self.assertEqual(code, 1)
        worktree.assert_called_once()
        self.assertIn('cache error', next((self.root / 'reports').glob('*.md')).read_text())

    def test_report_escapes_tables_and_counts_only_proposals(self):
        self.entry.actions = [dict(tier='cache', path='/a|b', action='would clean cache', bytes=123, reason=''),
                              dict(tier='archive', path='/blocked', action='skip', bytes=456, reason='open\nfile')]
        self.assertEqual(self.entry.would_free, 123)
        text = report.render([self.entry])
        self.assertIn('/a\\|b', text)
        self.assertIn('open file', text)
        self.assertIn('123 bytes', text)
        self.assertIn('Google DriveFS', text)

    def test_skips_are_counted_per_reason_with_only_the_largest_listed(self):
        self.entry.actions = [dict(tier='cache', path=f'/skip{index}', action='skip', bytes=index, reason='recent' if index % 2 else 'open files')
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
        self.assertNotIn('| cache | skip |', action_section)
        self.assertEqual(
            [line for line in largest.splitlines() if line.startswith('| cache |')],
            [f"| cache | skip | /skip{index} | {index} | {'recent' if index % 2 else 'open files'} |"
             for index in range(29, 9, -1)])

    def test_not_on_github_table(self):
        self.entry.repos = [self.state('/repo', 'backup_needed')]
        self.assertIn('| /repo | backup_needed | 0 | 0 | 0 | 0 |', report.render([self.entry]))

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

    def test_github_only_does_not_depend_on_disk_measurement(self):
        git = Mock()
        git.find_repos.return_value = ['/repo']
        git.inspect.return_value = self.state('/repo')
        git.summary.return_value = 'all on GitHub'
        output = io.StringIO()
        with patch.object(cli, 'gitsafe', git), patch.object(disk, 'measure', side_effect=OSError('no disk data')), contextlib.redirect_stdout(output):
            code = cli.run(self.config, [self.host], github_only=True)
        self.assertEqual(code, 0)
        self.assertIn('all on GitHub', output.getvalue())

    def test_nas_cap_dry_without_archive_tiers_and_does_not_count_as_host_savings(self):
        self.config['live'] = ['cache', 'worktree']
        store = Mock()
        store.enforce_cap.return_value = [SimpleNamespace(archive_path='/nas/old.tar.zst', archive_bytes=100)]
        with patch.object(disk, 'measure', return_value=disk.Usage(100, 20, 20)), \
             patch.object(protect, 'collect', return_value=self.protection), patch.object(cli, 'store', store), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.run(self.config, [self.host], True), 0)
        store.enforce_cap.assert_called_once_with(self.config['nas_root'], 500 * 1024**3, apply=False)
        text = next((self.root / 'reports').glob('*.md')).read_text()
        self.assertIn('would expire archive', text)
        self.assertIn('Would free: 0.00 GiB (0 bytes)', text)

    def test_run_real_entrypoint_with_fake_host(self):
        with patch.dict(hosts.HOSTS, {'test': self.host}), patch.object(disk, 'measure', return_value=disk.Usage(100, 20, 20)), \
             patch.object(rules, 'load', return_value=self.config), \
             patch.object(protect, 'collect', return_value=self.protection), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(['run', '--host', 'test', '--report-dir', self.config['report_dir']])
        self.assertEqual(code, 0)
        self.assertTrue(any((self.root / 'reports').glob('*.md')))


if __name__ == '__main__':
    unittest.main()
