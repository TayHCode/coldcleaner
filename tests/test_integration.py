import base64
import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from coldcleaner import cli, disk, gitsafe, hosts, protect, report, rules, store, tiers
from tests import outside_git

outside_git.use()


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = rules.load(Path(__file__).parent / 'fixtures' / 'rules.toml')
        self.host = hosts.Host('integration', 'posix')
        host_patch = patch.dict(hosts.HOSTS, {self.host.name: self.host})
        host_patch.start()
        self.addCleanup(host_patch.stop)
        self.config.update(nas_root=str(self.root / 'nas'), report_dir=str(self.root / 'reports'))
        self.config['hosts'][self.host.name] = dict(roots=[str(self.root / 'projects')], archive=[], cache=[])
        self.protection = protect.Protection(self.host, str(self.root), set(), [])
        collector = patch.object(protect, 'collect', return_value=self.protection)
        collector.start()
        self.addCleanup(collector.stop)
        self.entry = report.HostReport(self.host.name)
        self.cleaner = tiers.Cleaner(self.host, self.config, False, self.protection, self.entry)

    def project(self):
        project = self.root / 'projects' / 'app'
        project.mkdir(parents=True)
        (project / 'evidence.txt').write_text('precious')
        (project / 'node_modules').mkdir()
        (project / 'node_modules' / 'package').write_text('regenerable')
        for path in sorted(project.rglob('*'), reverse=True) + [project]:
            os.utime(path, (1, 1))
        state = gitsafe.RepoState(str(project), verdict='on_github')
        self.cleaner.repos = [state]
        return project, state

    def test_cleaner_uses_real_gitsafe_boundary_by_default(self):
        state = gitsafe.RepoState('/repo', verdict='backup_needed')
        with patch.object(gitsafe, 'find_repos', autospec=True, return_value=['/repo']) as discover, \
             patch.object(gitsafe, 'inspect', autospec=True, return_value=state) as inspect, \
             patch.object(gitsafe, 'backup', autospec=True, return_value=['refs/coldcleaner/integration/main']) as backup:
            tiers.Cleaner(self.host, self.config, False, self.protection, self.entry).github()
        discover.assert_called_once_with(self.host, self.config['hosts'][self.host.name]['roots'], [])
        inspect.assert_called_once_with(self.host, '/repo')
        backup.assert_called_once_with(self.host, '/repo', apply=False)
        self.assertEqual(self.entry.repos, [state])

    def test_github_preview_counts_checkpoint_refs_and_preserves_blocked_reason(self):
        refs = [f't3/orchestration-v2/checkpoints/session/ordinal/{n}' for n in range(251)]
        state = gitsafe.RepoState('/repo', verdict='backup_needed', unpushed_branches=refs)
        for messages, expected in [
            (['refs/coldcleaner/integration/' + ref for ref in refs], '251 backup refs'),
            (['blocked: push failed: no GitHub credentials on integration'],
             'blocked: push failed: no GitHub credentials on integration'),
        ]:
            with self.subTest(expected=expected), \
                 patch.object(gitsafe, 'find_repos', return_value=['/repo']), \
                 patch.object(gitsafe, 'inspect', return_value=state), \
                 patch.object(gitsafe, 'backup', return_value=messages), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cli.run(self.config, [self.host], github_only=True), 0)
            text = output.getvalue()
            self.assertIn('| /repo | backup_needed | 0 | 0 | 251 | 0 |', text)
            self.assertIn(expected, text)
            self.assertNotIn('t3/orchestration-v2/checkpoints/', text)
            self.assertEqual(state.unpushed_branches, refs)

    def test_unreadable_discovery_folder_is_logged_and_scan_continues(self):
        def discover(host, roots, unreadable):
            unreadable.append('/denied')
            return []
        with patch.object(gitsafe, 'find_repos', side_effect=discover):
            self.cleaner.github()
        self.assertEqual(self.entry.actions, [dict(tier='github', path='/denied', action='skip', bytes=0,
                                                   reason='cannot read directory')])

    def test_native_windows_does_not_send_bash_to_powershell_for_git(self):
        self.cleaner.host = hosts.HOSTS['winhost']
        with patch.object(gitsafe, 'find_repos', autospec=True) as discover:
            with self.assertRaisesRegex(NotImplementedError, 'GitHub inspection requires POSIX or WSL'):
                self.cleaner.github()
        discover.assert_not_called()

    def test_broad_posix_references_protect_only_themselves(self):
        broad = ['/', str(self.root), '/usr', '/etc', '/var', '/opt', '/bin', '/sbin',
                 '/lib', '/lib64', '/tmp', '/Users', '/home', '/System', '/Library']
        with patch.object(disk, 'python', side_effect=lambda host, source, *args, **kw: dict.fromkeys(json.loads(kw['stdin_bytes'])[0], '')):
            for path in broad:
                with self.subTest(path=path):
                    self.protection.paths = {path}
                    self.assertIn('scheduler references', self.protection.reason(path))
                    self.assertEqual(self.protection.reason(path.rstrip('/') + '/child'), '')
        self.protection.paths = {'/usr/local/app/task.py'}
        self.assertIn('scheduler references', self.protection.reason('/usr/local/app'))
        self.protection.paths = {'/usr/local/app'}
        self.assertIn('scheduler references', self.protection.reason('/usr/local/app/data'))

    def test_broad_windows_references_protect_only_themselves(self):
        protection = protect.Protection(hosts.HOSTS['winhost'], r'C:\Users\Alice', set(), [])
        broad = ['C:\\', r'C:\Users', r'C:\Windows', r'C:\Program Files',
                 r'C:\Program Files (x86)', r'C:\Users\Alice']
        def response(host, script, **kwargs):
            encoded = re.search(r"FromBase64String\('([^']+)'\)", script)[1]
            paths = json.loads(base64.b64decode(encoded))
            return type('Result', (), dict(returncode=0, stdout=json.dumps(dict.fromkeys(paths, '')).encode()))()
        with patch.object(disk, 'powershell', side_effect=response):
            for path in broad:
                with self.subTest(path=path):
                    protection.paths = {path}
                    self.assertIn('scheduler references', protection.reason(path.lower()))
                    self.assertEqual(protection.reason(path.rstrip('\\') + r'\child'), '')
        protection.paths = {r'C:\Users\Alice\jobs\task.ps1'}
        self.assertIn('scheduler references', protection.reason(r'C:\Users\Alice\jobs'))

    def test_root_reference_allows_candidates_and_is_reported_once(self):
        cache = self.root / 'cache'
        cache.mkdir()
        (cache / 'data').write_bytes(b'cached')
        self.config['hosts'][self.host.name]['cache'] = [dict(path=str(cache))]
        self.protection.paths = {'/', str(self.root)}
        with patch.object(disk, 'measure', return_value=disk.Usage(100, 75, 75)), \
             patch.object(protect, 'collect', return_value=self.protection), \
             patch.object(self.protection, 'reason', return_value=''), \
             patch.object(self.protection, 'batch', side_effect=lambda paths, **kw: dict.fromkeys(paths, '')), \
             patch.object(gitsafe, 'find_repos', return_value=[]), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.run(self.config, [self.host]), 0)
        text = next(Path(self.config['report_dir']).glob('*.md')).read_text()
        self.assertIn('would clean cache', text)
        self.assertIn('6 bytes', text)
        self.assertEqual(text.count('Broad scheduler references, equality only:'), 1)
        self.assertNotIn('scheduler references /; size not measured', text)
        self.assertEqual((cache / 'data').read_bytes(), b'cached')

    def test_project_uses_one_verified_whole_folder_archive(self):
        project, state = self.project()
        self.config['live'] = ['project']
        self.cleaner.apply = True
        archive = store.archive
        calls = []
        def capture(host, path, **kwargs):
            calls.append(str(path))
            self.assertFalse((project / 'node_modules').exists())
            self.assertEqual((project / 'evidence.txt').read_text(), 'precious')
            return archive(host, path, **kwargs)
        with patch.object(self.protection, 'reason', return_value=''), \
             patch.object(self.protection, 'batch', side_effect=lambda paths, **kw: dict.fromkeys(paths, '')), \
             patch.object(gitsafe, 'inspect', return_value=state), \
             patch.object(store, 'archive', side_effect=capture):
            self.cleaner.project()
        self.assertEqual(calls, [str(project)])
        self.assertFalse(project.exists())
        records = store.find('evidence.txt', self.config['nas_root'])
        self.assertEqual(len(records), 1)
        store.restore(records[0].id, self.config['nas_root'])
        self.assertEqual((project / 'evidence.txt').read_text(), 'precious')
        self.assertFalse((project / 'node_modules').exists())

    def test_project_dry_run_reports_both_steps_without_double_counting(self):
        project, _ = self.project()
        with patch.object(self.protection, 'reason', return_value=''), \
             patch.object(self.protection, 'batch', side_effect=lambda paths, **kw: dict.fromkeys(paths, '')), \
             patch.object(store, 'archive', autospec=True) as archive:
            self.cleaner.project()
        archive.assert_not_called()
        proposed = [(row['action'], row['bytes']) for row in self.entry.actions]
        self.assertEqual(proposed, [('would remove regenerable data', 11),
                                    ('would archive project and verify then remove', 8)])
        self.assertEqual(self.entry.would_free, 19)
        self.assertEqual((project / 'node_modules' / 'package').read_text(), 'regenerable')
        self.assertEqual((project / 'evidence.txt').read_text(), 'precious')

    def test_archive_tier_selects_compression_by_bytes(self):
        for directory, compressed, expected in [(False, True, 1), (True, True, 1), (True, False, 10)]:
            with self.subTest(directory=directory, compressed=compressed):
                path = self.root / f'{directory}-{compressed}.GGUF'
                if directory:
                    path.mkdir()
                    (path / 'model.GGUF').write_bytes(b'x' * (100 if compressed else 1))
                    (path / 'text.txt').write_bytes(b'y' * 10)
                    for child in path.iterdir():
                        os.utime(child, (1, 1))
                else:
                    path.write_bytes(b'x' * 100)
                os.utime(path, (1, 1))
                self.config['hosts'][self.host.name]['archive'] = [str(path)]
                self.config['live'] = ['archive']
                self.cleaner.apply = True
                with patch.object(self.protection, 'reason', return_value=''), \
                     patch.object(self.protection, 'batch', side_effect=lambda paths, **kw: dict.fromkeys(paths, '')), \
                     patch.object(store, 'archive', autospec=True, return_value=object()) as archive:
                    self.cleaner.archive()
                archive.assert_called_once_with(self.host, str(path), apply=True,
                    nas_root=self.config['nas_root'], level=expected)

    def test_single_file_archive_round_trip(self):
        source = self.root / 'model.GGUF'
        source.write_bytes(b'compressed model')
        record = store.archive(self.host, source, apply=True, nas_root=self.config['nas_root'], level=1)
        self.assertEqual(record.file_count, 1)
        self.assertFalse(source.exists())
        store.restore(record.id, self.config['nas_root'])
        self.assertEqual(source.read_bytes(), b'compressed model')

    def test_empty_compressed_file_uses_level_one(self):
        source = self.root / 'empty.GGUF'
        source.touch()
        self.assertEqual(store.compression_level(self.host, source, self.config['already_compressed_extensions']), 1)
