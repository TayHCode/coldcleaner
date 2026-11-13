import base64
import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from coldcleaner import cli, disk, hosts, protect, reclaim, rules, store
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
        self.config['hosts'][self.host.name] = dict(roots=[str(self.root / 'projects')], archive=[])
        self.protection = protect.Protection(self.host, str(self.root), set(), [])
        collector = patch.object(protect, 'collect', return_value=self.protection)
        collector.start()
        self.addCleanup(collector.stop)

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
        protection = protect.Protection(hosts.HOSTS['winhost'], r'C:\Users\user', set(), [])
        broad = ['C:\\', r'C:\Users', r'C:\Windows', r'C:\Program Files',
                 r'C:\Program Files (x86)', r'C:\Users\user']
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
        protection.paths = {r'C:\Users\user\jobs\task.ps1'}
        self.assertIn('scheduler references', protection.reason(r'C:\Users\user\jobs'))

    def test_root_reference_is_reported_once(self):
        self.protection.paths = {'/', str(self.root)}
        steps = {name: lambda self: None for name in ('worktrees', 'clones', 'archives', 'unlisted')}
        with patch.object(disk, 'measure', return_value=disk.Usage(100, 75, 75)), \
             patch.multiple(reclaim.Reclaimer, **steps), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.run(self.config, [self.host]), 0)
        text = next(Path(self.config['report_dir']).glob('*.md')).read_text()
        self.assertEqual(text.count('Broad scheduler references, equality only:'), 1)
        self.assertNotIn('scheduler references /; size not measured', text)

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
