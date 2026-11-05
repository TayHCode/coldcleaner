import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from coldcleaner import cli, disk, hosts, protect, report, rules, version


def run(path, *args):
    subprocess.run(['git', '-C', str(path), '-c', 'user.name=t', '-c', 'user.email=t@t', *args],
                   check=True, capture_output=True)


class VersionCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        registry = patch.dict(hosts.HOSTS, {'version-test': hosts.Host('version-test', 'posix')}, clear=True)
        registry.start()
        self.addCleanup(registry.stop)
        self.root = Path(directory.name)
        self.checkout = self.root / 'install'
        self.checkout.mkdir()
        run(self.checkout, 'init', '-q', '-b', 'main')
        run(self.checkout, 'commit', '-q', '--allow-empty', '-m', 'one')
        run(self.checkout, 'update-ref', 'refs/remotes/origin/main', 'HEAD')

    def advance_origin(self):
        run(self.checkout, 'commit', '-q', '--allow-empty', '-m', 'two')
        run(self.checkout, 'update-ref', 'refs/remotes/origin/main', 'HEAD')
        run(self.checkout, 'reset', '-q', '--hard', 'HEAD~1')

    def test_current_checkout_has_no_warning(self):
        label = version.describe(self.checkout)
        self.assertRegex(label, r'^main @ [0-9a-f]+$')

    def test_checkout_missing_origin_main_commits_is_flagged(self):
        self.advance_origin()
        run(self.checkout, 'checkout', '-q', '-b', 'fix/old')
        label = version.describe(self.checkout)
        self.assertRegex(label, r'^fix/old @ [0-9a-f]+ \(WARNING: does not contain origin/main')

    def test_installed_copy_reports_its_package_version(self):
        with patch('importlib.metadata.version', return_value='0.1.0'), patch.object(version, 'CHECKOUT', self.root):
            self.assertEqual(version.describe(self.root), 'installed coldcleaner 0.1.0 (not a Git checkout; revision unknown)')
            with patch.object(version, 'git', side_effect=FileNotFoundError('git')):
                self.assertEqual(version.describe(self.root), 'installed coldcleaner 0.1.0 (not a Git checkout; revision unknown)')
        with patch('importlib.metadata.version', side_effect=version.importlib.metadata.PackageNotFoundError):
            self.assertIsNone(version.installed())

    def test_not_a_checkout_is_none(self):
        self.assertIsNone(version.describe(self.root))

    def test_folder_inside_another_repository_is_not_a_checkout(self):
        inside = self.checkout / 'tools' / 'site'
        inside.mkdir(parents=True)
        self.assertIsNone(version.describe(inside))

    def test_report_and_status_show_code(self):
        self.advance_origin()
        label = version.describe(self.checkout)
        reports = Path(self.root) / 'reports'
        saved = report.write([report.HostReport('one')], reports, code=label)
        self.assertIn(f'Code: {label}', saved.read_text().splitlines())
        config = dict(report_dir=str(reports), alert_pct=80, hard_pct=85)
        output = io.StringIO()
        with patch.object(disk, 'measure', return_value=disk.Usage(100, 20, 20)), \
                patch.object(rules, 'load', return_value=config), \
                patch.object(version, 'describe', return_value=label), \
                contextlib.redirect_stdout(output):
            cli.main(['status', '--host', 'version-test', '--report-dir', str(reports)])
        self.assertIn(f'Code: {label}', output.getvalue().splitlines())

    def test_cleanup_report_keeps_starting_version_when_checkout_advances(self):
        describe = version.describe
        label = describe(self.checkout)
        config = rules.load(); config['report_dir'] = str(self.root / 'reports')
        def measure(host):
            run(self.checkout, 'commit', '-q', '--allow-empty', '-m', 'during cleanup')
            return disk.Usage(100, 20, 20)
        with patch.object(version, 'describe', side_effect=lambda: describe(self.checkout)), \
                patch.object(disk, 'measure', side_effect=measure), \
                patch.object(protect, 'collect'), patch.object(cli.reclaim, 'Reclaimer'), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.run(config, [hosts.LOCAL], reclaim_only=True), 0)
        saved = next(Path(config['report_dir']).glob('*.md'))
        self.assertIn('Code: ' + label, saved.read_text())
        self.assertNotEqual(version.describe(self.checkout), label)
