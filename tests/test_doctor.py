import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from coldcleaner import cli, doctor, hosts, reclaim_probe

WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
WRITE_EVENTS = {'os.mkdir', 'os.remove', 'os.rename', 'os.rmdir', 'os.symlink', 'os.link', 'os.truncate',
                'os.chmod', 'os.chown', 'os.utime', 'shutil.rmtree', 'shutil.copyfile', 'shutil.move',
                'shutil.copytree', 'tempfile.mkstemp', 'tempfile.mkdtemp', 'subprocess.Popen', 'os.system'}
recorded = None


def audit(event, args):
    if recorded is None:
        return
    if event == 'open' and isinstance(args[2], int) and args[2] & WRITE_FLAGS:
        recorded.append((event, args[0]))
    elif event in WRITE_EVENTS:
        recorded.append((event, args[0] if args else None))


sys.addaudithook(audit)


class FakeFleet:
    def __init__(self, down=(), sudo_refused=(), gh_ok=True):
        self.down, self.sudo_refused, self.gh_ok = set(down), set(sudo_refused), gh_ok
        self.scripts, self.operations = [], []

    def run(self, host, script, **kwargs):
        self.scripts.append((host.name, script))
        if script == 'gh auth status':
            if self.gh_ok:
                return subprocess.CompletedProcess(['gh'], 0, b'', b'Logged in to github.com\n')
            return subprocess.CompletedProcess(['gh'], 1, b'', b'You are not logged into any GitHub hosts. To log in, run: gh auth login\n')
        if host.name in self.down:
            raise subprocess.CalledProcessError(255, ['ssh'], b'', f'ssh: Could not resolve hostname {host.ssh}\n'.encode())
        return subprocess.CompletedProcess(['ssh'], 0, b'', b'')

    def probe(self, host, operation, **request):
        self.operations.append((host.name, operation))
        if host.name in self.sudo_refused:
            raise ValueError(reclaim_probe.NEEDS_SUDO)
        return dict(threads=[], references=['/proc/1/cwd', '/usr/bin/bash'])


class DoctorCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        registry = patch.dict(hosts.HOSTS, clear=True)
        registry.start()
        self.addCleanup(registry.stop)

    def rules(self, nas_root, report_dir):
        path = self.directory / 'rules.toml'
        fixture = (Path(__file__).parent.parent / 'rules.example.toml').read_text()
        lines = [line for line in fixture.splitlines() if not line.startswith(('nas_root', 'report_dir', 'reclaim_hosts'))]
        top = lines.index(next(line for line in lines if line.startswith('[')))
        lines[top:top] = [f'nas_root = "{nas_root}"', f'report_dir = "{report_dir}"', 'reclaim_hosts = ["box", "nas-box"]']
        lines += ['[hosts.box]', 'kind = "posix"', 'ssh = "box.example.invalid"', 'roots = []', 'archive = []',
                  'compact = []', 'cache = []',
                  '[hosts.nas-box]', 'kind = "posix"', 'ssh = "nas-box.example.invalid"', 'roots = []',
                  'archive = []', 'compact = []', 'cache = []']
        path.write_text('\n'.join(lines) + '\n')
        return path

    def doctor(self, fleet, rules, *argv, missing=()):
        stdout = io.StringIO()
        def which(name):
            return None if name in missing else f'/usr/bin/{name}'
        with patch.object(doctor.hosts, 'run', side_effect=fleet.run), \
                patch.object(doctor.reclaim, 'probe', side_effect=fleet.probe), \
                patch.object(doctor.shutil, 'which', side_effect=which), \
                contextlib.redirect_stdout(stdout):
            code = cli.main(['doctor', '--rules', str(rules), *argv])
        return code, stdout.getvalue().splitlines()

    def test_healthy_fleet_passes_every_check_and_exits_zero(self):
        rules = self.rules(self.directory / 'nas', self.directory / 'reports')
        code, lines = self.doctor(FakeFleet(), rules)
        self.assertEqual(code, 0)
        self.assertEqual([line.split(':')[0] for line in lines[:-1]], [
            'PASS  python', 'PASS  zstd', 'PASS  git', 'PASS  gh auth', 'PASS  nas_root', 'PASS  report_dir',
            'PASS  box reach', 'PASS  box process inventory', 'PASS  nas-box reach', 'PASS  nas-box process inventory'])
        self.assertIn(f'PASS  nas_root: {self.directory}/nas (will be created in {self.directory})', lines)
        self.assertIn('PASS  box reach: ssh box.example.invalid', lines)
        self.assertIn('PASS  box process inventory: 2 process references readable', lines)
        self.assertEqual(lines[-1], 'doctor: all checks passed')

    def test_broken_fixture_names_every_failure_and_exits_one(self):
        blocker = self.directory / 'blocker'
        blocker.write_text('a file where a directory belongs')
        rules = self.rules(self.directory / 'nas', blocker / 'reports')
        fleet = FakeFleet(down={'box'}, sudo_refused={'nas-box'}, gh_ok=False)
        code, lines = self.doctor(fleet, rules, missing={'zstd'})
        self.assertEqual(code, 1)
        self.assertIn('FAIL  zstd: zstd not found on PATH', lines)
        self.assertIn('FAIL  gh auth: You are not logged into any GitHub hosts. To log in, run: gh auth login', lines)
        self.assertIn(f'FAIL  report_dir: {blocker}/reports: {blocker} is not a directory', lines)
        self.assertIn('FAIL  box reach: ssh: Could not resolve hostname box.example.invalid', lines)
        self.assertIn('FAIL  box process inventory: not checked: host unreachable', lines)
        self.assertIn('PASS  nas-box reach: ssh nas-box.example.invalid', lines)
        self.assertIn('FAIL  nas-box process inventory: ' + reclaim_probe.NEEDS_SUDO, lines)
        self.assertIn('PASS  git: /usr/bin/git', lines)
        self.assertEqual(lines[-1], 'doctor: 6 check(s) failed')
        self.assertEqual(fleet.operations, [('nas-box', 'activity')])

    def test_host_option_checks_only_that_host(self):
        rules = self.rules(self.directory / 'nas', self.directory / 'reports')
        fleet = FakeFleet()
        code, lines = self.doctor(fleet, rules, '--host', 'nas-box')
        self.assertEqual(code, 0)
        self.assertFalse(any(line.startswith('PASS  box ') for line in lines))
        self.assertEqual(fleet.operations, [('nas-box', 'activity')])

    def test_python_floor(self):
        self.assertEqual(doctor.python((3, 14, 0)), (True, 'Python 3.14'))
        self.assertEqual(doctor.python((3, 12, 3)), (False, 'Python 3.12; coldcleaner needs Python 3.14+'))

    def test_unwritable_directory_fails_without_writing(self):
        locked = self.directory / 'locked'
        locked.mkdir()
        with patch.object(doctor.os, 'access', return_value=False):
            self.assertEqual(doctor.writable(locked / 'reports'),
                             (False, f'{locked}/reports: {locked} is not writable'))

    def test_doctor_never_writes_the_filesystem_or_starts_a_process(self):
        global recorded
        rules = self.rules(self.directory / 'nas' / 'cold', self.directory / 'reports')
        before = sorted((str(path), path.stat().st_mtime_ns) for path in self.directory.rglob('*'))
        fleet = FakeFleet(down={'box'}, sudo_refused={'nas-box'}, gh_ok=False)
        recorded = []
        try:
            code, lines = self.doctor(fleet, rules, '--report-dir', str(self.directory / 'reports'), missing={'zstd'})
            code_ok, _ = self.doctor(FakeFleet(), rules)
            events = recorded
        finally:
            recorded = None
        self.assertEqual((code, code_ok), (1, 0))
        self.assertEqual(events, [])
        self.assertEqual(sorted((str(path), path.stat().st_mtime_ns) for path in self.directory.rglob('*')), before)
        self.assertFalse((self.directory / 'nas').exists())
        self.assertFalse((self.directory / 'reports').exists())
        self.assertEqual({script for _, script in fleet.scripts}, {'gh auth status', 'exit 0'})
        self.assertEqual({operation for _, operation in fleet.operations}, {'activity'})


if __name__ == '__main__':
    unittest.main()
