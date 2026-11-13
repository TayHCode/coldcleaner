import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
from unittest.mock import patch

from coldcleaner import cli, hosts, rules


class HostTests(unittest.TestCase):
    def launcher(self, script):
        command = hosts.argv(hosts.Host("winhost-wsl", "wsl", "winhost"), script)[-1]
        prefix = 'wsl.exe -e python3 -c "'
        self.assertTrue(command.startswith(prefix))
        self.assertTrue(command.endswith('"'))
        self.assertFalse(any(value in command for value in '&|<>^%!'))
        return command, command[len(prefix):-1]

    def test_large_wsl_script_round_trips_through_python_launcher(self):
        script = "printf '%s\\n' 'payload ☃'\n" * 8000
        self.assertGreater(len(script.encode()), 200000)
        command, launcher = self.launcher(script)
        with patch("os.execvp") as execute:
            exec(launcher, {})
        execute.assert_called_once_with("bash", ["bash", "-c", script])

    def test_typical_100kb_script_fits_windows_command_line(self):
        script = 'for path in "$HOME/projects/"*; do printf "%s\\n" "$path"; done\n' * 1800
        self.assertGreater(len(script), 100000)
        command, launcher = self.launcher(script)
        self.assertLess(len(command), 8000)

    def test_retired_wsl_run_is_refused_but_native_windows_inventory_remains_available(self):
        result = subprocess.CompletedProcess([], 0, stdout=b'inventory', stderr=b'')
        with patch('subprocess.run', return_value=result) as run:
            with self.assertRaisesRegex(ValueError, 'Windows WSL execution is retired'):
                hosts.run(hosts.Host('winhost-wsl', 'wsl', 'winhost'), 'cat', stdin_bytes=b'refs')
            observed = hosts.run(hosts.Host('winhost', 'powershell', 'winhost'), 'Get-PSDrive C')
        self.assertEqual(observed.stdout, b'inventory')
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs['input'], b'Get-PSDrive C')

    def test_powershell_host_without_ssh_runs_powershell_exe_locally(self):
        local = hosts.Host('winlocal', 'powershell')
        result = subprocess.CompletedProcess([], 0, stdout=b'inventory', stderr=b'')
        with patch('subprocess.run', return_value=result) as run:
            hosts.run(local, 'Get-PSDrive C')
        self.assertEqual(run.call_args.args[0], ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', '-'])
        self.assertEqual(run.call_args.kwargs['input'], b'Get-PSDrive C')
        command = hosts.python_argv(local)
        self.assertEqual(command[:2], ['python.exe', '-c'])
        self.assertNotIn('ssh', command)

    def test_retired_wsl_stream_is_refused_but_native_posix_stream_remains_available(self):
        with patch('subprocess.Popen', return_value='native stream') as popen:
            with self.assertRaisesRegex(ValueError, 'Windows WSL execution is retired'):
                hosts.popen(hosts.Host('winhost-wsl', 'wsl', 'winhost'), 'tar -cf - source')
            observed = hosts.popen(hosts.Host('fixture', 'posix', 'bridge.example.invalid'), 'printf fixture')
        self.assertEqual(observed, 'native stream')
        self.assertEqual(popen.call_count, 1)
        self.assertIn('bridge.example.invalid', popen.call_args.args[0])


class ConfiguredHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'rules.toml'
        self.head = (Path(__file__).resolve().parents[1] / 'rules.example.toml').read_text().split('[hosts.local]')[0]
        registry = patch.dict(hosts.HOSTS, {}, clear=True)
        registry.start()
        self.addCleanup(registry.stop)

    def load(self, tables, settings=''):
        self.path.write_text(self.head + settings + '\n' + tables)
        return rules.load(self.path)

    def test_registry_is_populated_in_place_and_replaces_previous_hosts(self):
        original = hosts.HOSTS
        config = self.load('[hosts.mine]\nkind = "posix"\n[hosts.remote]\nkind = "powershell"\nssh = "bridge.example.invalid"\ndistro = "Ubuntu"')
        self.assertIs(hosts.HOSTS, original)
        self.assertEqual(hosts.HOSTS, {
            'mine': hosts.Host('mine', 'posix'),
            'remote': hosts.Host('remote', 'powershell', 'bridge.example.invalid', 'Ubuntu'),
        })
        self.assertEqual(config['reclaim_hosts'], ['mine', 'remote'])
        self.load('[hosts.replacement]\nkind = "posix"')
        self.assertEqual(hosts.HOSTS, {'replacement': hosts.Host('replacement', 'posix')})

    def test_host_kind_ssh_and_distro_are_validated(self):
        self.load('[hosts.original]\nkind = "posix"')
        for key, values in (('kind', ['"unknown"', '42', '[]']),
                            ('ssh', ['42', 'false', '[]', '""']),
                            ('distro', ['42', 'false', '[]', '""'])):
            for value in values:
                with self.subTest(key=key, value=value):
                    with self.assertRaisesRegex(ValueError, 'custom.' + key):
                        self.load('[hosts.custom]\n' + ('' if key == 'kind' else 'kind = "posix"\n') + key + ' = ' + value)
                    self.assertEqual(hosts.HOSTS, {'original': hosts.Host('original', 'posix')})

    def test_reclaim_defaults_to_configured_non_wsl_hosts(self):
        config = self.load('[hosts.mine]\nkind = "posix"\n[hosts.bridge]\nkind = "powershell"\nssh = "bridge.example.invalid"\n'
                           '[hosts.linux]\nkind = "wsl"\nssh = "bridge.example.invalid"')
        self.assertEqual(config['reclaim_hosts'], ['mine', 'bridge'])
        with patch.object(cli, 'run', return_value=0) as run:
            self.assertEqual(cli.main(['reclaim', '--rules', str(self.path)]), 0)
        self.assertEqual(run.call_args.args[1], [hosts.Host('mine', 'posix'),
                                               hosts.Host('bridge', 'powershell', 'bridge.example.invalid')])

    def test_reclaim_explicit_selection_and_empty_list(self):
        for value, expected in (('["remote"]', ['remote']), ('[]', [])):
            with self.subTest(value=value):
                config = self.load('[hosts.mine]\nkind = "posix"\n[hosts.remote]\nkind = "posix"\nssh = "remote.example.invalid"',
                                   'reclaim_hosts = ' + value)
                self.assertEqual(config['reclaim_hosts'], expected)
                with patch.object(cli, 'run', return_value=0) as run:
                    self.assertEqual(cli.main(['reclaim', '--rules', str(self.path)]), 0)
                self.assertEqual([host.name for host in run.call_args.args[1]], expected)

    def test_reclaim_hosts_must_be_a_list_of_configured_names(self):
        for value in ('"mine"', '["missing"]', '[42]', '[[]]'):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, 'reclaim_hosts'):
                    self.load('[hosts.mine]\nkind = "posix"', 'reclaim_hosts = ' + value)

    def test_unknown_host_options_are_refused_after_rules_load(self):
        self.load('[hosts.mine]\nkind = "posix"')
        for args, option in ((['reclaim', '--json', '--host', 'missing'], '--host'),
                             (['restore', 'archive-id', '--to-host', 'missing'], '--to-host')):
            with self.subTest(option=option), patch.object(cli, 'run') as run, \
                    patch.object(cli.store, 'restore') as restore, contextlib.redirect_stdout(io.StringIO()) as output:
                code = cli.main(args + ['--rules', str(self.path)])
            self.assertEqual(code, 2)
            self.assertIn('unknown ' + option + ' host: missing; known hosts: mine', output.getvalue())
            run.assert_not_called()
            restore.assert_not_called()
            if '--json' in args:
                self.assertEqual(json.loads(output.getvalue())['status'], 'refused')

    def test_custom_host_is_accepted_and_non_posix_restore_is_refused(self):
        self.load('[hosts.mine]\nkind = "posix"\n[hosts.bridge]\nkind = "powershell"\nssh = "bridge.example.invalid"')
        with patch.object(cli, 'run', return_value=0) as run:
            self.assertEqual(cli.main(['reclaim', '--rules', str(self.path), '--host', 'mine']), 0)
        self.assertEqual(run.call_args.args[1], [hosts.Host('mine', 'posix')])
        with patch.object(cli.store, 'restore') as restore, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(['restore', 'id', '--rules', str(self.path), '--to-host', 'bridge']), 2)
        self.assertIn('--to-host requires a POSIX host', output.getvalue())
        restore.assert_not_called()

    def test_local_output_paths_are_protected_for_custom_host_names(self):
        with self.assertRaisesRegex(ValueError, 'mine.roots.*would clean up nas_root'):
            self.load('[hosts.mine]\nkind = "posix"\nroots = ["~/.local/share/coldcleaner"]')
        config = self.load('[hosts.remote]\nkind = "posix"\nssh = "remote.example.invalid"\nroots = ["~/.local/share/coldcleaner"]')
        self.assertEqual(config['hosts']['remote']['roots'], ['~/.local/share/coldcleaner'])

if __name__ == "__main__":
    unittest.main()
