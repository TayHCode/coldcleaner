import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import hosts, reclaim

MINIMUM_PYTHON = (3, 14)


def reason(exc):
    if isinstance(exc, subprocess.CalledProcessError):
        output = (exc.stderr or exc.stdout or b'').decode(errors='replace').strip().splitlines()
        return output[-1] if output else f'exit {exc.returncode}'
    return str(exc) or type(exc).__name__


def python(version=sys.version_info):
    found = f'Python {version[0]}.{version[1]}'
    if tuple(version[:2]) >= MINIMUM_PYTHON:
        return True, found
    return False, f'{found}; coldcleaner needs Python 3.14+'


def tool(name):
    path = shutil.which(name)
    return (True, path) if path else (False, f'{name} not found on PATH')


def gh_auth():
    result = hosts.run(hosts.LOCAL, 'gh auth status', check=False, timeout=60)
    if result.returncode == 0:
        return True, 'gh auth status OK'
    lines = (result.stderr + result.stdout).decode(errors='replace').strip().splitlines()
    return False, lines[-1].strip() if lines else f'gh auth status exited {result.returncode}'


def writable(path):
    target = Path(path)
    while not target.exists() and target != target.parent:
        target = target.parent
    if not target.is_dir():
        return False, f'{path}: {target} is not a directory'
    if not os.access(target, os.W_OK | os.X_OK):
        return False, f'{path}: {target} is not writable'
    return True, str(path) if target == Path(path) else f'{path} (will be created in {target})'


def reach(host):
    hosts.run(host, 'exit 0', timeout=60)
    return True, f'ssh {host.ssh}' if host.ssh else 'local shell'


def inventory(host):
    found = reclaim.probe(host, 'activity')
    return True, f"{len(found['references'])} process references readable"


def outcome(check, *args):
    try:
        return check(*args)
    except Exception as exc:
        return False, reason(exc)


def checks(config, chosen_hosts):
    yield 'python', outcome(python)
    yield 'zstd', outcome(tool, 'zstd')
    yield 'git', outcome(tool, 'git')
    yield 'gh auth', outcome(gh_auth)
    yield 'nas_root', outcome(writable, config['nas_root'])
    yield 'report_dir', outcome(writable, config['report_dir'])
    for host in chosen_hosts:
        reachable = outcome(reach, host)
        yield f'{host.name} reach', reachable
        yield f'{host.name} process inventory', (outcome(inventory, host) if reachable[0]
                                                 else (False, 'not checked: host unreachable'))


def main(config, chosen_hosts):
    failures = 0
    for name, (ok, detail) in checks(config, chosen_hosts):
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}", flush=True)
    print(f'doctor: {failures} check(s) failed' if failures else 'doctor: all checks passed')
    return 1 if failures else 0
