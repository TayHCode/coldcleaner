import importlib.metadata
import subprocess
import tomllib
from pathlib import Path

CHECKOUT = Path(__file__).resolve().parent.parent


def git(checkout, *args):
    return subprocess.run(['git', '-C', str(checkout), *args], capture_output=True, text=True, timeout=30)


def describe(checkout=CHECKOUT):
    try:
        top = git(checkout, 'rev-parse', '--show-toplevel')
        if top.returncode or Path(top.stdout.strip()).resolve() != Path(checkout).resolve():
            return installed() if checkout == CHECKOUT else None
        head = git(checkout, 'rev-parse', '--short', 'HEAD')
        branch = git(checkout, 'branch', '--show-current').stdout.strip() or 'detached'
        behind = git(checkout, 'merge-base', '--is-ancestor', 'origin/main', 'HEAD').returncode == 1
    except (OSError, subprocess.SubprocessError):
        return installed() if checkout == CHECKOUT else None
    label = f'{branch} @ {head.stdout.strip()}'
    if behind:
        label += ' (WARNING: does not contain origin/main; newer hosts and fixes are not in use)'
    return label


def installed():
    try:
        return 'installed coldcleaner ' + importlib.metadata.version('coldcleaner') + ' (not a Git checkout; revision unknown)'
    except importlib.metadata.PackageNotFoundError:
        return None


def number():
    try:
        project = tomllib.loads((CHECKOUT / 'pyproject.toml').read_text(encoding='utf-8')).get('project', {})
    except FileNotFoundError:
        project = {}
    if isinstance(project, dict) and project.get('name') == 'coldcleaner':
        return project['version']
    return importlib.metadata.version('coldcleaner')
