import fnmatch
import math
import os
import re
import tomllib
from pathlib import Path, PurePosixPath

from . import hosts
from .reclaim_probe import CACHE_TOOLS

TIERS = ('cache', 'github', 'worktree', 'archive', 'project', 'compact')
def default_path(checkout=Path(__file__).resolve().parent.parent):
    if (checkout / 'rules.toml').is_file():
        return checkout / 'rules.toml'
    return Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'coldcleaner' / 'rules.toml'


DEFAULT_PATH = default_path()


TOP_LEVEL_KEYS = frozenset({
    'hard_pct', 'alert_pct', 'cache_idle_days', 'compact_idle_days',
    'worktree_idle_days', 'archive_idle_days',
    'project_idle_days', 'nas_cap_gb', 'nas_root', 'local_archive_mount', 'report_dir',
    'compact_weekday', 'live', 'regenerable_paths',
    'already_compressed_extensions', 'hosts', 'reclaim_hosts', 'actions_log_mb', 'manual_notes',
})
REQUIRED_KEYS = (
    'hard_pct', 'alert_pct', 'worktree_idle_days', 'archive_idle_days', 'project_idle_days',
    'nas_cap_gb', 'compact_weekday', 'live', 'nas_root', 'report_dir',
    'already_compressed_extensions', 'hosts',
)
HOST_KEYS = frozenset({'roots', 'archive', 'compact', 'cache', 'cache_tools', 'shared_roots', 'kind', 'ssh', 'distro'})
CACHE_KEYS = frozenset({'path', 'command', 'days', 'owner', 'runner', 'failed_days', 'clone'})
USERNAME = re.compile(r'[A-Za-z0-9._-]+')
WINDOWS_TEMP_FOLDERS = (
    '%TEMP%', '%TMP%', '%LOCALAPPDATA%\\TEMP', '%USERPROFILE%\\APPDATA\\LOCAL\\TEMP',
    'C:\\WINDOWS\\TEMP', '%SYSTEMROOT%\\TEMP',
)


def is_windows_temp(path):
    normal = path.replace('/', '\\').upper()
    return any(normal == folder or normal.startswith(folder + '\\') for folder in WINDOWS_TEMP_FOLDERS)


def load(path=DEFAULT_PATH):
    with open(path, 'rb') as stream:
        data = tomllib.load(stream)
    unknown = set(data) - TOP_LEVEL_KEYS
    if unknown:
        raise ValueError(f'unknown rules option: {sorted(unknown)[0]}; known options: {", ".join(sorted(TOP_LEVEL_KEYS))}')
    missing = [key for key in REQUIRED_KEYS if key not in data]
    if missing:
        raise ValueError(f'missing required key {missing[0]}')
    for key in ('hard_pct', 'alert_pct'):
        if type(data.get(key)) is not int or not 0 < data[key] <= 100:
            raise ValueError(f'{key} must be an integer from 1 through 100, got {data.get(key)!r}')
    if data['alert_pct'] > data['hard_pct']:
        raise ValueError(f"alert_pct must not be above hard_pct, got alert_pct={data['alert_pct']}, hard_pct={data['hard_pct']}")
    for key in ('cache_idle_days', 'worktree_idle_days', 'archive_idle_days', 'project_idle_days', 'compact_idle_days'):
        value = data.get(key, 0) if key in ('cache_idle_days', 'compact_idle_days') else data.get(key)
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError(f'{key} must be a non-negative finite number, got {value!r}')
    if type(data.get('nas_cap_gb')) is not int or data['nas_cap_gb'] < 1:
        raise ValueError(f"nas_cap_gb must be a positive integer, got {data.get('nas_cap_gb')!r}")
    if 'actions_log_mb' in data and (type(data['actions_log_mb']) is not int or data['actions_log_mb'] < 1):
        raise ValueError(f"actions_log_mb must be a positive integer, got {data['actions_log_mb']!r}")
    if data.get('compact_weekday') not in ('mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'):
        raise ValueError(f"compact_weekday must be one of mon, tue, wed, thu, fri, sat, sun, got {data.get('compact_weekday')!r}")
    live = data.get('live')
    if not isinstance(live, list):
        raise ValueError(f'live must be an array, got {live!r}')
    for index, tier in enumerate(live):
        if tier not in TIERS:
            raise ValueError(f'live[{index}]: unknown tier: {tier!r}; known tiers: {", ".join(TIERS)}')
        if tier in live[:index]:
            raise ValueError(f'live[{index}]: repeated tier: {tier!r}')
    output_paths = {key: data.get(key) for key in ('nas_root', 'report_dir')}
    for key in ('nas_root', 'report_dir'):
        if isinstance(data.get(key), str):
            data[key] = str(Path(data[key]).expanduser())
        if not isinstance(data.get(key), str) or not Path(data[key]).is_absolute():
            raise ValueError(f'{key} must be absolute, got {data.get(key)!r}')
        if any(c in data[key] for c in '*?['):
            raise ValueError(f'{key} must not contain glob characters, got {output_paths[key]!r}')
        if has_control(data[key]):
            raise ValueError(f'{key} must not contain control characters, got {output_paths[key]!r}')
        if data[key] != data[key].strip():
            raise ValueError(f'{key} must not start or end with whitespace, got {output_paths[key]!r}')
        if '..' in data[key].replace('\\', '/').split('/'):
            raise ValueError(f"{key} must not contain '..' segments, got {output_paths[key]!r}")
        if root_or_home(data[key]):
            raise ValueError(f'{key} must not be a filesystem root or the home folder, got {output_paths[key]!r}')
    mount = data.get('local_archive_mount', '')
    if mount != '':
        if not isinstance(mount, str) or not Path(mount).is_absolute() or any(c in mount for c in '*?[') or has_control(mount) \
                or '..' in mount.replace('\\', '/').split('/') or root_or_home(mount):
            raise ValueError(f'local_archive_mount must be an absolute mount point, not a root, home or glob path, got {mount!r}')
        if not PurePosixPath(data['nas_root']).is_relative_to(PurePosixPath(mount)):
            raise ValueError(f"nas_root must be inside local_archive_mount, got {output_paths['nas_root']!r} outside {mount!r}")
    regenerable = data.get('regenerable_paths', [])
    if not isinstance(regenerable, list):
        raise ValueError(f'regenerable_paths must be an array, got {regenerable!r}')
    for index, path in enumerate(regenerable):
        if not valid_relative_path(path):
            raise ValueError(f'regenerable_paths[{index}]: not an explicit project-relative directory path: {path!r}')
        if path in regenerable[:index]:
            raise ValueError(f'regenerable_paths[{index}]: repeated path: {path!r}')
    notes = data.get('manual_notes', [])
    if not isinstance(notes, list):
        raise ValueError(f'manual_notes must be an array of strings, got {notes!r}')
    for index, note in enumerate(notes):
        if not isinstance(note, str) or not note.strip() or has_control(note):
            raise ValueError(f'manual_notes[{index}]: not a nonempty single-line string: {note!r}')
        if note in notes[:index]:
            raise ValueError(f'manual_notes[{index}]: repeated note: {note!r}')
    extensions = data.get('already_compressed_extensions')
    if not isinstance(extensions, list):
        raise ValueError(f'already_compressed_extensions must be an array, got {extensions!r}')
    seen_extensions = set()
    for index, extension in enumerate(extensions):
        if (not isinstance(extension, str) or not extension.startswith('.') or len(extension) < 2
                or any(c.isspace() or c in '/\\*?[' for c in extension)):
            raise ValueError(f"already_compressed_extensions[{index}]: not a file extension like '.zip': {extension!r}")
        if extension.lower() in seen_extensions:
            raise ValueError(f'already_compressed_extensions[{index}]: repeated extension: {extension!r}')
        seen_extensions.add(extension.lower())
    host_rules = data.get('hosts')
    if not isinstance(host_rules, dict):
        raise ValueError(f'hosts must be a table, got {host_rules!r}')
    registry = {}
    for name, config in host_rules.items():
        if not isinstance(config, dict):
            raise ValueError(f'{name} must be a table, got {config!r}')
        unknown = set(config) - HOST_KEYS
        if unknown:
            raise ValueError(f'unknown host option: {name}.{sorted(unknown)[0]}; known options: {", ".join(sorted(HOST_KEYS))}')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name):
            raise ValueError(f'invalid host name {name!r}: use letters, digits, dot, dash or underscore, starting with a letter or digit')
        if 'kind' not in config:
            raise ValueError(f'{name}.kind is missing: rules files from before configured hosts must add kind = "posix", '
                             f'"powershell" or "wsl" to every host table, and ssh = "<destination>" to every remote host; '
                             f'a table without ssh runs on this machine')
        kind = config['kind']
        if kind not in ('posix', 'powershell', 'wsl'):
            raise ValueError(f'{name}.kind must be posix, powershell or wsl, got {kind!r}')
        if kind != 'posix' and 'ssh' not in config:
            raise ValueError(f'{name}.ssh is required for {kind} hosts: the controller runs on Linux or macOS')
        for key in ('ssh', 'distro'):
            if key in config and (not isinstance(config[key], str) or not config[key].strip()):
                raise ValueError(f'{name}.{key} must be a nonempty string, got {config[key]!r}')
        registry[name] = hosts.Host(name, kind, config.get('ssh'), config.get('distro'))
        for key in ('roots', 'archive', 'compact', 'shared_roots'):
            paths = config.get(key, [])
            if not isinstance(paths, list):
                raise ValueError(f'{name}.{key} must be an array, got {paths!r}')
            for index, path in enumerate(paths):
                if not valid_path(path):
                    raise ValueError(f'{name}.{key}[{index}]: not an explicit absolute or home path: {path!r}')
                if key == 'shared_roots' and any(char in path for char in '*?['):
                    raise ValueError(f'{name}.{key}[{index}]: shared roots must not contain globs')
                if path_key(path) in [path_key(earlier) for earlier in paths[:index]]:
                    raise ValueError(f'{name}.{key}[{index}]: repeated path: {path!r}')
        tools = config.get('cache_tools', [])
        if not isinstance(tools, list):
            raise ValueError(f'{name}.cache_tools must be an array, got {tools!r}')
        for index, tool in enumerate(tools):
            if not isinstance(tool, str) or tool not in CACHE_TOOLS:
                raise ValueError(f'{name}.cache_tools[{index}]: unknown tool {tool!r}; known tools: {", ".join(CACHE_TOOLS)}')
            if tool in tools[:index]:
                raise ValueError(f'{name}.cache_tools[{index}]: repeated tool: {tool!r}')
        if tools and kind != 'posix':
            raise ValueError(f'{name}.cache_tools needs a POSIX host, got kind {kind!r}')
        caches = config.get('cache', [])
        if not isinstance(caches, list):
            raise ValueError(f'{name}.cache must be an array, got {caches!r}')
        cache_paths = set()
        for index, entry in enumerate(caches):
            location = f'{name}.cache[{index}]: '
            if not isinstance(entry, dict):
                raise ValueError(f'{location}cache entry must be a table, got {entry!r}')
            if not valid_path(entry.get('path')):
                raise ValueError(f"{location}cache needs an explicit absolute or home path, got {entry.get('path')!r}")
            if path_key(entry['path']) in cache_paths:
                raise ValueError(f"{location}repeated cache path: {entry['path']!r}")
            cache_paths.add(path_key(entry['path']))
            unknown = set(entry) - CACHE_KEYS
            if unknown:
                raise ValueError(f'{location}unknown cache option: {sorted(unknown)[0]}; known options: {", ".join(sorted(CACHE_KEYS))}')
            if type(entry.get('days', 0)) is not int or entry.get('days', 0) < 0:
                raise ValueError(f"{location}cache days must be a nonnegative integer, got {entry.get('days')!r}")
            if 'command' in entry and (not isinstance(entry['command'], str) or not entry['command'].strip()):
                raise ValueError(f"{location}cache command must be a nonempty string, got {entry['command']!r}")
            if 'owner' in entry and not valid_owner(entry['owner']):
                raise ValueError(f"{location}owner must be one plain username (letters, digits, dot, dash, underscore; not root), got {entry['owner']!r}")
            if 'runner' in entry and type(entry['runner']) is not bool:
                raise ValueError(f"{location}runner must be boolean, got {entry['runner']!r}")
            if 'failed_days' in entry and (type(entry['failed_days']) is not int or entry['failed_days'] < entry.get('days', 0) or not entry.get('days')):
                raise ValueError(f"{location}failed_days must be an integer of at least days, and needs days, got {entry['failed_days']!r}")
            if 'clone' in entry and (type(entry['clone']) is not bool or entry['clone'] and (not entry.get('days') or 'command' in entry)):
                raise ValueError(f"{location}clone must be boolean and needs days and no command, got {entry['clone']!r}")
            if registry[name].kind == 'powershell' and ('failed_days' in entry or 'clone' in entry):
                raise ValueError(f'{location}failed_days and clone need a POSIX host')
            path = entry['path']
            parts = PurePosixPath(path).parts
            if path.startswith('/') and (any(c in parts[1] for c in '*?[')
                    or parts[1] == 'var' and len(parts) > 2 and any(c in parts[2] for c in '*?[')):
                raise ValueError(f'{location}cache paths must not glob temporary directory prefixes, got path={path!r}')
            key = path_key(path)
            if key[:2] == (True, 'tmp') or key[:3] == (True, 'var', 'tmp'):
                if entry.get('days', 0) < 7 or 'owner' not in entry:
                    raise ValueError(f"{location}temporary files require seven days and an owner, got path={path!r}, days={entry.get('days')!r}, owner={entry.get('owner')!r}")
            if is_windows_temp(path) and entry.get('days', 0) < 7:
                raise ValueError(f"{location}Windows temporary files require seven days, got path={path!r}, days={entry.get('days')!r}")
            if 'actions-runners' in path.casefold() and (not entry.get('runner') or entry.get('days', 0) < 2):
                raise ValueError(f"{location}runner entries require two days and an idle worker check, got path={path!r}, days={entry.get('days')!r}, runner={entry.get('runner')!r}")
    reclaim_hosts = data.get('reclaim_hosts', [name for name, host in registry.items() if host.kind != 'wsl'])
    if not isinstance(reclaim_hosts, list):
        raise ValueError(f'reclaim_hosts must be an array, got {reclaim_hosts!r}')
    for index, name in enumerate(reclaim_hosts):
        if not isinstance(name, str) or name not in registry:
            raise ValueError(f'reclaim_hosts[{index}]: unknown host: {name!r}; known hosts: {", ".join(sorted(registry))}')
    data['reclaim_hosts'] = reclaim_hosts
    for name, local in host_rules.items():
        if registry[name].ssh is not None:
            continue
        for tier in ('roots', 'archive', 'compact', 'cache'):
            for index, entry in enumerate(local.get(tier, [])):
                path = entry['path'] if tier == 'cache' else entry
                cleanup = PurePosixPath(Path(path).expanduser()).parts
                for key in ('nas_root', 'report_dir'):
                    output = PurePosixPath(data[key]).parts
                    if len(cleanup) <= len(output) and all(
                            fnmatch.fnmatchcase(part, pattern)
                            and (not part.startswith('.') or pattern.startswith('.'))
                            for part, pattern in zip(output, cleanup)):
                        raise ValueError(f'{name}.{tier}[{index}]: would clean up {key} {output_paths[key]!r}, got {path!r}')
    hosts.HOSTS.clear()
    hosts.HOSTS.update(registry)
    return data


def valid_owner(owner):
    return isinstance(owner, str) and owner != 'root' and USERNAME.fullmatch(owner) is not None


def has_control(path):
    return any(ord(c) < 32 or c == '\x7f' for c in path)


def plain(path):
    return not has_control(path) and path == path.strip()


def path_key(path):
    windows = path.startswith('%') or path[1:3] == ':\\'
    segments = path.replace('\\', '/').casefold().split('/') if windows else path.split('/')
    return path.startswith('/'), *(s for s in segments if s not in ('', '.'))


def valid_relative_path(path):
    return (isinstance(path, str) and bool(path) and path != '.' and not PurePosixPath(path).is_absolute()
            and '..' not in PurePosixPath(path).parts and not any(c in path for c in '\\:*?[') and plain(path)
            and str(PurePosixPath(path)) == path)


def root_or_home(path):
    normalized = PurePosixPath(path.replace('\\', '/'))
    parts = normalized.parts
    return (str(normalized) in ('.', '/', '//', '~', str(Path.home()))
            or str(normalized).upper() == '%USERPROFILE%'
            or len(parts) == 1 and len(parts[0]) == 2
            and parts[0][0].isascii() and parts[0][0].isalpha() and parts[0][1] == ':')


def valid_path(path):
    if not isinstance(path, str):
        return False
    if root_or_home(path):
        return False
    return path not in ('', '/', '~/', 'C:\\', 'c:\\') and plain(path) and '..' not in path.replace('\\', '/').split('/') and (
        path.startswith(('/', '~/', '%')) or (len(path) > 2 and path[1:3] == ':\\'))


def selected(used_pct, rules):
    return tuple(tier for tier in TIERS if tier != 'project' or used_pct >= rules['hard_pct'])


def enabled(rules, tier, apply):
    return apply and tier in rules['live']
