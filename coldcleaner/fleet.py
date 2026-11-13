import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from . import metrics, reclaim, report, rules

RUNS = 30
TOP = 5
NAME = Path('fleet', 'summary.md')
BARS = '▁▂▃▄▅▆▇█'


def recent_runs(directory):
    runs = []
    for path in reversed(report.paths(directory)):
        usage = metrics.apply_usage(path)
        if usage is not None:
            runs.append((metrics.written(path), usage))
            if len(runs) > RUNS:
                break
    runs.reverse()
    return (runs[0][0], runs[1:]) if len(runs) > RUNS else (None, runs)


def held_now(rows, directory):
    latest = {}
    for row in rows:
        if row['tier'] in metrics.TIERS and row['action'] != 'error':
            latest[row['host'], row['path']] = row
    state = report.held_state(Path(directory) / 'held.json')
    found = defaultdict(list)
    for (host, path), row in latest.items():
        if report.held(row) and (host not in state or path in state[host][1]):
            found[host].append(row)
    return found


def reclaimed(rows, since, runs):
    found = defaultdict(int)
    until = runs[-1][0] if runs else None
    for row in rows:
        if (until and row['tier'] in metrics.TIERS and report.acted(row)
                and (since is None or row['at'] > since) and row['at'] <= until):
            found[row['host']] += row['bytes']
    return found


def sparkline(values):
    low, high = min(values), max(values)
    return ''.join(BARS[round((value - low) / (high - low) * (len(BARS) - 1)) if high > low else 3] for value in values)


def disk_cells(values):
    if not values:
        return ['no apply runs', 'n/a', 'n/a', 'n/a']
    return [f'{sparkline(values)} ({len(values)} runs)', *(f'{value:.2f}%' for value in (values[-1], min(values), max(values)))]


def policy_cells(host_rules):
    if host_rules is None:
        return ['not configured', '', '']
    overrides = [f'{pattern} {days} days' for pattern in rules.archive_patterns(host_rules)
                 if (days := rules.archive_entry(host_rules, pattern)['days']) is not None]
    return [len(host_rules.get('roots', [])), len(rules.archive_patterns(host_rules)), ', '.join(overrides) or 'none']


def policy(config):
    merged = min(config['worktree_idle_days'], reclaim.WORKTREE_MERGED_DAYS)
    return (f"Policy: live = {', '.join(config['live']) or 'none'}; worktree idle {config['worktree_idle_days']} days "
            f"({merged} once merged); archive idle {config['archive_idle_days']} days (at least 7 for system temp folders).")


def held_section(name, rows):
    lines = [f'### {name}', '', '| Held because | Worktrees | GiB | To release |', '| --- | ---: | ---: | --- |']
    for reason, todo in report.HELD.items():
        matched = [row for row in rows if report.held(row) == reason]
        if matched:
            lines.append(f"| {reason} | {len(matched)} | {metrics.gib(sum(row['bytes'] for row in matched))} | {todo} |")
    lines.extend(['', f'Top {TOP} held directories:', '', '| Path | GiB | Reason |', '| --- | ---: | --- |'])
    for row in sorted(rows, key=lambda row: (-row['bytes'], row['path']))[:TOP]:
        lines.append('| ' + ' | '.join(map(report.cell, (row['path'], metrics.gib(row['bytes']), row['reason']))) + ' |')
    return lines + ['']


def render(config, now=None):
    now = now or datetime.now(timezone.utc)
    directory = config['report_dir']
    since, runs = recent_runs(directory)
    rows = metrics.actions(directory)
    held, acted = held_now(rows, directory), reclaimed(rows, since, runs)
    names = list(config['reclaim_hosts'])
    names += sorted(({name for _, usage in runs for name in usage} | set(held) | set(acted)) - set(names))
    window = f'the last {len(runs)} reclaim --apply runs (from {runs[0][0]:%Y-%m-%d})' if runs else 'no reclaim --apply runs yet'
    start = ('' if since or not runs else ' With 30 or fewer apply reports there is no earlier report to start from, '
             'so reclaimed counts every logged action up to the newest one, including any from before these runs.')
    lines = ['# coldcleaner fleet', '', f'Updated {now:%Y-%m-%d %H:%M} UTC. Disk used (after each run) and reclaimed cover {window}.{start} '
             'Held is the current state from the action log and held.json.', '', policy(config), '',
             '| Host | Disk used | Latest | Min | Max | Reclaimed GiB | Held | Held GiB | Roots | Archive patterns | Archive days overrides |',
             '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |']
    for name in names:
        values = [usage[name][1][0] for _, usage in runs if name in usage]
        cells = [name, *disk_cells(values), metrics.gib(acted[name]), len(held[name]),
                 metrics.gib(sum(row['bytes'] for row in held[name])), *policy_cells(config['hosts'].get(name))]
        lines.append('| ' + ' | '.join(map(report.cell, cells)) + ' |')
    lines.extend(['', '## Held for a person', ''])
    for name in names:
        if held[name]:
            lines.extend(held_section(name, held[name]))
    if not any(held.values()):
        lines.extend(['None.', ''])
    return lines


def write(config, now=None):
    try:
        lines = render(config, now)
    except Exception as exc:
        lines = ['# coldcleaner fleet', '', 'Fleet summary unavailable: ' + report.cell(exc), '']
    path = Path(config['report_dir']) / NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f'.{os.getpid()}.tmp')
    try:
        temporary.write_text('\n'.join(lines) + '\n', encoding='utf-8', errors='backslashreplace')
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path
