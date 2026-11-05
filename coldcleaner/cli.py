import argparse
import json
import re
import sys
import time
from pathlib import Path

from . import disk, gitsafe, hosts, protect, reclaim, report, rules, store, tiers, version


def summary(reports, apply, path, code, failed, errors):
    def percent(usage):
        return None if usage is None else round(usage.percent, 2)
    return dict(status='incomplete' if failed else 'ok', mode='apply' if apply else 'dry-run', code=code, report=path and str(path), errors=list(errors),
                hosts=[dict(name=entry.name, disk_before_percent=percent(entry.before), disk_after_percent=percent(entry.after),
                            would_free_bytes=entry.would_free, acted_bytes=entry.acted_bytes, errors=entry.errors, notes=entry.notes,
                            skipped=sum(row['action'] == 'skip' for row in entry.actions),
                            actions=[row for row in entry.actions if row['action'] != 'skip'])
                       for entry in reports])


def run(config, chosen_hosts, apply=False, github_only=False, *, reclaim_only=False, as_json=False):
    code = version.describe()
    progress = dict(file=sys.stderr if as_json else sys.stdout, flush=True)
    reports = []
    errors = []
    failed = False
    for host in chosen_hosts:
        print(f'{host.name}: inspect', **progress)
        entry = report.HostReport(host.name)
        reports.append(entry)
        try:
            if not github_only:
                entry.before = disk.measure(host)
        except Exception as exc:
            entry.errors.append('Host unreachable or disk measurement unavailable: ' + str(exc))
            failed = True
            continue
        try:
            if host.kind == 'wsl':
                entry.notes.append('Disk gating uses the Windows bridge C:, which contains the WSL virtual disk.')
                entry.actions.append(dict(tier='execution', path='', action='skip', bytes=0,
                    reason='Windows WSL execution is retired'))
            else:
                protection = protect.collect(host) if not github_only else None
                if protection is not None:
                    entry.broad_references = sorted(path for path in protection.paths
                        if protect.broad_reference(path, protection.home, host.kind == 'powershell'))
                cleaner = (reclaim.Reclaimer(host, config, apply, protection, entry) if reclaim_only else
                           tiers.Cleaner(host, config, apply, protection, entry, gitsafe, store))
                selected = ('worktrees', 'archives') if reclaim_only else ('github',) if github_only else rules.selected(entry.before.percent, config)
                for tier in selected:
                    started = time.monotonic()
                    print(f'{host.name}: {tier} start', **progress)
                    try:
                        getattr(cleaner, tier)()
                    except Exception as exc:
                        entry.errors.append(f'{tier} incomplete: {tiers.describe(exc)}')
                        failed = True
                    items = sum(action['tier'] == (tier.removesuffix('s') if reclaim_only else tier) for action in entry.actions)
                    print(f'{host.name}: {tier} done, {items} items, {time.monotonic() - started:.0f}s', **progress)
        except Exception as exc:
            entry.errors.append('Protection inventory unavailable; cleanup skipped: ' + str(exc))
            failed = True
        finally:
            if not github_only:
                try:
                    entry.after = disk.measure(host)
                except Exception as exc:
                    entry.errors.append('Final disk measurement unavailable: ' + str(exc))
                    failed = True
        if entry.errors or any(action['action'] == 'error' for action in entry.actions):
            failed = True
        if entry.after and entry.after.percent >= config['alert_pct']:
            failed = True
    if not github_only and not reclaim_only and reports:
        cap_live = apply and bool({'archive', 'project'} & set(config['live']))
        try:
            records = store.enforce_cap(config['nas_root'], config['nas_cap_gb'] * 1024**3, apply=cap_live)
            for record in records:
                reports[0].actions.append(dict(tier='nas', path=record.archive_path,
                    action='expire archive' if cap_live else 'would expire archive', bytes=record.archive_bytes, reason='NAS cap'))
        except Exception as exc:
            reports[0].errors.append('NAS cap check incomplete: ' + str(exc))
            failed = True
    if github_only:
        print(report.render(reports, apply))
    else:
        try:
            path = report.write(reports, config['report_dir'], apply, code)
        except OSError as exc:
            path, failed = None, True
            problem = 'Report not written: ' + str(exc)
            (reports[0].errors if reports else errors).append(problem)
        if as_json:
            print(json.dumps(summary(reports, apply, path, code, failed, errors), default=str))
            return int(failed)
        print(path or problem)
        for entry in reports:
            acted = f'; acted on {report.size(entry.acted_bytes)}' if apply else ''
            print(f'{entry.name}: {report.usage(entry.before)} -> {report.usage(entry.after)}; would free {report.size(entry.would_free)}{acted}')
    return int(failed)


def parser():
    result = argparse.ArgumentParser(prog='coldcleaner')
    commands = result.add_subparsers(dest='command', required=True)
    descriptions = {
        'run': 'Preview legacy tiers. Apply cleanup with reclaim instead.',
        'reclaim': 'Reclaim agent work and staging with current GitHub, process, T3 and verified NAS proofs; exclude package caches.',
        'status': 'Show disk usage per host and the last report.',
        'github': 'Inspect Git repositories and preview GitHub backups.',
        'find': 'Search NAS archives and their file lists.',
        'restore': 'Restore an archive to its original host or recover a legacy archive on a POSIX host.',
        'check-rules': 'Validate a rules file offline.',
    }
    for name, description in descriptions.items():
        command = commands.add_parser(name, help=description, description=description)
        command.add_argument('--rules', type=Path, default=rules.DEFAULT_PATH, help='Read configuration from this rules file.')
        if name in ('run', 'reclaim', 'github', 'status'):
            command.add_argument('--host', help='Select one host instead of all hosts.')
        if name in ('run', 'reclaim', 'github'):
            command.add_argument('--apply', action='store_true', help='Perform actions enabled by the rules instead of a dry run.')
        if name == 'reclaim':
            command.add_argument('--json', action='store_true', help='Print one JSON summary on stdout and progress on stderr. Exit 0 when complete, 1 when incomplete, 2 when refused.')
        if name in ('run', 'reclaim', 'status'):
            command.add_argument('--report-dir', type=Path, help='Use this directory for cleanup reports.')
        if name == 'find':
            command.add_argument('term', help='Search archive records and file paths for this text.')
        if name == 'restore':
            command.add_argument('id', help='Restore the archive with this ID.')
            command.add_argument('--to', help='Replace the archived root with this path, including with --member.')
            command.add_argument('--member', help='Restore only this path within the archive.')
            command.add_argument('--to-host', help='Recover a legacy archive on this POSIX host. Requires --to.')
    return result


def rules_problem(path, exc):
    return f'coldcleaner: {path}: ' + ' '.join(str(exc).splitlines())


def pressure_note(usage, config):
    if usage.percent >= config['hard_pct']:
        return f"  (at or above hard limit {config['hard_pct']}%: project cleanup is included)"
    if usage.percent >= config['alert_pct']:
        return f"  (at or above alert level {config['alert_pct']}%)"
    return ''


def print_archive(record):
    print(f'{record.id}  {record.host}:{record.source_path}  '
          f'archived {record.archived_at}  {record.status}  '
          f'{record.file_count} files, {report.size(record.original_bytes)} '
          f'({report.size(record.archive_bytes)} stored)')
    for member in record.matches:
        print(f'  member {member}')


def refuse(args, message):
    if getattr(args, 'json', False):
        print(json.dumps(dict(status='refused', reason=message)))
    else:
        print(message)
    return 2


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        args = parser().parse_args(argv)
    except SystemExit as exc:
        if exc.code == 2 and '--json' in argv:
            print(json.dumps(dict(status='refused', reason='invalid arguments; see stderr')))
        raise
    if args.command == 'run' and args.apply:
        return refuse(args, 'coldcleaner: legacy run --apply is disabled; use reclaim --apply')
    try:
        config = rules.load(args.rules)
    except (OSError, ValueError) as exc:
        if args.command == 'check-rules':
            print(rules_problem(args.rules, exc))
            return 1
        return refuse(args, rules_problem(args.rules, exc))
    for option in ('host', 'to_host'):
        name = getattr(args, option, None)
        if name is not None and name not in hosts.HOSTS:
            return refuse(args, f'coldcleaner: unknown --{option.replace("_", "-")} host: {name}; known hosts: {", ".join(sorted(hosts.HOSTS))}')
    if getattr(args, 'to_host', None) and hosts.HOSTS[args.to_host].kind != 'posix':
        return refuse(args, 'coldcleaner: --to-host requires a POSIX host')
    if args.command == 'reclaim' and args.apply and not {'worktree', 'archive'} & set(config['live']):
        return refuse(args, 'coldcleaner: reclaim --apply refused: neither worktree nor archive is listed in live')
    if args.command == 'check-rules':
        live = ', '.join(config['live']) or 'none'
        print(f"OK: {args.rules} (live: {live}; alert {config['alert_pct']}%, hard {config['hard_pct']}%)")
        return 0
    try:
        if getattr(args, 'report_dir', None):
            config['report_dir'] = str(args.report_dir.resolve())
        selected = [hosts.HOSTS[args.host]] if getattr(args, 'host', None) else list(hosts.HOSTS.values())
        if args.command == 'reclaim':
            if not args.host:
                selected = [hosts.HOSTS[name] for name in config['reclaim_hosts']]
            return run(config, selected, args.apply, reclaim_only=True, as_json=args.json)
        if args.command in ('run', 'github'):
            return run(config, selected, args.apply, args.command == 'github')
        if args.command == 'status':
            failed = False
            code = version.describe()
            if code:
                print(f'Code: {code}')
            for host in selected:
                try:
                    usage = disk.measure(host)
                    print(f'{host.name}: {report.usage(usage)}{pressure_note(usage, config)}')
                except Exception as exc:
                    print(f'{host.name}: unavailable ({exc})')
                    failed = True
            paths = sorted((path for path in Path(config['report_dir']).glob('????-??-??*.md')
                            if re.fullmatch(r'\d{4}-\d{2}-\d{2}(?:-\d{6}-\d{6}-[0-9a-f]{32})?\.md', path.name)),
                           key=lambda path: path.stem)
            print('Last report: ' + (str(paths[-1]) if paths else 'none'))
            for line in report.summarize(paths[-1]) if paths else ():
                print(line)
            return int(failed)
        if args.command == 'find':
            records = store.find(args.term, config['nas_root'])
            for record in records:
                print_archive(record)
            if not records:
                print(f'no archives match {args.term!r}')
        elif args.command == 'restore':
            record = store.restore(args.id, config['nas_root'], to=args.to, member=args.member, to_host=args.to_host)
            target = args.to if args.to is not None else record.source_path
            suffix = f' (member {args.member})' if args.member is not None else ''
            print(f'restored {record.id} to {record.host}:{target}{suffix}')
        return 0
    except Exception as exc:
        return refuse(args, f'coldcleaner: {exc}')
