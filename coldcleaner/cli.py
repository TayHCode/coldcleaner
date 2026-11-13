import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import disk, doctor, fleet, hosts, metrics, protect, reclaim, report, store, rules, version

RETRY_SECONDS = 30


def measure(host, progress):
    try:
        return disk.measure(host)
    except Exception as exc:
        print(f'{host.name}: unreachable ({exc}); retrying in {RETRY_SECONDS}s', **progress)
        time.sleep(RETRY_SECONDS)
        return disk.measure(host)


def summary(reports, apply, path, code, status, errors, plan=None):
    def percent(usage):
        return None if usage is None else round(usage.percent, 2)
    return dict(status=status, mode='apply' if apply else 'dry-run', code=code, report=path and str(path),
                plan=plan and str(plan), errors=list(errors),
                categories=report.categories(reports),
                hosts=[dict(name=entry.name, disk_before_percent=percent(entry.before), disk_after_percent=percent(entry.after),
                            would_free_bytes=entry.would_free, acted_bytes=entry.acted_bytes, errors=entry.errors, notes=entry.notes,
                            skipped=sum(row['action'] == 'skip' for row in entry.actions),
                            actions=[row for row in entry.actions if row['action'] != 'skip'],
                            unlisted=entry.unlisted, unlisted_complete=entry.unlisted_complete)
                       for entry in reports])


def failure_reasons(reports, errors):
    reasons = list(errors)
    for entry in reports:
        reasons += [f'{entry.name}: {problem}' for problem in entry.errors]
        failed_rows = [row for row in entry.actions if row['action'] == 'error']
        if failed_rows:
            first = failed_rows[0]
            reasons.append(f"{entry.name}: {len(failed_rows)} error action(s), first {first['path']}: {first['reason']}")
    return reasons


def run(config, chosen_hosts, apply=False, *, as_json=False):
    run_started = datetime.now(timezone.utc)
    code = version.describe()
    progress = dict(file=sys.stderr if as_json else sys.stdout, flush=True)
    reports = []
    errors = []
    failed = False
    deadline = time.monotonic() + reclaim.RUN_SECONDS
    for host in chosen_hosts:
        entry = report.HostReport(host.name)
        reports.append(entry)
        if time.monotonic() >= deadline:
            entry.errors.append('not started: ' + reclaim.DEADLINE)
            failed = True
            continue
        print(f'{host.name}: inspect', **progress)
        try:
            entry.before = measure(host, progress)
        except Exception as exc:
            entry.errors.append('Host unreachable or disk measurement unavailable: ' + str(exc))
            failed = True
            continue
        try:
            if host.kind == 'wsl':
                entry.notes.append('Disk gating uses the Windows bridge C:, which contains the WSL virtual disk.')
                reclaim.Reclaimer(host, config, apply, None, entry).log('execution', '', 'skip', 0,
                    'Windows WSL execution is retired', rule=f'{host.name}.kind:wsl', idle_days=None)
            else:
                protection = protect.collect(host)
                entry.broad_references = sorted(path for path in protection.paths
                    if protect.broad_reference(path, protection.home, host.kind == 'powershell'))
                cleaner = reclaim.Reclaimer(host, config, apply, protection, entry)
                cleaner.deadline = deadline
                for tier in ('worktrees', 'clones', 'archives', 'unlisted'):
                    if time.monotonic() >= deadline:
                        entry.errors.append(f'{tier} not started: {reclaim.DEADLINE}')
                        failed = True
                        continue
                    started = time.monotonic()
                    print(f'{host.name}: {tier} start', **progress)
                    try:
                        getattr(cleaner, tier)()
                    except Exception as exc:
                        entry.errors.append(f'{tier} incomplete: {reclaim.describe(exc)}')
                        failed = True
                    items = sum(action['tier'] == tier.removesuffix('s') for action in entry.actions)
                    print(f'{host.name}: {tier} done, {items} items, {time.monotonic() - started:.0f}s', **progress)
        except Exception as exc:
            entry.errors.append('Protection inventory unavailable; cleanup skipped: ' + str(exc))
            failed = True
        finally:
            try:
                entry.after = disk.measure(host)
            except Exception as exc:
                entry.errors.append('Final disk measurement unavailable: ' + str(exc))
                failed = True
        if entry.errors or any(action['action'] == 'error' for action in entry.actions):
            failed = True
        alerts = []
        if entry.after and entry.after.percent >= config['alert_pct']:
            alerts.append(f"disk {entry.after.percent:.2f}% is at or above alert_pct {config['alert_pct']}%")
        if any(row['action'] == 'skip' and row['reason'] == reclaim.LIMIT_REACHED for row in entry.actions):
            alerts.append('deletion limit reached (max_items_per_run or max_gib_per_run); the rest waits for the next run')
        entry.attention = '; '.join(alerts)
    try:
        path = report.write(reports, config['report_dir'], apply, code, config.get('manual_notes', ()),
                            config.get('rules_sha256'), True, metrics_footer(config, reports if apply else ()))
    except OSError as exc:
        path, failed = None, True
        problem = 'Report not written: ' + str(exc)
        (reports[0].errors if reports else errors).append(problem)
    plan = None
    if path and not apply:
        try:
            plan = reclaim.write_plan(path.with_suffix('.plan.json'), reports, config.get('rules_sha256'))
        except OSError as exc:
            failed = True
            (reports[0].errors if reports else errors).append('Plan not written: ' + str(exc))
    if path and apply and config.get('attention_note'):
        try:
            report.announce(reports, config['report_dir'], config['attention_note'], path, run_started)
        except (OSError, ValueError) as exc:
            failed = True
            (reports[0].errors if reports else errors).append('Attention note not written: ' + str(exc))
    if path:
        try:
            fleet.write(config)
        except OSError as exc:
            print(f'coldcleaner: fleet summary not written: {exc}', file=sys.stderr, flush=True)
    if failed:
        for reason in failure_reasons(reports, errors):
            print('coldcleaner: FAILED: ' + reason, file=sys.stderr, flush=True)
    for entry in reports:
        if entry.attention:
            print(f'coldcleaner: ATTENTION: {entry.name}: {entry.attention}', file=sys.stderr, flush=True)
    if as_json:
        result = exit_code(failed, reports)
        status = {0: 'ok', 1: 'incomplete', 3: 'attention'}[result]
        print(json.dumps(summary(reports, apply, path, code, status, errors, plan), default=str))
        return result
    print(path or problem)
    if plan:
        print(f'Plan: {plan}')
    for entry in reports:
        acted = f'; acted on {report.size(entry.acted_bytes)}' if apply else ''
        print(f'{entry.name}: {report.usage(entry.before)} -> {report.usage(entry.after)}; would free {report.size(entry.would_free)}{acted}')
    return exit_code(failed, reports)


def metrics_footer(config, current):
    try:
        rows = metrics.render(metrics.compute(config['report_dir'], config['nas_root'], current=current))
    except Exception as exc:
        rows = ['Metrics unavailable: ' + report.cell(exc)]
    return ['## Metrics', '', *rows, '']


def exit_code(failed, reports):
    return 1 if failed else 3 if any(entry.attention for entry in reports) else 0


class PrintVersion(argparse.Action):
    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, default=argparse.SUPPRESS, help='Print the coldcleaner version and exit.')

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            number = version.number()
        except (OSError, ValueError, KeyError, ImportError) as exc:
            parser.exit(1, f'coldcleaner: version unknown: {exc}\n')
        print(f'coldcleaner {number}')
        parser.exit()


def positive(text):
    if not text.isdigit() or int(text) < 1:
        raise argparse.ArgumentTypeError(f'must be a positive whole number of days, got {text!r}')
    return int(text)


def parser():
    result = argparse.ArgumentParser(prog='coldcleaner', description='Free disk space from finished Git worktrees and idle listed folders. '
                                     'Cleanup is a dry run unless you pass --apply.')
    result.add_argument('--version', action=PrintVersion)
    commands = result.add_subparsers(dest='command', required=True)
    descriptions = {
        'reclaim': 'Remove finished Git worktrees and idle listed folders, after checking GitHub, running programs and coding agents and verifying an archive copy.',
        'status': 'Show disk usage per host and the last report.',
        'find': 'Search archives and their file lists.',
        'restore': 'Restore an archive to its original host or recover a legacy archive on a POSIX host.',
        'check-rules': 'Validate a rules file offline.',
        'doctor': 'Check prerequisites read-only and print PASS or FAIL for each.',
        'metrics': 'Print per-host cleanup metrics from the action log, reports and archive index.',
        'restore-drill': 'Restore one random archive into a scratch folder on this machine, check it against its file list and SHA-256s, '
                         'delete the copy and log pass or fail. Exit 1 on fail.',
        'approve': 'Approve items from a reclaim dry-run plan so reclaim --apply may act on them.',
    }
    for name, description in descriptions.items():
        command = commands.add_parser(name, help=description, description=description)
        command.add_argument('--rules', type=Path, default=rules.DEFAULT_PATH, help='Read configuration from this rules file.')
        if name in ('reclaim', 'status', 'doctor'):
            command.add_argument('--host', help='Select one host instead of all hosts.')
        if name == 'reclaim':
            command.add_argument('--apply', action='store_true', help='Perform actions enabled by the rules instead of a dry run.')
            command.add_argument('--json', action='store_true', help='Print one JSON summary on stdout and progress on stderr. Exit 0 when complete, 1 when incomplete, 2 when refused, 3 when complete but a host is at or above alert_pct.')
            command.add_argument('--i-reviewed', type=Path, metavar='REPORT',
                                 help='Allow --apply after reviewing this dry-run report, even if the rules changed since it was made.')
        if name == 'metrics':
            command.add_argument('--days', type=positive, default=metrics.DAYS, help=f'Count the last N days (default {metrics.DAYS}).')
        if name == 'approve':
            command.add_argument('plan', type=Path, help='The .plan.json file written next to a reclaim dry-run report.')
            command.add_argument('ids', nargs='+', metavar='ID', help='Item IDs from the plan, or all.')
        if name in ('reclaim', 'status', 'doctor', 'metrics', 'restore-drill', 'approve'):
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


def restore_drill(config, scratch):
    try:
        row = reclaim.drill(config['nas_root'], config['report_dir'], scratch)
    except Exception as exc:
        print(f'restore drill fail: {exc}')
        return 1
    reason = f" ({row['reason']})" if row['reason'] else ''
    print(f"restore drill {row['result']}: {row['host']} {row['id']} {row['archive']}{reason}")
    return 0 if row['result'] == 'pass' else 1


def refuse(args, message):
    if getattr(args, 'json', False):
        print(json.dumps(dict(status='refused', reason=message)))
    else:
        print(message)
    return 2


def unreviewed(config, selected, reviewed):
    names = [host.name for host in selected]
    if reviewed is not None:
        missing = [name for name in names if name not in report.dry_run_hosts(reviewed)]
        if missing:
            return f"coldcleaner: reclaim --apply refused: {reviewed} is not a complete reclaim dry-run report for {', '.join(missing)}"
        return None
    sha = config.get('rules_sha256')
    covered = set().union(*(report.dry_run_hosts(path, sha) for path in report.paths(config['report_dir'])))
    missing = [name for name in names if name not in covered]
    if missing:
        return (f"coldcleaner: reclaim --apply refused: no complete reclaim dry-run report in {config['report_dir']} with rules sha256 {sha} "
                f"for {', '.join(missing)}; run reclaim without --apply, review its report, then retry "
                '(or pass --i-reviewed REPORT)')
    return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        args = parser().parse_args(argv)
    except SystemExit as exc:
        if exc.code == 2 and '--json' in argv:
            print(json.dumps(dict(status='refused', reason='invalid arguments; see stderr')))
        raise
    try:
        config = rules.load(args.rules)
    except (OSError, ValueError) as exc:
        if args.command == 'check-rules':
            print(rules_problem(args.rules, exc))
            return 2 if isinstance(exc, OSError) else 1
        return refuse(args, rules_problem(args.rules, exc))
    for option in ('host', 'to_host'):
        name = getattr(args, option, None)
        if name is not None and name not in hosts.HOSTS:
            return refuse(args, f'coldcleaner: unknown --{option.replace("_", "-")} host: {name}; known hosts: {", ".join(sorted(hosts.HOSTS))}')
    if getattr(args, 'to_host', None) and hosts.HOSTS[args.to_host].kind != 'posix':
        return refuse(args, 'coldcleaner: --to-host requires a POSIX host')
    if args.command == 'reclaim' and args.apply and not {'worktree', 'clone', 'archive'} & set(config['live']):
        return refuse(args, 'coldcleaner: reclaim --apply refused: none of worktree, clone or archive is listed in live')
    if args.command == 'reclaim' and args.apply and not Path(config['nas_root']).is_dir():
        return refuse(args, f"coldcleaner: reclaim --apply refused: nas_root {config['nas_root']} does not exist; "
                            'create it on a network share (NFS or SMB) or under local_archive_mount (see docs/reference.md#archive-storage)')
    if args.command == 'check-rules':
        live = ', '.join(config['live']) or 'none'
        print(f"OK: {args.rules} (live: {live}; alert {config['alert_pct']}%)")
        return 0
    try:
        if getattr(args, 'report_dir', None):
            config['report_dir'] = str(args.report_dir.resolve())
        selected = [hosts.HOSTS[args.host]] if getattr(args, 'host', None) else list(hosts.HOSTS.values())
        if args.command in ('reclaim', 'doctor') and not args.host:
            selected = [hosts.HOSTS[name] for name in config['reclaim_hosts']]
        if args.command == 'doctor':
            return doctor.main(config, selected)
        if args.command == 'restore-drill':
            return restore_drill(config, Path.home() / '.cache' / 'coldcleaner' / 'restore-drill')
        if args.command == 'approve':
            chosen = reclaim.approve(config['report_dir'], args.plan, args.ids)
            print(f"approved {len(chosen)} items in {Path(config['report_dir']) / reclaim.APPROVALS}: {', '.join(chosen) or 'none'}")
            return 0
        if args.command == 'metrics':
            print('\n'.join(metrics.render(metrics.compute(config['report_dir'], config['nas_root'], args.days), args.days)))
            return 0
        if args.command == 'reclaim' and args.apply and (problem := unreviewed(config, selected, args.i_reviewed)):
            return refuse(args, problem)
        if args.command == 'reclaim':
            return run(config, selected, args.apply, as_json=args.json)
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
            paths = report.paths(config['report_dir'])
            print('Last report: ' + (str(paths[-1]) if paths else 'none'))
            for line in report.summarize(paths[-1]) if paths else ():
                print(line)
            return int(failed)
        if args.command == 'find':
            if not args.term:
                return refuse(args, 'coldcleaner: search term is empty')
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
