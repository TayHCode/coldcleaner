import os
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .disk import Usage

SKIP_ROWS = 20


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')


def size(value):
    return f'{value / 1024**3:.2f} GiB ({value} bytes)'


def usage(value):
    return 'unavailable' if value is None else f'{value.percent:.2f}% ({size(value.used)} of {size(value.total)})'


@dataclass
class HostReport:
    name: str
    before: Usage | None = None
    after: Usage | None = None
    actions: list = field(default_factory=list)
    repos: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    summary: object = ''
    broad_references: list = field(default_factory=list)

    @property
    def would_free(self):
        return sum(row['bytes'] for row in self.actions if row['action'].startswith('would ') and row['tier'] not in ('github', 'nas'))

    @property
    def acted_bytes(self):
        return sum(row['bytes'] for row in self.actions
                   if not row['action'].startswith('would ')
                   and row['action'] not in ('skip', 'error', 'report only', 'unreadable')
                   and row['tier'] not in ('github', 'nas'))


def action_table(lines, rows):
    lines.extend(['', '| Tier | Action | Path | Bytes | Reason |', '| --- | --- | --- | ---: | --- |'])
    for row in rows:
        values = [row[key] for key in ('tier', 'action', 'path', 'bytes')]
        values.append('; '.join(filter(None, (row['reason'], row.get('age', '')))))
        lines.append('| ' + ' | '.join(map(cell, values)) + ' |')


def render(reports, apply=False, code=None):
    now = datetime.now(timezone.utc)
    lines = [f'# coldcleaner {now:%Y-%m-%d %H:%M:%S} UTC', '',
             f'Mode: {"apply, limited to live tiers" if apply else "dry run"}. Byte estimates are logical file sizes, not guaranteed free space.', '']
    if code:
        lines[2:2] = [f'Code: {code}', '']
    for report in reports:
        lines.extend([f'## {report.name}', '', f'Before: {usage(report.before)}', '',
                      f'After: {usage(report.after)}', '', f'Would free: {size(report.would_free)}', ''])
        if apply:
            lines.extend([f'Acted on: {size(report.acted_bytes)}', ''])
        lines.extend(f'- {cell(error)}' for error in report.errors)
        lines.extend(f'- Note: {cell(note)}' for note in report.notes)
        if report.broad_references:
            lines.extend(['', 'Broad scheduler references, equality only: '
                          + ', '.join(map(cell, report.broad_references)), ''])
        skips = [row for row in report.actions if row['action'] == 'skip']
        action_table(lines, [row for row in report.actions if row['action'] != 'skip'])
        lines.extend(['', f'### Skipped: {len(skips)}', '', '| Reason | Count | Bytes |', '| --- | ---: | ---: |'])
        reasons = Counter(row['reason'] for row in skips)
        for reason, count in reasons.most_common():
            lines.append(f"| {cell(reason)} | {count} | {sum(row['bytes'] for row in skips if row['reason'] == reason)} |")
        lines.extend(['', f'Largest {SKIP_ROWS} skipped:'])
        action_table(lines, sorted((row for row in skips if not row.get('age')),
                                   key=lambda row: row['bytes'], reverse=True)[:SKIP_ROWS])
        cache_skips = [row for row in skips if row.get('age')]
        if cache_skips:
            lines.extend(['', 'All skipped cache candidates with age:'])
            action_table(lines, cache_skips)
        lines.extend(['', '### Not on GitHub', '', '| Path | Verdict | Dirty | Untracked | Unpushed | Stashes |', '| --- | --- | ---: | ---: | --- | ---: |'])
        for repo in report.repos:
            if repo.verdict != 'on_github':
                lines.append('| ' + ' | '.join(map(cell, (repo.path, repo.verdict, len(repo.dirty_files), len(repo.untracked_files), sum(ref != 'HEAD' for ref in repo.unpushed_branches), repo.stash_count))) + ' |')
        if report.summary:
            lines.extend(['', str(report.summary)])
        lines.append('')
    lines.extend(['## Manual fixes, report only', '',
                  '- Windows Google DriveFS cache at `%LOCALAPPDATA%\\Google\\DriveFS` was previously measured at 362 GB. Switch Google Drive to Stream files after reviewing offline needs.',
                  '- Review Ollama and llama.cpp model downloads manually.',
                  '- Review Mac Messages attachments manually.', ''])
    return '\n'.join(lines)


def write(reports, directory, apply=False, code=None):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f'{datetime.now(timezone.utc):%Y-%m-%d-%H%M%S-%f}-{uuid.uuid4().hex}.md'
    temporary = path.with_suffix(f'.{os.getpid()}.tmp')
    try:
        temporary.write_text(render(reports, apply, code), encoding='utf-8', errors='backslashreplace')
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def total(lines, label):
    found = [int(match.group(1)) for line in lines if (match := re.fullmatch(rf'{label}: .*\((\d+) bytes\)', line))]
    return size(sum(found)) if found else None


def summarize(path):
    try:
        lines = Path(path).read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return ['  Could not read this report.']
    written = re.fullmatch(r'# coldcleaner (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC)', lines[0]) if lines else None
    mode = next((m.group(1) for line in lines if (m := re.match(r'Mode: (apply|dry run)\b', line))), None)
    parts = [('Written', written and written.group(1)), ('Mode', mode),
             ('Would free', total(lines, 'Would free')), ('Acted on', total(lines, 'Acted on'))]
    return [f'  {label}: {value}' for label, value in parts if value]
