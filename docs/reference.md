# coldcleaner reference

The [README](../README.md) covers installing, the one-machine quick start and turning cleanup on. This page has the details.

## Other ways to install

`pipx install .` works when Python 3.14 is installed. Inside an active Python 3.14 virtual environment, pip installs it too:

```sh
python3 -m pip install .
```

With Python 3.14 as `python3`, you can also run it from the repository folder without installing:

```sh
python3 -m coldcleaner --help
```

Under an older Python it exits 2 with `coldcleaner needs Python 3.14+ (found 3.12)` before doing anything. `python3 -m coldcleaner --version` prints the version from `pyproject.toml` (an installed copy prints its package version). Releases are tagged `v<version>`. Coldcleaner uses only Python's standard library.

## The rules file

An installed copy reads `~/.config/coldcleaner/rules.toml` (or `$XDG_CONFIG_HOME/coldcleaner/rules.toml`). Running from a repository folder that has its own `rules.toml` uses that file. Every command accepts `--rules PATH` to read another file.

The example writes reports to `~/.local/state/coldcleaner/reports` and sets `nas_root` to `~/.local/share/coldcleaner/archive`, so a dry run works as any user. Archiving refuses until `nas_root` is on network storage or under `local_archive_mount` ([Archive storage](#archive-storage)), and `reclaim --apply` exits 2 without touching any host while `nas_root` does not exist. The example has one local host, `live = []`, and no cleanup paths.

### Hosts

Each `[hosts.<name>]` table needs `kind` (`posix`, `powershell` or `wsl`) and accepts `ssh` (an SSH destination) and `distro`. A `posix` host without `ssh` runs on this machine. `powershell` and `wsl` hosts need `ssh`, because the controller (the machine running coldcleaner) runs on Linux or macOS. The example file has commented remote POSIX and Windows hosts. `reclaim_hosts` lists the hosts that `reclaim` cleans by default; without it, every configured host except WSL.

Rules files written before hosts moved into configuration are refused until every host table declares `kind`. Add `ssh = "<destination>"` to each remote host, because a table without `ssh` runs on this machine.

Remote macOS hosts need Bash 3.2 and Python 3.9 or newer. Native Windows uses PowerShell. Compression always happens on the controller.

A host can list `shared_roots` for shared disk folders such as `/srv/shared`. A scheduler reference to that folder protects the folder itself; references to its children still protect those children.

## What reclaim removes

`coldcleaner reclaim` cleans the `reclaim_hosts` (or one `--host`). It is a dry run unless you add `--apply`, and `--apply` acts only on tiers listed in `live`. Each report records `Rules: sha256 <hash>` of the rules file bytes. A `reclaim` dry run also writes `Reclaim dry run complete for: <hosts>`, naming each host that ran without errors. `--apply` exits 2 without touching any host unless `report_dir` (or `--report-dir`) holds such reports with the current hash for every selected host; several dry runs add up. Reports from the removed `run` command and failed hosts never count. `--i-reviewed REPORT` instead accepts one such report that covers every selected host, whatever rules it was made with. WSL and package caches are out of scope. A rules file with a `cache` or `cache_tools` table, `cache_idle_days` or `cache` in `live` is rejected with `removed; caches are out of scope`.

**Worktrees** (`worktree` tier). Git worktrees under the host's `roots`. A worktree is removed only after a fresh check against GitHub shows that its current head is published and either merged or the head of a closed pull request. A merged worktree must be idle 1 day (or `worktree_idle_days`, if lower); one whose pull request was closed without merging must be idle `worktree_idle_days` (7 in the example). Coldcleaner runs `git worktree remove` and deletes the local branch, unless the worktree is detached or another worktree has that branch checked out. Ignored files inside are archived first, with a Git recovery bundle, so a full restore recreates a usable repository.

**Archive folders** (`archive` tier). Paths and glob patterns listed under the host's `archive`, once idle `archive_idle_days` (4 in the example). System temp folders (`/tmp`, `/var/tmp`, Windows `AppData\Local\Temp` and `Windows\Temp`) need at least 7 idle days. Each is archived, every file's SHA-256 checksum is compared with the original, and only then is the source deleted. An entry may be a table, `{ path = "...", days = 30, backup = "nas", exclude = ["..."] }`: `days` replaces `archive_idle_days` for that pattern (the 7-day temp minimum still applies). `exclude`, and the host's own `exclude` list, drop any match that equals, sits inside or holds an excluded path. `backup` is `nas` (the default) or `none-if-regenerable`, which needs a path ending in `node_modules`, `.venv`, `venv`, `target`, `dist`, `build`, `__pycache__`, `.cache` or `.next`. Both values still archive and verify the copy before deletion. `category` tags the pattern for the report's totals: `scratch` (the default, also for plain string entries), `test-output` or `artifact`. When several patterns match the same path, the first tagged one wins over untagged ones; a pattern that only matches a folder's contents does not tag the folder. An `artifact` path, such as an agent transcript, is held unless the top-level `memory_store` folder (ColdVault first) holds its preservation receipt: `<memory_store>/<sha256 of "HOST:PATH">.json`, exactly `{"schema_version": 1, "host": HOST, "path": PATH, "sha256": HASH}`. HASH is the original's content hash: a file's SHA-256, or for a folder the SHA-256 of the JSON list of sorted `[member, SHA-256 or null]` pairs, members named from the folder's parent. It must match the verified archive copy before deletion. An entry with `preservation = "summary"` instead needs `"summary": WHERE` in place of `"sha256"`, an explicit rule that the store's summary is enough. Without `memory_store`, artifact paths are never removed. No `archive` or `roots` rule may cover `memory_store`.

The legacy `run` and `github` commands, the `project`, `compact` and `github` tiers and the archive storage cap are removed. A rules file that still sets `hard_pct`, `project_idle_days`, `compact_idle_days`, `compact_weekday`, `nas_cap_gb`, `regenerable_paths`, a host `compact` list or one of those tiers in `live` is rejected with `removed with the legacy run tiers; delete <keys>`, naming each key.

## Protections in detail

Reclaim keeps a candidate when any of these is true. An incomplete check also keeps it.

- **Git work not on GitHub.** Dirty files, unpushed commits, open pull requests, and published heads that are neither merged nor the head of a closed pull request. A stash holds the main checkout only; removing a linked worktree preserves the repository's shared stash. Coldcleaner never force-pushes and never creates GitHub repositories.
- **Schedulers.** Paths named by systemd units and timers, crontab, launchd or Task Scheduler. Broad references such as your home folder, `/` or `C:\` protect only that exact path. A system unit link whose target no longer exists is skipped when systemd reports that unit as not loaded (`LoadState=not-found`), since it schedules nothing; any other unreadable scheduler file makes the check incomplete.
- **Running programs.** Files open in a running program, and their parent folders, and the working folders and command lines of running programs. Each live batch takes a fresh snapshot. On Linux and macOS this needs root or passwordless sudo ([README](../README.md#sudo)).
- **Coding agents.** Worktrees in use by T3 Code (a desktop app that runs coding agents), the Codex CLI or Claude Code. Coldcleaner reads each agent's local state: T3 Code's `~/.t3/userdata/statev2.sqlite`, Codex's newest `~/.codex/state_N.sqlite` and every `cwd` in Claude Code's `~/.claude/projects/**/*.jsonl` session files. Active T3 runs, pinned or unsettled T3 threads, unarchived Codex threads updated within the tier's idle days, and Claude Code sessions whose file changed within the tier's idle days keep their worktrees. An absent agent is noted once per host (`T3 not installed`). If that state cannot be read, for example after an agent upgrade changes it, every candidate on the host is kept with one `IN USE: <agent> state unreadable` reason. Codex and Claude Code sessions whose folder is the home folder or `/` protect only that folder.
- **`.keep-local`.** Any folder with a `.keep-local` file in it or above it.
- **`.coldcleaner-lease`.** Any agent can claim a folder until a time: write one UTC time such as `2026-12-01T00:00:00Z` to `.coldcleaner-lease` in the folder. Until then, that folder, everything inside it and any candidate containing it are kept. An expired lease is ignored; a lease that cannot be read or parsed protects like an unexpired one.
- **Artifact markers.** A Cold Stack artifact marker (`.cold-artifact.json` inside a folder, `<file>.cold-artifact.json` beside a file) in, above or inside a candidate keeps it while its `retention.policy` is `keep` or its `temporary` `expires` time is still ahead. A marker that is not a regular file, cannot be read or breaks the schema (`schema_version` 1) also keeps it. An expired `temporary` marker still keeps it while its `owner` is running: a process with a command-line word whose last path part, before its first dot, equals the owner (case-insensitive: `coldcontribute`, `/opt/coldcontribute.py` and `-m coldcontribute.fix` all count), or a process list that cannot be read (including a Linux `/proc` mounted with `hidepid` when the probe is not root; macOS reads it through `sudo`). Windows protected system processes, whose command lines no one can read, are not checked; they are operating-system processes, not products. On a Windows host, a product running inside WSL is not detected by the owner-running hold (#214). This can over-hold: any process whose arguments contain the owner's name, such as an editor or shell in a folder named after it, keeps that owner's expired artifacts for that run. Once a `temporary` marker expires and its owner is not running, the owner has abandoned the artifact, and the tier's own rules apply: ColdContribute's receipts on ops (`~/.local/state/coldcontribute/fix/OWNER/REPO/ISSUE`) are then archived, verified and deleted like any archive folder once idle 30 days; an unmarked receipt waits the same 30 idle days.
- **Protected locations.** Rules that overlap one fail to load. On the host, the check refuses any candidate that is inside, equal to or holding one: `/etc`, `/usr`, `/System`, `/mnt/shared-memory`, `C:\Windows` (its `Temp` stays allowed), `Program Files*`, the home folder's `Documents`, `Desktop`, `Pictures`, `Library`, `iCloud Drive`/`iCloudDrive`, `Google Drive` and `OneDrive*`, any folder holding `.obsidian`, and the paths in the host's `protected` list (no globs). The host check also covers glob expansions that the rules check cannot see.
- **Recent changes.** Anything changed within its idle window.
- **File system details.** Mount points and nested file systems. Windows files with alternate data streams. POSIX ACLs, extended attributes, special modes and files owned by other users (the macOS `com.apple.provenance` and `com.apple.quarantine` stamps hold no user data and are the only attributes allowed).
- **Never in scope.** Remote branches, GitHub repositories, registered VM disks, containers, Docker volumes and services other than coldcleaner's own timer. Reclaim never expires archives.

Archive copies keep Windows owner, group and DACL descriptors, and POSIX ownership, modes and timestamps. Checks run again just before removal; they do not lock paths against programs that start writing afterwards.

### Windows and WSL

Native Windows reclaim needs every running program's command line. An unreadable command line blocks cleanup. Only the probe itself, kernel processes with PIDs 0 and 4, and processes that Windows reports as protected (for example `lsass.exe`, `Registry`, `LsaIso.exe` and Defender), whose command line and executable path are both unreadable, are left out.

While the WSL virtual machine runs, the Windows check reads the open files of every process inside each running WSL distro, as root and read-only, and maps drive mounts such as `/mnt/c` to Windows paths, so Windows data a WSL job uses stays protected. If that read fails, Windows reclaim is incomplete. The Windows Sandbox template VM counts only while no sandbox session runs. WSL is never stopped.

Running cleanup inside WSL is retired. Runs report its tiers as skipped and keep reporting disk pressure on `C:`. Old WSL archives can still be restored with `restore ID --to-host HOST --to PATH` on a POSIX host.

## Archive storage

Archives go under `nas_root` as `<host>/<YYYY-MM-DD>/<name>.tar.zst`, with a `<name>.files.txt` list of every path and an `INDEX.csv` of all archives. The name comes from NAS (network-attached storage). By default the folder must be on an NFS or SMB network share.

A reclaim copy stays marked `attempt.creating`, and listed in `<nas_root>/.attempts/`, until its `INDEX.csv` row is written. The next copy to that `nas_root` deletes any listed, marked folder without a row. It reads only that list, not every archive folder. A retry whose source, permissions and Git head are unchanged reuses the indexed copy after a fresh test-read instead of copying again.

To archive to an external or second internal drive instead, mount it and name its mount point:

```toml
nas_root = "/mnt/backup/coldcleaner"
local_archive_mount = "/mnt/backup"
```

The same verification applies. `local_archive_mount` replaces the network-share check with these: the drive must be mounted at that exact path, the archive folder (after following symlinks) must be on it, it must be a different file system than `/`, it must not be memory-backed (`tmpfs`, `ramfs`), and it must not be the file system of the data being removed.

This mode only supports data on the controller. While it is set, archive candidates and worktrees with ignored data on any other host are left in place with an error in the report, because that host cannot recheck the drive before removal. Use a network share (leave `local_archive_mount` empty) for those hosts. The archive is checked again right before each removal, so an unplugged drive stops the run instead of filling an empty mount folder.

## Run it every night

Review a dry-run report first, then add the tiers you want to `live`, for example `live = ["worktree", "archive"]`. Run the commands below from the shell you used for the quick start. `command -v coldcleaner gh` must print both paths: the scheduled run reuses that shell's `PATH`, the installed `coldcleaner` and your rules file.

On Linux, install a systemd user timer (04:30 local time):

```sh
config="${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner"
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/coldcleaner.service <<EOF
[Unit]
Description=coldcleaner nightly reclaim

[Service]
Type=oneshot
Environment="PATH=$PATH"
ExecStart="$(command -v coldcleaner)" reclaim --apply --rules "$config/rules.toml"
SuccessExitStatus=3
Nice=10
IOSchedulingClass=idle
EOF
cat > ~/.config/systemd/user/coldcleaner.timer <<EOF
[Unit]
Description=Nightly coldcleaner run

[Timer]
OnCalendar=*-*-* 04:30:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now coldcleaner.timer
loginctl enable-linger "$USER"
```

`loginctl enable-linger` lets the timer run while you are logged out. Check it with `systemctl --user list-timers coldcleaner.timer` and read a run with `journalctl --user -u coldcleaner.service`. `SuccessExitStatus=3` treats "worked, but a disk is still at or above `alert_pct`" as success, so `journalctl` shows a `coldcleaner: ATTENTION:` line instead of a failed unit. Add `OnFailure=<your-alert>.service` under `[Unit]` to be told about failures. To stop the nightly run: `systemctl --user disable --now coldcleaner.timer`.

On macOS, or without systemd, add a cron entry instead:

```sh
config="${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner"
( crontab -l 2>/dev/null; echo "30 4 * * * PATH='$PATH' '$(command -v coldcleaner)' reclaim --apply --rules '$config/rules.toml'" ) | crontab -
```

## Commands

Every command accepts `--rules PATH`. `reclaim`, `status`, `doctor`, `metrics` and `approve PLAN ID` also accept `--report-dir PATH`; reports otherwise go to `report_dir` from the rules (`~/.local/state/coldcleaner/reports` in the example).

- `coldcleaner check-rules` validates the rules file without contacting hosts or scanning disks. It exits 0 when the rules are valid, 1 when they are invalid (for example `missing required key alert_pct`) and 2 when the file cannot be read.
- `coldcleaner doctor` prints one PASS or FAIL line per check: Python 3.14+, `zstd`, `git`, `gh auth status`, a writable `nas_root` and `report_dir` (or their nearest existing parent), and for each `reclaim_hosts` host (or `--host`) that it answers over SSH and that its process check, including passwordless sudo, works. It writes, moves and deletes nothing. It exits 0 when every check passes and 1 when any fails.
- `coldcleaner reclaim` previews or, with `--apply`, performs cleanup ([What reclaim removes](#what-reclaim-removes)). `--host` picks one host. `--json` prints one JSON summary ([Calling it from another tool](#calling-it-from-another-tool)).
- `coldcleaner status` shows disk use per host and the last report. A host at or above `alert_pct` gets a note on its line.
- `coldcleaner find TERM` searches archive records and file lists. It prints one line per archive with its restore ID, then matching members.
- `coldcleaner restore ID` puts an archive back where it came from. `--member M` restores one path from it, and `--to PATH` restores somewhere else. Restore refuses to overwrite an existing path and does not need `--apply`.
- `coldcleaner restore-drill` restores one random archive into a temporary folder under `~/.cache/coldcleaner/restore-drill` on this machine, checks every path against `.files.txt` and every file against the archive's SHA-256 receipt, deletes the copy and appends pass or fail to `restore-drill.jsonl` in the report folder. It does not change the archive or `INDEX.csv`, and exits 1 on a failure. `scripts/install.sh` schedules it weekly.
- `coldcleaner approve PLAN ID...` (or `approve PLAN all`) approves items from a dry-run plan ([Approval mode](#approval-mode)). It refuses IDs that are not in the plan and records nothing then.
- `coldcleaner metrics` prints one row per host for the last 7 days (`--days N` to change): bytes acted on, the `df` drop across `reclaim --apply` runs, distinct candidates, acted and held-for-a-person paths, the automation rate (acted ÷ (acted + held)), paths seen again after removal, restored archives (all time), the latest restore drill result from `restore-drill.jsonl` in the report folder, the disk-used trend and the age of the oldest held worktree. It reads the action log, the reports, `held.json` and `INDEX.csv` and changes nothing. Every `reclaim` report repeats the table under `## Metrics`, after the host sections.
- Every `reclaim` run (dry run or apply) also rewrites `fleet/summary.md` in the report folder: per host, the after-run disk % over the last 30 `reclaim --apply` runs (sparkline, latest, min, max), bytes reclaimed in those runs (logged after the report before them and up to the newest), worktrees held now by reason with the 5 largest, and the policy (`live`, idle days, `roots` and `archive` counts, archive entries with their own `days`). If the logs cannot be read, the file says why; if it cannot be written, the run prints a warning and its exit code is unchanged.

`--to PATH` replaces the archived root, also with `--member`. For an archive rooted at `.scratch`, `--to /tmp/recovered --member .scratch/evidence.txt` writes `/tmp/recovered/evidence.txt`. `/tmp/recovered` must not already exist.

## Reports

Each run writes a timestamped Markdown report in the report folder. For each host it shows disk use before and after, and every proposed or applied action with its size. Skipped items are summed by reason, with counts and bytes, and the 20 largest are listed by path. Skipped paths are sized read-only in one batched check per tier, capped at 30 seconds; a note says when some sizes are lower bounds. Sizes are logical file sizes, and a skip does not count toward savings. A `reclaim` report also lists, per host, the 20 largest folders directly under home or a `roots` entry that no `archive` rule or worktree covers, with a hint such as "looks like scratch", "benchmark output" or "agent transcripts". That scan only reads, stops after 120 seconds per host (sizes are then lower bounds), and coldcleaner never acts on what it lists. In `--json`, each host carries them as `unlisted` with `unlisted_complete`. A `reclaim` report opens with "Totals by category": items, reclaimable bytes (proposed plus done) and acted bytes for completed worktrees, scratch and temp, test and benchmark outputs, and archived agent artifacts. `--json` carries the same numbers as top-level `categories`, keyed `worktree`, `scratch`, `test-output` and `artifact`.

An optional top-level `attention_note` path names a Markdown file, such as a team notes channel. After each `reclaim --apply`, coldcleaner appends one `ATTENTION` line there when a host is at or above `alert_pct`, a host reached its deletion limit, or worktrees are held that the previous run did not hold. The line names the report. The held set is kept in `held.json` in the report folder; a host whose run had errors keeps its previous set, and a run that started before the last saved one leaves it unchanged. If the note cannot be written, the run exits 1. Without `attention_note`, nothing is written.

An optional top-level `manual_notes` array of one-line strings in the rules adds a final "Manual fixes, report only" section.

Dry runs still inspect the hosts over SSH. Long scans write progress to stderr every five seconds, with folder and file counts, bytes and elapsed time.

Worktree removal and preview rows also record `head`, `branch`, `remote`, `merged` (whether the probe proved ancestry of the published `main`, or `master` when `main` is absent; false also covers unavailable proof), and `pull_requests` (PR URLs matching that exact head). To recreate a removed worktree, use a local checkout of the logged `remote` and run `git -C <repo> worktree add <path> <head>`. When the row has a branch that no longer exists locally, run `git -C <repo> worktree add -b <branch> <path> <head>` instead. If the branch was retained or is in use, restore the exact commit with `git -C <repo> worktree add --detach <path> <head>`.

Every reclaim row also names the policy it ran under: `rule` (`<host>.<key>:<value>`, the `roots` entry, or `archive` pattern that selected the path), `idle_days` (the idle window applied, or null when the row stopped before one was chosen or none applies), `rules_sha256` (SHA-256 of the rules file bytes) and `code` (the full Git commit of the controller checkout, or the installed package label).

`reclaim --apply` also appends one JSON line per action to `reclaim-actions.jsonl` in the report folder. When a new line would push that file past `actions_log_mb` (default 10), it is gzipped to `reclaim-actions-<UTC timestamp>.jsonl.gz`, read back and only then removed. Rotated files are kept; read them with `zcat`.

Each host acts on at most `max_items_per_run` items (default 200) and `max_gib_per_run` GiB (default 100) per `reclaim --apply`; a host table can override either. Once the next item would cross a limit, it and the rest on that host are skipped with `deletion limit reached`, and the run exits 3 with an `ATTENTION:` line.

### Approval mode

Every `reclaim` dry run writes `<report>.plan.json` next to its report, listing each candidate with a stable `id`, host, tier, path, bytes, rule and reason. The ID is a hash of the host, tier, path, Git head (worktrees) and every file's path, type, size, modification time and change time, so it stays the same while the item is unchanged. `coldcleaner approve PLAN ID...` records approvals in `approvals.json` in the report folder.

Items of a tier listed in the top-level `approval` array, or matched by an archive table entry with `approval = true`, are acted on by `reclaim --apply` only when their current ID is approved. Others are skipped with `APPROVAL NEEDED`; an approved item whose ID has changed since the plan is skipped with `APPROVAL STALE`. Each approved item still passes every fresh check before acting, and its ID is recomputed from the fresh check and again by the host right before removal, so a change after approval also skips it. An approval is used up once the item is acted on. On Windows hosts, gated items are always skipped with `APPROVAL UNAVAILABLE`, because Windows reports no file change time. Tiers and entries without the flag act automatically, as before.

## Calling it from another tool

`coldcleaner reclaim --rules /path/to/rules.toml --host local --json` is the stable entry point for other programs. With a pip install, or from the repository folder, `python3 -m coldcleaner reclaim --rules /path/to/rules.toml --host local --json` does the same. One JSON object goes to stdout and progress to stderr. Add `--apply` to act; without it nothing changes. Top-level `errors` lists problems that belong to no single host, such as an unwritable report folder.

```json
{"status": "ok", "mode": "dry-run", "code": "main @ abc1234", "report": "/path/report.md", "errors": [],
 "hosts": [{"name": "local", "disk_before_percent": 71.2, "disk_after_percent": 71.2,
            "would_free_bytes": 0, "acted_bytes": 0, "errors": [], "skipped": 12, "actions": []}]}
```

| Exit | `status` | Meaning |
| ---: | --- | --- |
| 0 | `ok` | The run finished and no host is at or above `alert_pct`. |
| 1 | `incomplete` | A host was unreachable, a step failed, or the report could not be written (`report` is `null`). Actions already taken are still listed. |
| 2 | `refused` | Nothing ran: bad rules file, `--apply` with neither `worktree` nor `archive` in `live`, or invalid arguments. The object has a `reason`. |
| 3 | `attention` | The run finished without errors, but a host is still at or above `alert_pct` or reached its deletion limit. |

Each entry in `actions` has `tier`, `action`, `path`, `bytes` and `reason`. `skipped` counts protected items; the Markdown report lists them with their reasons.

## Limitations

- Projects with nested repositories need manual review.
- Tests use temporary folders, local Git remotes and fake hosts. They do not prove correctness on every remote system, so review every live configuration before use.
