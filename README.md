# coldcleaner

Coldcleaner runs every night and cleans up what coding agents leave behind. It checks what is already durable on GitHub, so it no longer needs a local copy, and deletes it. Anything else it removes is archived and verified first. Protections stop it from deleting your drive or breaking anything in use. The point is that drives stop filling up.

## What it cleans and what it keeps

It cleans only what you list in your rules file, and only for tiers you list in `live`:

- **Git worktrees** under your configured `roots`, once their current head is published on GitHub and either merged or the head of a closed PR. A merged worktree must be idle 1 day (or `worktree_idle_days`, if lower); a worktree whose PR was closed without merging must be idle `worktree_idle_days` (7 in the example). It runs `git worktree remove` and deletes the worktree's local branch, unless the worktree is detached or another worktree has that branch checked out. Ignored files inside are archived first.
- **Scratch, evidence, staging and temp folders** you list under `archive`, once idle `archive_idle_days` (4 in the example). System temp paths (`/tmp`, `/var/tmp`, Windows `AppData\Local\Temp` and `Windows\Temp`) must be idle at least 7 days. Each is archived, every file's SHA-256 is compared, and only then is the source deleted.

It keeps, and never deletes:

- Remote branches, GitHub repositories and anything on GitHub.
- Virtual machines, VM disks, containers, Docker volumes and services.
- Package caches (pip, npm, uv, cargo and similar).
- Anything a scheduler names, a running process has open, a `.keep-local` file marks, or that changed within its idle window.
- Git work that is not proven on GitHub: dirty files, stashes, unpushed commits, open PRs, and published heads that are neither merged nor the head of a closed PR.
- Folders you did not list. Big unknown folders appear in the report only.

## Safety: will it erase my drive?

Not if you keep to the defaults. It only acts on what you list, and it keeps a verified copy of anything it removes that exists nowhere else.

- **Dry run by default.** Nothing is deleted, moved or pushed unless you pass `--apply` and the tier is listed in `live` in your rules file. The example rules ship with `live = []`.
- **Only listed paths.** It acts on paths and patterns in your rules file and nothing else. Unknown big folders are reported, never touched.
- **Protected items stay.** Deletion is blocked for paths named by a scheduler (cron, systemd, launchd, Task Scheduler), files open in a running process (lsof), folders with a `.keep-local` file, files changed within the idle window (example defaults: 4 days for archives, 7 for worktrees, or 1 once merged, 28 for whole projects), and Git work without a verified remote copy.
- **Verified copy first.** Before it removes data that exists nowhere else (ignored files, staging, evidence), it archives it, compares a SHA-256 for every file, and only then deletes. A worktree is removed only after its commits are proven published on GitHub, and ignored data inside it is archived with a Git recovery bundle.
- **Restorable.** `restore ID` puts an archive back, or just one file with `--member`, or somewhere else with `--to`. It refuses to overwrite an existing path.
- **Safe with Git.** It never force-pushes and never creates GitHub repositories.
- **See it first.** `python3 -m coldcleaner reclaim --host local` changes nothing. It prints a report path; the report lists every action it would take with the path, size and reason, counts what it skipped by reason, and names the 20 largest skipped items.

## What it does

A disk cleanup controller for Linux, macOS, Windows and WSL. It reviews configured caches, Git worktrees and projects, archives selected data, and reports protected paths and incomplete checks. The controller uses Python 3.14 and its standard library. Archiving also requires tar and zstd on the controller.

## Quickstart

Install from the checkout with one command. [uv](https://docs.astral.sh/uv/) fetches Python 3.14 if needed; `pipx install .` also works when Python 3.14 is present.

```sh
uv tool install .
config="${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner"
mkdir -p "$config" && { [ -e "$config/rules.toml" ] || cp rules.example.toml "$config/rules.toml"; }
coldcleaner check-rules
coldcleaner reclaim --host local --report-dir "$config/reports"
```

An installed copy reads `~/.config/coldcleaner/rules.toml` (or `$XDG_CONFIG_HOME/coldcleaner/rules.toml`); a checkout with its own `rules.toml` uses that file. An existing rules file is kept. Tests: `python3 -m unittest discover -s tests -v`. Inside an active Python 3.14 virtual environment, pip installs it too:

```sh
python3 -m pip install .
```

Running from the checkout without installing also works:

```sh
python3 -m coldcleaner --help
```

Choose writable archive and report directories. The example has one local POSIX host, `live = []`, and empty cleanup paths. Configure hosts only in `rules.toml`. Each `[hosts.<name>]` table requires `kind` (`posix`, `powershell` or `wsl`) and accepts `ssh` and optional `distro`. A `posix` host without `ssh` runs on this machine; `powershell` and `wsl` hosts require `ssh`, because the controller runs on Linux or macOS. Commented examples show remote POSIX and Windows hosts. Rules files written before hosts moved into configuration are refused until every host table declares `kind`; add `ssh = "<destination>"` to each remote host, because a table without `ssh` runs on this machine. macOS needs Bash 3.2 and Python 3.9 or newer. WSL execution remains retired. Native Windows uses PowerShell. Remote execution goes through `coldcleaner/hosts.py`.

### Run it every night

Review a dry-run report first, then add the tiers you want to `live` in your rules file, for example `live = ["worktree", "archive"]`. With `live = []`, `reclaim --apply` refuses to run and exits 2. Worktree cleanup needs [`gh`](https://cli.github.com/) logged in (`gh auth status`) to prove merges on GitHub.

Run these from the shell you used for the quickstart. `command -v coldcleaner gh` must print both paths: the scheduled run reuses that shell's `PATH`, the installed `coldcleaner` and your rules file.

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
ExecStart="$(command -v coldcleaner)" reclaim --apply --rules "$config/rules.toml" --report-dir "$config/reports"
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

`loginctl enable-linger` lets the timer run while you are logged out. Check it with `systemctl --user list-timers coldcleaner.timer` and read a run with `journalctl --user -u coldcleaner.service`. The service exits 1 when a host stays at or above `alert_pct` or a step fails; add `OnFailure=<your-alert>.service` under `[Unit]` to be notified. To stop the nightly run: `systemctl --user disable --now coldcleaner.timer`.

On macOS, or without systemd, add a cron entry instead:

```sh
config="${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner"
( crontab -l 2>/dev/null; echo "30 4 * * * PATH='$PATH' '$(command -v coldcleaner)' reclaim --apply --rules '$config/rules.toml' --report-dir '$config/reports'" ) | crontab -
```

### Archive to a local or external drive (no NAS)

A NAS is optional. `nas_root` is just a folder, and the key keeps its name for now. To archive to an external or second internal drive, mount it and name its mount point:

```toml
nas_root = "/mnt/backup/coldcleaner"
local_archive_mount = "/mnt/backup"
```

The same verification applies. `local_archive_mount` replaces the NFS/SMB check with these: the drive must be mounted at that exact path, the archive folder (after following symlinks) must be on it, it must be a different filesystem than `/`, it must not be memory-backed (`tmpfs`, `ramfs`), and, for data on the controller itself, it must not be the filesystem of the data being removed. This mode only supports data on the controller. While it is set, archive candidates and worktrees with ignored data on any other host are left in place with an error in the report, because that host cannot recheck the drive before removal. Use the NAS setting (leave this empty) for those hosts. The archive is checked again right before each removal, so an unplugged drive stops the run instead of filling an empty mount folder. The example rules leave the setting empty (off). Without it, the archive folder must be an NFS or SMB mount. The check applies to `reclaim`.

## Commands and safety

`python3 -m coldcleaner check-rules --rules rules.toml` validates configuration offline without contacting hosts or scanning disks.

`python3 -m coldcleaner reclaim` selects the configured `reclaim_hosts` list.
When absent, it selects every configured host except WSL. It excludes package caches and all WSL execution. Use `--host` for
one machine and `--report-dir` for private reports. Preview first; `--apply` still
requires the worktree/archive tier in `live`.

Reclaim removes a worktree only after a fresh GitHub ref/PR proof shows that its
current head is published and merged or its matching PR is closed. Open PRs,
dirty files, stashes, process use, active T3 runs, pinned or unsettled T3 threads
and incomplete checks retain it.
Native Windows reclaim requires a complete process inventory. An unreadable
command line blocks cleanup. Only the probe itself, kernel pseudo-processes with
PIDs 0 and 4, and processes that Windows reports as protected or secure (for example
`lsass.exe`, `Registry`, `LsaIso.exe` and Defender), whose command line and executable path
are both unreadable, are excluded from that inventory.
Ignored data gets a NAS archive with a SHA-256 comparison of every file before
`git worktree remove` and local branch deletion. Listed staging, temporary data
and evidence also get a verified NAS copy before removal; temporary directories
retain at least seven days. SHA-256 manifests, searchable file lists and the archive index retain the
copy location. Reclaim archives are pinned against legacy cap expiry and support
full and member restores on native Windows as well as POSIX. Worktree backups
also retain a verified Git recovery bundle, so a full restore recreates a usable
repository after the original worktree metadata is removed. Windows candidates
with alternate streams are retained. Exclusive-open checks retain open files and
working directories. Mount points and nested filesystems are retained. Recovery
receipts preserve Windows owner/group/DACL descriptors and POSIX ownership, modes
and timestamps. POSIX ACLs, extended attributes, special modes and foreign ownership
require separate preservation and retain the source. Reclaim never expires NAS archives, removes registered VM disks,
prunes Docker volumes, or changes services other than its separately installed
timer. Attached VM disks, container/service state and unproven paths are kept.

`python3 -m coldcleaner run` previews legacy tiers. Its `--apply` option is disabled;
use `reclaim --apply` for cleanup with the current safeguards. A host can list
`shared_roots` for shared disk namespaces such as `/srv/shared`. A scheduler
reference to that namespace protects the namespace itself; explicit references to
its children still protect those children. Reclaim keeps process, open-file, T3
and Git checks for every child.

Dry runs still inspect configured hosts over SSH and write a report. POSIX and WSL inventory scans write progress to stderr at the start, end and every five seconds while traversing entries, with directory/file counts, bytes and elapsed time. ETA is an estimate from completed candidates in a known batch, such as aged cache children. It stays unknown while the remaining tree size is unknown. Review configuration and the dry-run report before enabling a tier. For the first live run, list one folder, enable one tier in `live`, and compare the apply report with the dry-run report.

`status` shows disk use and the last report; a host at or above `alert_pct` or `hard_pct` gets a note on its line. `github` inventories GitHub safety; `github --apply` requires the `github` live tier. Git backup uses dedicated backup refs rather than normal branch refs. `find TERM` searches archive records and prints one readable line per archive with its restore ID, followed by matching members. `restore ID` restores to the original location, or accepts `--to PATH` and `--member M`. Restore refuses existing destinations and performs writes without the run command's apply switch.

`--to PATH` replaces the archived root, including when `--member` selects one file. For an archive rooted at `.scratch`, `--to /tmp/recovered --member .scratch/evidence.txt` writes `/tmp/recovered/evidence.txt`. The target `/tmp/recovered` must not already exist.

GitHub inventory tables show counts for dirty files, untracked files, unpushed refs and stashes. Backup action rows show the number of planned or pushed refs; blocked-backup messages remain visible. Git safety checks still inspect every ref.

Each run writes a separate timestamped Markdown report in `~/.local/state/coldcleaner/reports/`. Each host has before/after usage, all proposed and applied actions with byte estimates, and repos needing GitHub backup. Skipped items are summarized by reason with counts and bytes; all cache candidates include their age and minimum age, while only the 20 largest other skipped items are listed individually. Reports do not scan for the largest home folders. Estimates use logical file sizes. A skip or incomplete check does not count toward estimated savings. Exit code 1 means a host remains at or above 80%, is unreachable, or a cleanup step failed.

Each command accepts `--rules PATH`. Run and status also accept `--report-dir PATH`. Reports default to `~/.local/state/coldcleaner/reports/` for dry runs and apply runs. The `/tmp` and `/var/tmp` sweep requires seven days of inactivity across the entire candidate, retains Git clones and worktrees including their descendants, and reports each candidate's age and minimum age. A cleanup report records before and after disk usage, proposed actions, protected paths and errors. Exit code 1 reports an unreachable host, an incomplete cleanup step or disk use at or above the configured alert threshold.

Scheduler references, open files, `.keep-local`, recent projects and Git work without a verified remote copy prevent cleanup. Unknown folders are reported. All tiers except project run their configured checks daily; project cleanup also requires the hard disk threshold. Whole project removal requires a verified archive. Archive retention can expire old archives when the cap is exceeded and archive or project cleanup is enabled.

Each live candidate batch refreshes scheduler protection and takes a fresh open-file snapshot. Legacy tier checks do not reserve paths against later writers. Reclaim also checks active T3 runs immediately before removal; it does not reserve their workspaces. A dry-run NAS cap preview reads the atomic index without creating a lock file; an apply run locks and reads the index again, so concurrent archive changes can change its result.

Windows WSL execution is retired. Runs report its execution tiers as skipped while retaining historical identity and native C: pressure reporting and alerts. Both remote execution boundaries refuse to launch it. Legacy archives remain recoverable through `restore ID` with `--to-host` set to an approved POSIX host and `--to` set to an explicit destination. Full and member recovery keep the archive and its original host identity in the index. Native Windows metadata access keeps its existing SSH route. No workload is silently redirected to another host.

Windows reclaim needs every process command line. While the WSL VM runs, the Windows probe reads the open files of every process inside each running distro as root (read-only, through `wsl.exe`) and maps drvfs mounts such as `/mnt/c` to drive paths, so Windows data a WSL job uses stays protected. If that read fails, Windows reclaim is incomplete. The Windows Sandbox template VM counts only while no sandbox session runs. WSL is never stopped.

## Calling it from another tool

`python3 -m coldcleaner reclaim --rules /path/to/rules.toml --host local --json` is the stable non-interactive entry for other programs, for example a sandbox host reclaiming old images and work directories. The rules file comes in, one JSON object goes out on stdout, and progress goes to stderr. Add `--apply` to act; without it nothing changes. Top-level `errors` lists problems that belong to no single host, such as an unwritable report with no host selected.

```json
{"status": "ok", "mode": "dry-run", "code": "main @ abc1234", "report": "/path/report.md", "errors": [],
 "hosts": [{"name": "local", "disk_before_percent": 71.2, "disk_after_percent": 71.2,
            "would_free_bytes": 0, "acted_bytes": 0, "errors": [], "skipped": 12, "actions": []}]}
```

| Exit | `status` | Meaning |
| ---: | --- | --- |
| 0 | `ok` | The run finished and no host is at or above `alert_pct`. |
| 1 | `incomplete` | A host was unreachable, a step failed, the report could not be written (`report` is `null`), or a host is still at or above `alert_pct`. Actions already taken are still listed. |
| 2 | `refused` | Nothing ran: bad rules file, `--apply` with neither `worktree` nor `archive` in `live`, or invalid arguments. The object has a `reason`. |

Each entry in `actions` has `tier`, `action`, `path`, `bytes` and `reason`. `skipped` counts protected items. The Markdown report lists them with their reasons.

## Limitations

Coldcleaner is licensed under the MIT License. See `LICENSE` for the copyright notice and terms.

Native Windows GitHub inventory and projects with nested repositories need manual review. Open-file protection uses lsof on POSIX hosts. Incomplete protection checks retain candidates. Verification uses temporary directories, local Git remotes and fake host boundaries; it does not establish correctness on every remote system. Review every live cleanup configuration before use. A cache entry with `days` may set `failed_days` (at least `days`, POSIX hosts only): a directory whose `.cold/verify-history.jsonl` ends in a failing run is kept that long instead. That optional file holds one JSON object per line with a `run_id` and a `status`, appended by whatever verification runner you use; a run fails when any of its lines has `status` of `fail`, and a missing file adds no extra hold. Cache directories referenced by a running process (command line, environment or working directory, read from `/proc` for the same user) are never removed. `clone = true` treats each match as one unit: it retains clones with ignored or untracked files or submodules, and removes others only while their GitHub safety verdict is `on_github`; both checks run again just before removal. A `/tmp` or `/var/tmp` cache entry needs `days` of at least 7 and an `owner`, which must be your own username (not root).

## Development

1. Install Python 3.14, Git, tar and zstd.
2. Clone the repository and run the offline tests from its root: `python3 -m unittest discover -s tests -v`.
3. Open a pull request with a test for the behavior you changed. See `CONTRIBUTING.md`.

The tests exercise Git safety, archive verification and restore, cleanup protection, reporting and host command encoding. They use temporary directories, local bare Git remotes and fake hosts, and never contact real machines, archive storage or GitHub.
