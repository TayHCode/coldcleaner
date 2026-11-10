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

The example writes reports to `~/.local/state/coldcleaner/reports` and sets `nas_root` to `~/.local/share/coldcleaner/archive`, so a dry run works as any user. Archiving refuses until `nas_root` is on network storage or under `local_archive_mount` ([Archive storage](#archive-storage)). The example has one local host, `live = []`, and no cleanup paths.

### Hosts

Each `[hosts.<name>]` table needs `kind` (`posix`, `powershell` or `wsl`) and accepts `ssh` (an SSH destination) and `distro`. A `posix` host without `ssh` runs on this machine. `powershell` and `wsl` hosts need `ssh`, because the controller (the machine running coldcleaner) runs on Linux or macOS. The example file has commented remote POSIX and Windows hosts. `reclaim_hosts` lists the hosts that `reclaim` cleans by default; without it, every configured host except WSL.

Rules files written before hosts moved into configuration are refused until every host table declares `kind`. Add `ssh = "<destination>"` to each remote host, because a table without `ssh` runs on this machine.

Remote macOS hosts need Bash 3.2 and Python 3.9 or newer. Native Windows uses PowerShell. Compression always happens on the controller.

A host can list `shared_roots` for shared disk folders such as `/srv/shared`. A scheduler reference to that folder protects the folder itself; references to its children still protect those children.

## What reclaim removes

`coldcleaner reclaim` cleans the `reclaim_hosts` (or one `--host`). It is a dry run unless you add `--apply`, and `--apply` acts only on tiers listed in `live`. WSL is excluded, and package caches are cleaned only by the `cache` tier below.

**Worktrees** (`worktree` tier). Git worktrees under the host's `roots`. A worktree is removed only after a fresh check against GitHub shows that its current head is published and either merged or the head of a closed pull request. A merged worktree must be idle 1 day (or `worktree_idle_days`, if lower); one whose pull request was closed without merging must be idle `worktree_idle_days` (7 in the example). Coldcleaner runs `git worktree remove` and deletes the local branch, unless the worktree is detached or another worktree has that branch checked out. Ignored files inside are archived first, with a Git recovery bundle, so a full restore recreates a usable repository.

**Archive folders** (`archive` tier). Paths and glob patterns listed under the host's `archive`, once idle `archive_idle_days` (4 in the example). System temp folders (`/tmp`, `/var/tmp`, Windows `AppData\Local\Temp` and `Windows\Temp`) need at least 7 idle days. Each is archived, every file's SHA-256 checksum is compared with the original, and only then is the source deleted.

**Package caches** (`cache` tier). For each tool listed in a POSIX host's `cache_tools` (`uv`, `npm`, `pnpm`, `pip`, `brew`), coldcleaner runs only that tool's own cleaner: `uv cache prune`, `npm cache clean --force`, `pnpm store prune`, `pip cache purge` or `brew cleanup -s`. `brew` runs with `HOMEBREW_NO_AUTOREMOVE=1`, and only while `brew cleanup -n -s` lists nothing outside the Homebrew cache. A tool is skipped while any process of it runs, when it is not installed, or when its cache folder is outside your home, is a symlink, is marked `.keep-local`, is open in a process or is named by a scheduler. A failed or unavailable check skips or errors; it never cleans. With `--apply`, the cleaners run only when `live` lists `cache` together with `worktree` or `archive`. The example lists no tools and leaves `cache` out of `live`.

The legacy `run` command previews older tiers (caches, projects, WSL compaction). Its `--apply` option is disabled; use `reclaim --apply`.

## Protections in detail

Reclaim keeps a candidate when any of these is true. An incomplete check also keeps it.

- **Git work not on GitHub.** Dirty files, stashes, unpushed commits, open pull requests, and published heads that are neither merged nor the head of a closed pull request. Coldcleaner never force-pushes and never creates GitHub repositories.
- **Schedulers.** Paths named by systemd units and timers, crontab, launchd or Task Scheduler. Broad references such as your home folder, `/` or `C:\` protect only that exact path.
- **Running programs.** Files open in a running program, and their parent folders, and the working folders and command lines of running programs. Each live batch takes a fresh snapshot. On Linux and macOS this needs root or passwordless sudo ([README](../README.md#sudo)).
- **Coding agents.** Worktrees in use by T3 Code (a desktop app that runs coding agents) or the Codex CLI. Coldcleaner reads each agent's local state: T3 Code's `~/.t3/userdata/statev2.sqlite` and Codex's newest `~/.codex/state_N.sqlite`. Active T3 runs, pinned or unsettled T3 threads, and unarchived Codex threads updated within the tier's idle days keep their worktrees. An absent agent is noted once per host (`T3 not installed`). If that state cannot be read, for example after an agent upgrade changes it, every candidate on the host is kept with one `IN USE: <agent> state unreadable` reason. Codex threads whose folder is the home folder or `/` protect only that folder.
- **`.keep-local`.** Any folder with a `.keep-local` file in it or above it.
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

Every command accepts `--rules PATH`. `run`, `reclaim`, `status` and `doctor` also accept `--report-dir PATH`; reports otherwise go to `report_dir` from the rules (`~/.local/state/coldcleaner/reports` in the example).

- `coldcleaner check-rules` validates the rules file without contacting hosts or scanning disks. It exits 0 when the rules are valid, 1 when they are invalid (for example `missing required key hard_pct`) and 2 when the file cannot be read.
- `coldcleaner doctor` prints one PASS or FAIL line per check: Python 3.14+, `zstd`, `git`, `gh auth status`, a writable `nas_root` and `report_dir` (or their nearest existing parent), and for each `reclaim_hosts` host (or `--host`) that it answers over SSH and that its process check, including passwordless sudo, works. It writes, moves and deletes nothing. It exits 0 when every check passes and 1 when any fails.
- `coldcleaner reclaim` previews or, with `--apply`, performs cleanup ([What reclaim removes](#what-reclaim-removes)). `--host` picks one host. `--json` prints one JSON summary ([Calling it from another tool](#calling-it-from-another-tool)).
- `coldcleaner status` shows disk use per host and the last report. A host at or above `alert_pct` or `hard_pct` gets a note on its line.
- `coldcleaner github` lists Git repositories and what is not yet on GitHub. `github --apply` (which needs `github` in `live`) pushes work that is on no remote to dedicated backup refs (`refs/coldcleaner/...`), never to normal branches. Its tables count dirty files, untracked files, unpushed refs and stashes.
- `coldcleaner find TERM` searches archive records and file lists. It prints one line per archive with its restore ID, then matching members.
- `coldcleaner restore ID` puts an archive back where it came from. `--member M` restores one path from it, and `--to PATH` restores somewhere else. Restore refuses to overwrite an existing path and does not need `--apply`.
- `coldcleaner run` previews the legacy tiers. `run --apply` is refused.

`--to PATH` replaces the archived root, also with `--member`. For an archive rooted at `.scratch`, `--to /tmp/recovered --member .scratch/evidence.txt` writes `/tmp/recovered/evidence.txt`. `/tmp/recovered` must not already exist.

## Reports

Each run writes a timestamped Markdown report in the report folder. For each host it shows disk use before and after, every proposed or applied action with its size, and repositories that need a GitHub backup. Skipped items are summed by reason, with counts and bytes, and the 20 largest are listed by path; every skipped cache candidate is listed with its age and minimum age. Skipped paths are sized read-only in one batched check per tier, capped at 30 seconds; a note says when some sizes are lower bounds. Sizes are logical file sizes, and a skip does not count toward savings.

An optional top-level `manual_notes` array of one-line strings in the rules adds a final "Manual fixes, report only" section.

Dry runs still inspect the hosts over SSH. Long scans write progress to stderr every five seconds, with folder and file counts, bytes and elapsed time.

`reclaim --apply` also appends one JSON line per action to `reclaim-actions.jsonl` in the report folder. When a new line would push that file past `actions_log_mb` (default 10), it is gzipped to `reclaim-actions-<UTC timestamp>.jsonl.gz`, read back and only then removed. Rotated files are kept; read them with `zcat`.

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
| 3 | `attention` | The run finished without errors, but a host is still at or above `alert_pct`. |

Each entry in `actions` has `tier`, `action`, `path`, `bytes` and `reason`. `skipped` counts protected items; the Markdown report lists them with their reasons.

## Limitations

- Native Windows GitHub inventory, and projects with nested repositories, need manual review.
- Tests use temporary folders, local Git remotes and fake hosts. They do not prove correctness on every remote system, so review every live configuration before use.
- A cache entry (legacy `run` tiers) with `days` may set `failed_days` (at least `days`, POSIX hosts only): a folder whose `.cold/verify-history.jsonl` ends in a failing run is kept that long instead. That optional file holds one JSON object per line with a `run_id` and a `status`; a run fails when any of its lines has `status` of `fail`.
- Cache folders used by a running program of the same user are never removed. `clone = true` treats each match as one unit: it keeps clones with ignored or untracked files or submodules, and removes others only when they are fully on GitHub.
- A `/tmp` or `/var/tmp` cache entry needs `days` of at least 7 and an `owner`, which must be your own username (not root).
- Archive cap: when archives exceed `nas_cap_gb`, legacy tiers can expire the oldest dated folders. Reclaim archives are pinned and never expire.
