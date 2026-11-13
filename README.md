# coldcleaner

Coldcleaner frees disk space that coding work leaves behind. It removes finished Git worktrees once their commits are on GitHub, and it archives the scratch, evidence and temp folders you list, checks every archived file, and only then deletes the original. It runs from one machine and can clean that machine or others over SSH (Linux, macOS and Windows).

> **What it never touches**
>
> - Anything you did not list in your rules file. The report lists the largest folders directly under home or `roots`, but never touches them.
> - Anything a scheduled job uses (cron, systemd, launchd or Windows Task Scheduler).
> - Any file a running program has open, any folder holding one, and any worktree a coding agent is still using.
> - Any folder with a `.keep-local` file in it or above it.
> - System, personal and cloud-drive folders, Obsidian vaults and a host's `protected` list ([list](docs/reference.md#protections-in-detail)).
> - Git work that is not on GitHub: uncommitted files, stashes, unpushed commits and open pull requests.
> - Anything changed recently: 4 days for archived folders, 7 days for worktrees (1 day once merged).
> - GitHub itself (no force-push, no new repositories), virtual machines, containers and Docker volumes.
> - Package caches. They are out of scope, and an `archive` path that holds a well-known cache folder (`.cache`, `.npm`, `.cargo`, `.bun`, `npm-cache`, `pip-cache`, `uv-cache`, `go-build`, `node-compile-cache`) is skipped. Keep other caches out of `archive`.
>
> By default nothing is changed at all. It only deletes when you pass `--apply` **and** list that kind of cleanup in `live` in your rules file. The example rules list nothing.

## Install

Coldcleaner needs Python 3.14. The simplest install uses [uv](https://docs.astral.sh/uv/), which downloads Python 3.14 for you if needed. If you don't have uv yet:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then open a new terminal so the `uv` command is found.

Cleanup itself also needs `tar`, `zstd`, `git`, `lsof` and the GitHub CLI `gh` (logged in with `gh auth login`). A dry run works without them. `coldcleaner doctor` checks for `zstd`, `git` and `gh`.

Other ways to install (pipx, pip in a virtual environment, or running from the checkout) are in [docs/reference.md](docs/reference.md#other-ways-to-install).

## Quick start (one machine)

```sh
uv tool install git+https://github.com/TayHCode/coldcleaner@v0.3.1
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner"
[ -e "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner/rules.toml" ] || { curl -fsSL https://raw.githubusercontent.com/TayHCode/coldcleaner/v0.3.1/rules.example.toml -o "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner/rules.toml.part" && mv "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner/rules.toml.part" "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner/rules.toml"; }
coldcleaner doctor
coldcleaner reclaim --host local
```

1. `uv tool install` installs the v0.3.1 release and adds a `coldcleaner` command to `~/.local/bin`. From a clone, `uv tool install .` installs that copy.
2. The next two lines download the example rules file to `~/.config/coldcleaner/rules.toml` (or `$XDG_CONFIG_HOME/coldcleaner/rules.toml` if you set `XDG_CONFIG_HOME`), which is where coldcleaner looks. An existing file is kept.
3. `doctor` checks what cleanup needs and prints one PASS or FAIL line for each item. It changes nothing. It exits 1 while anything fails; that is expected on a new machine, and the dry run below still works.
4. `reclaim --host local` is a dry run. It changes nothing, writes a report and prints the report's path, then one line per host with its disk use and how much it would free. The report lists each proposed action with its reason, and sums skips by reason.

The example rules list no folders, so the first report has nothing to do. That is the point: you add folders next.

## Turn cleanup on

Open the rules file you just copied (`~/.config/coldcleaner/rules.toml`, or under `$XDG_CONFIG_HOME`) and work through these steps in order:

1. Under `[hosts.local]`, set `roots` to the folders that hold your Git repositories, for example `roots = ["~/projects"]`. Coldcleaner finds worktrees inside them.
2. Set `archive` to the scratch or temp folders you want archived and removed once they are idle, for example `archive = ["~/projects/*/.scratch"]`.
3. Set `nas_root` to the folder where archives go. The name comes from NAS (network-attached storage): the folder must be on a network share (NFS or SMB), or on a second drive that you name in `local_archive_mount`. See [Archive storage](docs/reference.md#archive-storage).
4. Run `coldcleaner check-rules`, then `coldcleaner reclaim --host local` again, and read the new report.
5. When the report shows only what you expect, turn on one kind of cleanup, for example `live = ["archive"]`, and run `coldcleaner reclaim --host local --apply`.

`--apply` refuses to run and exits 2 unless `live` lists `worktree` or `archive`, and until a current-rules dry run covers each host. Worktree cleanup (`live = ["worktree"]`) also needs `gh` logged in, because it asks GitHub whether each branch was merged.

There are two kinds of cleanup:

| `live` entry | What it removes | When |
| --- | --- | --- |
| `worktree` | Git worktrees under `roots` (`git worktree remove`, then the local branch) | The worktree's commits are on GitHub, its branch is merged or its pull request is closed, and it has been idle 7 days (1 day once merged). Ignored files inside are archived first. |
| `archive` | Folders listed in `archive` | Idle 4 days (system temp folders 7 days). Each is archived to `nas_root`, every file's SHA-256 checksum is compared with the original, and only then is it deleted. |

Get anything back with `coldcleaner find TERM` (search archives by path) and `coldcleaner restore ID`, which never overwrites an existing path.

## Run it every night

Once a live run looks right, schedule `coldcleaner reclaim --apply` daily with a systemd user timer on Linux or cron on macOS. Copy-paste setups for both are in [docs/reference.md](docs/reference.md#run-it-every-night).

Exit codes: 0 means the run worked; 1 means a host was unreachable or a step failed; 2 means it refused to run (bad rules or arguments); 3 means the run worked but a disk is still at or above `alert_pct` (80% in the example), or a host reached its per-run deletion limit (`max_items_per_run`, `max_gib_per_run`).

## Host-local policy

Each host removes only what its own `~/.config/coldcleaner/local.json` allows, whatever the controller asks: worktrees under its `roots`, folders matching its `archive` globs. Without it, nothing is removed there.

```json
{"roots": ["~/projects"], "archive": ["/tmp/*"]}
```

## Sudo

Before removing anything, coldcleaner checks that no running program uses it. Only root can see every program's open files, so a non-root run uses `sudo -n` on Linux and macOS, which never asks for a password. Without passwordless sudo, nothing is removed, and each candidate is skipped with `IN USE: process inventory needs passwordless sudo (see README#sudo)`. Root inside an unprivileged container (LXC, Incus, rootless Docker) still cannot read all of `/proc`, so there candidates are skipped as `process inventory incomplete: /proc not readable`. Run coldcleaner on the container's host instead.

On Linux, the narrowest rule lets your user run one root-owned, read-only scan and nothing else. From the repository folder, install the scan (repeat this after every upgrade; until you do, candidates are skipped with the sudo message):

```sh
python3 -c 'import coldcleaner.reclaim_probe as p; print(p.PROC_SCAN, end="")' | sudo install -D -m 0644 /dev/stdin /usr/local/libexec/coldcleaner-proc-scan.py
```

This needs `python3` to be Python 3.14. If your Python 3.14 came from uv, start the line with `"$(uv tool dir)/coldcleaner/bin/python" -c` instead of `python3 -c`. For a remote host, pipe into `ssh HOST 'sudo install -D -m 0644 /dev/stdin /usr/local/libexec/coldcleaner-proc-scan.py'` instead.

Then add this rule with `sudo visudo -f /etc/sudoers.d/coldcleaner`. Replace `alice` with the user that runs coldcleaner (the SSH user, for a remote host), and `/usr/bin/python3` with the output of `command -v python3` on that host:

```text
alice ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/coldcleaner-proc-scan.py /proc
```

On macOS, the check runs `lsof` and `ps`:

```text
alice ALL=(root) NOPASSWD: /usr/sbin/lsof -nP -Fn, /bin/ps -axww -o command\=
```

## More

[docs/reference.md](docs/reference.md) has the details:

- every command and option, including `status`, `find TERM` and `restore ID`;
- remote hosts over SSH, Windows and WSL;
- archiving to a local drive instead of a NAS;
- what the report shows, the actions log, and JSON output for other tools;
- every protection, in detail;
- known limitations.

`coldcleaner --help` lists the commands, and `--help` after any command describes it. Every command accepts `--rules PATH` to use another rules file, and `--host NAME` picks one host where it applies. `coldcleaner --version` prints the version.

## Limitations

When any safety check fails or cannot run, coldcleaner keeps the item, so it often leaves behind things you expected it to remove. Projects with nested repositories need manual review. The tests use fake hosts and do not prove correctness on every remote system, so check a dry run of every new configuration before `--apply`. The full list is in [docs/reference.md](docs/reference.md#limitations).

## Development

Install Python 3.14, Git, tar and zstd, then run the offline tests from the repository folder:

```sh
python3 -m unittest discover -s tests -v
```

The tests use temporary folders, local Git remotes and fake hosts. They never contact real machines, archive storage or GitHub. See `CONTRIBUTING.md` before opening a pull request, and `SECURITY.md` to report a security problem. Coldcleaner is licensed under the MIT License; see `LICENSE`.
