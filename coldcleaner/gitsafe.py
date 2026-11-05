import re
import shlex
import subprocess
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import hosts


@dataclass
class RepoState:
    path: str
    is_worktree: bool = False
    has_remote: bool = False
    remote_url: str = ""
    dirty_files: list[str] = field(default_factory=list)
    untracked_files: list[str] = field(default_factory=list)
    unpushed_branches: list[str] = field(default_factory=list)
    stash_count: int = 0
    verdict: str = "blocked"
    reason: str = ""


def _is_github_url(url: str) -> bool:
    if re.fullmatch(r"git@github\.com:[^\s]+", url):
        return True
    parsed = urlsplit(url)
    return parsed.scheme in {"https", "ssh", "git"} and parsed.hostname == "github.com"


_SCAN = r'''
set -euo pipefail
export GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
case "$repo" in '~') repo=$HOME ;; '~/'*) repo="$HOME/${repo#\~/}" ;; esac
cd -- "$repo"
[ "$(git rev-parse --is-inside-work-tree)" = true ]
[ "$(pwd -P)" = "$(cd -- "$(git rev-parse --show-toplevel)" && pwd -P)" ]
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
emit() { printf '%s\0%s\0' "$1" "$2"; }
blocked() { emit blocked "$1"; exit 0; }
head=$(git rev-parse --verify HEAD^{commit} 2>/dev/null) || blocked 'No commits on current branch'
common=$(git rev-parse --git-common-dir)
[ ! -s "$common/info/grafts" ] || blocked 'Git grafts prevent an ancestry proof'
if [ -f .git ]; then emit worktree yes; fi
git diff --name-only --no-renames -z HEAD -- > "$scratch/dirty"
git diff --cached --name-only --no-renames -z -- >> "$scratch/dirty"
git ls-files --others --exclude-standard -z > "$scratch/untracked"
while IFS= read -r -d '' file; do emit dirty "$file"; done < "$scratch/dirty"
while IFS= read -r -d '' file; do emit untracked "$file"; done < "$scratch/untracked"
git ls-files --stage > "$scratch/stages"
if LC_ALL=C grep -q '^160000 ' "$scratch/stages"; then
    blocked 'Submodule contents require a separate backup proof'
fi
if LC_ALL=C grep -Eq ' [123][[:space:]]' "$scratch/stages"; then
    blocked 'Unmerged index cannot be snapshotted'
fi
git ls-files -v > "$scratch/flags"
if LC_ALL=C grep -q '^[a-zS]' "$scratch/flags"; then blocked 'Index flags can hide local changes'; fi
git stash list --format='%H' > "$scratch/stashes"
stash_count=$(wc -l < "$scratch/stashes" | tr -d ' ')
emit stashes "$stash_count"
if git config --get-all remote.origin.url > "$scratch/url"; then
    url_count=$(wc -l < "$scratch/url" | tr -d ' ')
    [ "$url_count" -eq 1 ] || blocked 'Multiple origin URLs require manual inspection'
    remote_url=$(cat "$scratch/url")
else
    result=$?
    [ "$result" -eq 1 ] || exit "$result"
    remote_url=''
fi
emit remote "$remote_url"
[ "${phase:-prove}" != probe ] || exit 0
[ "$remote_url" = "$listed_url" ] || blocked 'Origin changed during inspection'
branch=$(git symbolic-ref -q --short HEAD) || branch=HEAD
git for-each-ref --format='%(objectname) %(refname)' > "$scratch/refs"
: > "$scratch/branches"
while read -r sha ref; do
    case "$ref" in
        refs/remotes/*|refs/stash) continue ;;
        refs/heads/*) name=${ref#refs/heads/} ;;
        *) name=${ref#refs/} ;;
    esac
    printf '%s %s\n' "$sha" "$name" >> "$scratch/branches"
done < "$scratch/refs"
printf '%s HEAD\n' "$head" >> "$scratch/branches"
cat > "$scratch/remote"
cut -f1 "$scratch/remote" | LC_ALL=C sort -u > "$scratch/remote-shas"
git cat-file --batch-check='%(objectname) %(objecttype)' < "$scratch/remote-shas" > "$scratch/objects"
: > "$scratch/known"
while read -r sha kind; do
    case "$kind" in
        commit) printf '%s\n' "$sha" >> "$scratch/known" ;;
        tag) if git cat-file -e "$sha^{commit}" 2>/dev/null; then
            git rev-parse "$sha^{commit}" >> "$scratch/known"
        fi ;;
    esac
done < "$scratch/objects"
git rev-list --stdin < "$scratch/known" > "$scratch/reachable"
cat "$scratch/remote-shas" "$scratch/known" "$scratch/reachable" | LC_ALL=C sort -u > "$scratch/candidates"
proven() {
    LC_ALL=C grep -Fxq "$1" "$scratch/candidates" || return 1
    if LC_ALL=C grep -Fxq "$1" "$scratch/remote-shas"; then
        git cat-file -e "$1" || exit "$?"
        if [ "$(git cat-file -t "$1")" = commit ]; then
            git merge-base --is-ancestor "$1" "$1" || exit "$?"
        fi
        return 0
    fi
    if LC_ALL=C grep -Fxq "$1" "$scratch/known"; then
        git merge-base --is-ancestor "$1" "$1" || exit "$?"
        return 0
    fi
    LC_ALL=C grep -Fxq "$1" "$scratch/reachable" || return 1
    { printf '%s\n' "$1"; sed 's/^/^/' "$scratch/known"; } | git rev-list -n 1 --stdin > "$scratch/unproven" || exit "$?"
    [ ! -s "$scratch/unproven" ]
}
while read -r sha name; do
    if ! proven "$sha"; then emit missing "$name"; fi
done < "$scratch/branches"
if [ "$branch" = HEAD ] && ! proven "$head"; then
    blocked 'Detached HEAD is not proven on GitHub'
fi
current=$(pwd -P)
sibling_blocked() {
    [ -z "$cache" ] || printf '%s\t%s\n' "$worktree" "$1" >> "$cache.blocked"
    blocked "$1: $worktree"
}
git worktree list --porcelain -z > "$scratch/worktrees"
while IFS= read -r -d '' entry; do
    case "$entry" in
        worktree\ *) worktree=${entry#worktree } ;;
        HEAD\ *)
            worktree_head=${entry#HEAD }
            [ "$worktree" != "$current" ] || continue
            case "$worktree_head" in *[!0]*)
                proven "$worktree_head" || blocked "Worktree HEAD is not proven on GitHub: $worktree" ;;
            esac
            if [ ! -d "$worktree" ]; then continue; fi
            worktree=$(cd -- "$worktree" && pwd -P)
            [ "$worktree" != "$current" ] || continue
            if [ -d .git ]; then
                case "$worktree/" in "$current/"*) ;; *)
                    blocked "Linked worktree outside repository: $worktree" ;;
                esac
            fi
            case "$worktree" in *$'\n'*) cache= ;; *) cache=${clean_cache:-} ;; esac
            if [ -n "$cache" ]; then
                if LC_ALL=C grep -Fxq -- "$worktree" "$cache" 2> /dev/null; then continue; fi
                reason=$(awk -F '\t' -v path="$worktree" '$1 == path {print $2; exit}' "$cache.blocked" 2> /dev/null) || true
                [ -z "$reason" ] || blocked "$reason: $worktree"
            fi
            git -C "$worktree" status --porcelain=v1 --untracked-files=all > "$scratch/worktree-status"
            [ ! -s "$scratch/worktree-status" ] || sibling_blocked "Local changes in linked worktree"
            git -C "$worktree" ls-files --stage > "$scratch/worktree-stages"
            if LC_ALL=C grep -q '^160000 ' "$scratch/worktree-stages"; then
                sibling_blocked "Submodule in linked worktree"
            fi
            git -C "$worktree" ls-files -v > "$scratch/worktree-flags"
            if LC_ALL=C grep -q '^[a-zS]' "$scratch/worktree-flags"; then
                sibling_blocked "Index flags in linked worktree"
            fi
            git -C "$worktree" stash list --format='%H' > "$scratch/worktree-stashes"
            [ ! -s "$scratch/worktree-stashes" ] || sibling_blocked "Stashes in linked worktree"
            [ -z "$cache" ] || printf '%s\n' "$worktree" >> "$cache"
            ;;
    esac
done < "$scratch/worktrees"
check_name() {
    remaining=$1
    while :; do
        component=${remaining%%/*}
        case "$(printf '%s' "$component" | LC_ALL=C tr '[:upper:]' '[:lower:]')" in
            .env*|*.pem|*.key|id_*|*credential*|*secret*|*.p12|*token*)
                blocked 'Secret-looking path in snapshot' ;;
        esac
        case "$remaining" in */*) remaining=${remaining#*/} ;; *) break ;; esac
    done
}
cat "$scratch/dirty" "$scratch/untracked" > "$scratch/changed"
while IFS= read -r -d '' file; do
    check_name "$file"
    if [ -d "$file" ] && [ ! -L "$file" ]; then
        blocked 'Embedded repository requires a separate backup proof'
    fi
    if [ -f "$file" ] && [ ! -L "$file" ]; then
        size=$(wc -c < "$file" | tr -d ' ')
        [ "$size" -le 52428800 ] || blocked 'File over 50 MB in snapshot'
    fi
    if git cat-file -e ":$file" 2>/dev/null; then
        size=$(git cat-file -s ":$file")
        [ "$size" -le 52428800 ] || blocked 'Staged file over 50 MB in snapshot'
    fi
done < "$scratch/changed"
check_tree() {
    git diff-tree --no-commit-id --name-only --no-renames -r -z "$1" "$2" > "$scratch/tree-files"
    while IFS= read -r -d '' file; do
        check_name "$file"
        if git cat-file -e "$2:$file" 2>/dev/null; then
            kind=$(git cat-file -t "$2:$file")
            [ "$kind" = blob ] || blocked 'Snapshot contains an embedded repository'
            size=$(git cat-file -s "$2:$file")
            [ "$size" -le 52428800 ] || blocked 'Snapshot file over 50 MB'
        fi
    done < "$scratch/tree-files"
}
if [ "$stash_count" -gt 0 ]; then
    while read -r stash; do
        git diff-tree --root --no-commit-id --name-only --no-renames -r -z "$stash^1" "$stash" > "$scratch/stash-files"
        if git rev-parse --verify -q "$stash^3" > /dev/null; then
            git ls-tree -r --name-only -z "$stash^3" >> "$scratch/stash-files"
        fi
        git diff-tree --no-commit-id --name-only --no-renames -r -z "$stash^1" "$stash^2" >> "$scratch/stash-files"
        while IFS= read -r -d '' file; do
            check_name "$file"
            for tree in "$stash" "$stash^2" "$stash^3"; do
                if git cat-file -e "$tree:$file" 2>/dev/null; then
                    size=$(git cat-file -s "$tree:$file")
                    [ "$size" -le 52428800 ] || blocked 'Stashed file over 50 MB in snapshot'
                fi
            done
        done < "$scratch/stash-files"
    done < "$scratch/stashes"
fi
'''


_caches = {}


@contextmanager
def clean_worktree_cache(host):
    cache = _caches[host.name] = {"path": "${TMPDIR:-/tmp}/coldcleaner-clean-" + uuid.uuid4().hex, "used": False}
    try:
        yield
    finally:
        del _caches[host.name]
        if cache["used"]:
            hosts.run(host, 'rm -f -- "' + cache["path"] + '" "' + cache["path"] + '.blocked"', check=False)


def _scan(host, script, after=""):
    cache = _caches.get(host.name)
    if cache:
        cache["used"] = True
        script += '\nclean_cache="' + cache["path"] + '"'
    output = hosts.run(host, script + "\nphase=probe\n" + _SCAN, timeout=180).stdout
    pairs = _pairs(output)
    if any(key == "blocked" for key, value in pairs):
        return output
    url = next(value for key, value in pairs if key == "remote")
    if not _is_github_url(url):
        if after:
            raise ValueError("Origin changed during backup")
        return output
    effective = hosts.run(hosts.LOCAL,
                          "git ls-remote --get-url -- " + shlex.quote(url), timeout=180).stdout
    effective_url = effective.decode("utf-8", "surrogateescape").rstrip("\n")
    if not _is_github_url(effective_url):
        return output + b"blocked\0origin URL is rewritten away from GitHub\0"
    listing = hosts.run(hosts.LOCAL,
                        "export GIT_TERMINAL_PROMPT=0 GIT_OPTIONAL_LOCKS=0\ngit ls-remote -- " + shlex.quote(url),
                        timeout=180).stdout
    return hosts.run(host, script + "\nlisted_url=" + shlex.quote(url) + "\n" + _SCAN + after,
                     timeout=180, stdin_bytes=listing).stdout


def _pairs(output: bytes) -> list[tuple[str, str]]:
    parts = output.decode("utf-8", "surrogateescape").split("\0")
    if parts.pop() != "" or len(parts) % 2:
        raise ValueError("Incomplete Git response")
    return list(zip(parts[::2], parts[1::2]))


def inspect(host, repo_path) -> RepoState:
    state = RepoState(str(repo_path))
    try:
        pairs = _pairs(_scan(host, "repo=" + shlex.quote(str(repo_path))))
        for key, value in pairs:
            if key == "worktree":
                state.is_worktree = True
            elif key == "remote":
                state.remote_url = value
                state.has_remote = bool(value)
            elif key == "dirty":
                state.dirty_files.append(value)
            elif key == "untracked":
                state.untracked_files.append(value)
            elif key == "missing":
                state.unpushed_branches.append(value)
            elif key == "stashes":
                state.stash_count = int(value)
            elif key == "blocked":
                state.reason = value
                return state
        state.dirty_files = sorted(set(state.dirty_files))
        state.untracked_files = sorted(set(state.untracked_files))
        if not _is_github_url(state.remote_url):
            state.verdict = "no_remote"
            state.reason = "Could be GitHub; no github.com origin"
        elif state.dirty_files or state.untracked_files or state.unpushed_branches or state.stash_count:
            state.verdict = "backup_needed"
            state.reason = "Local changes, refs, or stashes need backup"
        else:
            state.verdict = "on_github"
            state.reason = "Clean; every local ref and worktree HEAD proven on GitHub"
    except subprocess.TimeoutExpired:
        state.reason = "Git inspection timed out"
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        stderr = getattr(error, "stderr", b"") or b""
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        detail = stderr.strip().splitlines()
        state.reason = "Git inspection failed" + (": " + detail[-1] if detail else "")
    return state


_BACKUP = r'''
[ "$remote_url" = "$expected_url" ] || blocked 'Origin changed during backup'
git config --get-all remote.origin.pushurl > "$scratch/pushurls" || [ "$?" -eq 1 ]
[ ! -s "$scratch/pushurls" ] || blocked 'Explicit push URLs require manual backup'
git check-ref-format "refs/coldcleaner/$host_name/test"
export GIT_AUTHOR_NAME='Coldcleaner' GIT_AUTHOR_EMAIL='coldcleaner@localhost'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
date=$(date -u +%Y%m%d)
select_ref() {
    selected=$1
    suffix=0
    while :; do
        old=$(awk -v ref="$selected" '$2 == ref {print $1}' "$scratch/remote")
        [ -n "$old" ] || return 0
        [ "$old" != "$2" ] || return 0
        if [ "$(git cat-file -t "$old" 2>/dev/null)" = commit ] && [ "$(git cat-file -t "$2")" = commit ]; then
            if git merge-base --is-ancestor "$old" "$2"; then return 0; else
                result=$?
                [ "$result" -eq 1 ] || exit "$result"
            fi
        fi
        suffix=$((suffix + 1))
        selected="$1-$suffix"
    done
}
plan() {
    select_ref "$2" "$1"
    printf '%s %s\n' "$1" "$selected" >> "$scratch/plan"
    printf '%s %s\n' "$1" "$selected" >> "$scratch/remote"
    emit ref "$selected"
}
: > "$scratch/plan"
while read -r sha name; do
    if [ "$name" != HEAD ] && ! proven "$sha"; then
        plan "$sha" "refs/coldcleaner/$host_name/$name"
    fi
done < "$scratch/branches"
if [ -s "$scratch/changed" ]; then
    if [ "$apply" = yes ]; then
        index=$(git rev-parse --git-path index)
        export GIT_INDEX_FILE="$scratch/index"
        cp -- "$index" "$GIT_INDEX_FILE"
        staged_tree=$(git write-tree)
        staged=$(printf 'Coldcleaner staged snapshot\n' | git commit-tree "$staged_tree" -p "$head")
        git add -A -- .
        tree=$(git write-tree)
        check_tree "$head" "$staged_tree"
        check_tree "$head" "$tree"
        snapshot=$(printf 'Coldcleaner working snapshot\n' | git commit-tree "$tree" -p "$head" -p "$staged")
        unset GIT_INDEX_FILE
    else
        snapshot=$head
    fi
    plan "$snapshot" "refs/coldcleaner/$host_name/wip/$branch/$date"
fi
n=0
while read -r stash; do
    if ! proven "$stash"; then plan "$stash" "refs/coldcleaner/$host_name/stash/$n-$date"; fi
    n=$((n + 1))
done < "$scratch/stashes"
if [ "$apply" = yes ]; then
    while read -r sha ref; do
        if ! git -c remote.origin.mirror=false -c push.followTags=false -c push.recurseSubmodules=no \
            push --porcelain origin "$sha:$ref" > /dev/null 2> "$scratch/push-error"; then
            if LC_ALL=C grep -Eiq 'could not read (Username|Password)|authentication failed|could not.*credentials' "$scratch/push-error"; then
                blocked "push failed: no GitHub credentials on $host_name"
            fi
            blocked "push failed: $(tail -n 1 "$scratch/push-error")"
        fi
    done < "$scratch/plan"
fi
'''


def backup(host, repo_path, *, apply: bool) -> list[str]:
    state = inspect(host, repo_path)
    if state.verdict == "blocked":
        return ["blocked"]
    if state.verdict == "no_remote":
        return []
    variables = {"repo": str(repo_path), "expected_url": state.remote_url,
                 "host_name": host.name, "apply": "yes" if apply else "no"}
    script = "\n".join(key + "=" + shlex.quote(value) for key, value in variables.items())
    try:
        pairs = _pairs(_scan(host, script, _BACKUP))
        for key, value in pairs:
            if key == "blocked":
                return ["blocked: " + value if value.startswith("push failed:") else "blocked"]
        return [value for key, value in pairs if key == "ref"]
    except (OSError, subprocess.SubprocessError, ValueError):
        return ["blocked"]


def find_repos(host, roots, unreadable=None) -> list[str]:
    script = r'''
set -eu
shopt -s dotglob nullglob
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
for root in ROOTS; do
    case "$root" in '~') root=$HOME ;; '~/'*) root="$HOME/${root#\~/}" ;; esac
    printf '%s\0' "$root" >> "$scratch/queue"
done
[ -f "$scratch/queue" ] || exit 0
while IFS= read -r -d '' root; do
    [ -d "$root" ] || continue
    if [ ! -r "$root" ] || [ ! -x "$root" ]; then
        printf '%s\0' "$root" >&2
        continue
    fi
    if [ -d "$root/.git" ] || [ -f "$root/.git" ]; then
        printf '%s\0' "$root"
        if [ -d "$root/.worktrees" ] && [ ! -L "$root/.worktrees" ]; then
            printf '%s\0' "$root/.worktrees" >> "$scratch/queue"
        fi
        continue
    fi
    for child in "$root"/*; do
        [ -d "$child" ] && [ ! -L "$child" ] || continue
        case "${child##*/}" in
            node_modules) continue ;;
        esac
        printf '%s\0' "$child" >> "$scratch/queue"
    done
done < "$scratch/queue"
'''.replace("ROOTS", " ".join(shlex.quote(str(root)) for root in roots))
    result = hosts.run(host, script)
    if unreadable is not None:
        unreadable.extend(value for value in
                          result.stderr.decode("utf-8", "surrogateescape").split("\0") if value)
    output = result.stdout
    return sorted({value for value in
                   output.decode("utf-8", "surrogateescape").split("\0") if value})


@dataclass
class WorktreeCheck:
    clean: bool
    merged: str
    ignored_kb: int


_WORKTREE = r'''
set -eu
export GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 GIT_NO_REPLACE_OBJECTS=1
cd -- "$repo"
clean=yes
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || clean=no
if git ls-files -v | LC_ALL=C grep -q '^[abcdefghijklmnopqrstuvwxyzS]'; then clean=no; fi
merged=
main=$(awk '$2 == "refs/heads/main" {print $1}' "$scratch/remote")
if [ -n "$main" ] && [ ! -s "$(git rev-parse --git-common-dir)/info/grafts" ] && git rev-parse -q --verify "$main^{commit}" > /dev/null; then
    if git merge-base --is-ancestor HEAD "$main"; then
        merged=ancestor
    elif base=$(git merge-base HEAD "$main") && git diff --quiet HEAD "$main" --; then
        id=$(git diff --no-ext-diff "$base" HEAD | git patch-id --stable | cut -d' ' -f1)
        if [ -n "$id" ] && git log -p --no-merges --no-ext-diff "$base..$main" | git patch-id --stable \
            | cut -d' ' -f1 | LC_ALL=C grep -Fxq "$id"; then
            merged=squash
        fi
    fi
fi
kb=0
git ls-files -z --others --ignored --exclude-standard --directory > "$scratch/ignored"
while IFS= read -r -d '' path; do
    if size=$(du -sk -- "$path" 2> /dev/null); then
        kb=$((kb + ${size%%[[:space:]]*}))
        [ "$kb" -gt 0 ] || kb=1
    else
        kb=-1
        break
    fi
    [ "$kb" -le "$limit" ] || break
done < "$scratch/ignored"
emit clean "$clean"
emit merged "$merged"
emit ignored_kb "$kb"
'''


def worktree_check(host, path, limit_kb) -> WorktreeCheck:
    script = "repo=" + shlex.quote(str(path)) + "\nlimit=" + str(int(limit_kb))
    values = dict(_pairs(_scan(host, script, _WORKTREE)))
    if "blocked" in values:
        return WorktreeCheck(False, "", -1)
    return WorktreeCheck(values["clean"] == "yes", values["merged"], int(values["ignored_kb"]))


def summary(states) -> str:
    def cell(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")

    rows = ["| Path | Verdict | Reason |", "| --- | --- | --- |"]
    rows.extend("| " + " | ".join(map(cell, (s.path, s.verdict, s.reason))) + " |" for s in states)
    return "\n".join(rows)
