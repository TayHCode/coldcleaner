import os
import shlex
import subprocess
import tempfile
import time
import unittest
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from coldcleaner import gitsafe, hosts, report


class GitSafeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        config = self.root / "gitconfig"
        config.touch()
        environment = patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(config), "GIT_CONFIG_NOSYSTEM": "1", "GIT_ALLOW_PROTOCOL": "file"})
        environment.start()
        self.addCleanup(environment.stop)
        self.repo = self.root / "repo"
        self.remote = self.root / "remote.git"
        self.host = hosts.Host("test-host", "posix")
        self.git("init", "--bare", str(self.remote), cwd=self.root)
        self.git("init", "-b", "main", str(self.repo), cwd=self.root)
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@localhost")
        self.git("config", "commit.gpgsign", "false")
        self.github_url_check = gitsafe._is_github_url
        self.url_patch = patch.object(gitsafe, "_is_github_url",
                                      side_effect=lambda url: url == str(self.remote) or self.github_url_check(url))
        self.url_patch.start()
        self.addCleanup(self.url_patch.stop)
        self.git("remote", "add", "origin", str(self.remote))
        (self.repo / "tracked").write_text("original\n")
        self.git("add", ".")
        self.git("commit", "-m", "initial")
        self.git("push", "origin", "main")

    def git(self, *args, cwd=None):
        result = subprocess.run(["git", *args], cwd=cwd or self.repo,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                                env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        return result.stdout.decode().strip()

    def refs(self):
        return self.git("for-each-ref", "--format=%(refname)", cwd=self.remote).splitlines()

    def commit(self, content="unpushed\n"):
        (self.repo / "tracked").write_text(content)
        self.git("add", "tracked")
        self.git("commit", "-m", "local")
        return self.git("rev-parse", "HEAD")

    def test_report_counts_one_unpushed_branch_without_its_head_marker(self):
        self.commit()
        state = gitsafe.inspect(self.host, self.repo)
        entry = report.HostReport(self.host.name, repos=[state])
        self.assertIn(f'| {self.repo} | backup_needed | 0 | 0 | 1 | 0 |', report.render([entry]))

    def test_origin_rewritten_to_local_repo_is_blocked_in_production(self):
        self.url_patch.stop()
        self.git("remote", "set-url", "origin", "https://github.com/test/x")
        self.git("config", "--global", "url." + str(self.remote) + ".insteadOf", "https://github.com/test/x")
        state = gitsafe.inspect(self.host, self.repo)
        self.assertEqual(state.verdict, "blocked")
        self.assertEqual(state.reason, "origin URL is rewritten away from GitHub")
        self.assertEqual(gitsafe.backup(self.host, self.repo, apply=False), ["blocked"])

    def linked_worktree(self, *, outside=False):
        return self.linked_worktree_at(self.root / "outside" if outside else self.repo / ".worktrees/detached")

    def linked_worktree_at(self, path):
        self.git("config", "core.excludesFile", str(self.root / "ignore"))
        (self.root / "ignore").write_text(".worktrees/\n")
        self.git("worktree", "add", "--detach", str(path))
        return path

    def test_parent_checks_detached_linked_worktree_head(self):
        worktree = self.linked_worktree()
        (worktree / "unique").write_text("unique commit")
        self.git("add", ".", cwd=worktree)
        self.git("commit", "-m", "detached", cwd=worktree)
        state = gitsafe.inspect(self.host, self.repo)
        self.assertEqual(state.verdict, "blocked")
        self.assertIn(str(worktree), state.reason)

    def test_parent_checks_linked_worktree_local_state(self):
        worktree = self.linked_worktree()
        for change in ["dirty", "untracked", "assume-unchanged", "skip-worktree", "stash"]:
            with self.subTest(change=change):
                self.git("reset", "--hard", cwd=worktree)
                if change == "dirty":
                    (worktree / "tracked").write_text("changed")
                elif change == "untracked":
                    (worktree / "extra").write_text("untracked")
                elif change == "stash":
                    (worktree / "tracked").write_text("stashed")
                    self.git("stash", "push", cwd=worktree)
                else:
                    self.git("update-index", "--" + change, "tracked", cwd=worktree)
                state = gitsafe.inspect(self.host, self.repo)
                self.assertEqual(state.verdict, "blocked")
                self.assertIn(str(worktree), state.reason)
                if change == "untracked":
                    (worktree / "extra").unlink()
                elif change in {"assume-unchanged", "skip-worktree"}:
                    self.git("update-index", "--no-" + change, "tracked", cwd=worktree)

    def test_missing_worktree_head_is_still_proven(self):
        worktree = self.linked_worktree()
        (worktree / "tracked").write_text("unique")
        self.git("commit", "-am", "unique", cwd=worktree)
        worktree.rename(self.root / "moved")
        state = gitsafe.inspect(self.host, self.repo)
        self.assertEqual(state.verdict, "blocked")
        self.assertIn(str(worktree), state.reason)

    def test_parent_does_not_orphan_external_worktree(self):
        worktree = self.linked_worktree(outside=True)
        state = gitsafe.inspect(self.host, self.repo)
        self.assertEqual(state.verdict, "blocked")
        self.assertIn(str(worktree), state.reason)

    def test_tag_only_and_custom_refs_are_proven_and_backed_up(self):
        for ref in ["refs/tags/local", "refs/notes/local", "refs/custom/local"]:
            with self.subTest(ref=ref):
                self.git("checkout", "--detach")
                sha = self.commit(ref + "\n")
                self.git("update-ref", ref, sha)
                self.git("checkout", "main")
                self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "backup_needed")
                expected = "refs/coldcleaner/test-host/" + ref.removeprefix("refs/")
                self.assertEqual(gitsafe.backup(self.host, self.repo, apply=False), [expected])
                self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True), [expected])
                self.assertEqual(self.git("rev-parse", expected, cwd=self.remote), sha)
                self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "on_github")

    def test_annotated_tag_object_and_conflicts_are_preserved(self):
        self.git("tag", "-a", "local", "-m", "first annotation")
        first = self.git("rev-parse", "refs/tags/local")
        ref = "refs/coldcleaner/test-host/tags/local"
        self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True), [ref])
        self.git("tag", "-d", "local")
        self.git("tag", "-a", "local", "-m", "second annotation")
        second = self.git("rev-parse", "refs/tags/local")
        self.assertNotEqual(first, second)
        self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True), [ref + "-1"])
        self.assertEqual(self.git("rev-parse", ref, cwd=self.remote), first)
        self.assertEqual(self.git("rev-parse", ref + "-1", cwd=self.remote), second)
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "on_github")

    def test_noncommit_custom_ref_is_backed_up(self):
        blob = self.git("rev-parse", "HEAD:tracked")
        self.git("update-ref", "refs/custom/blob", blob)
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "backup_needed")
        ref = "refs/coldcleaner/test-host/custom/blob"
        self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True), [ref])
        self.assertEqual(self.git("rev-parse", ref, cwd=self.remote), blob)
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "on_github")

    def test_clean_and_missing_proven_linked_worktrees_are_safe(self):
        worktree = self.linked_worktree()
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "on_github")
        worktree.rename(self.root / "moved")
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "on_github")

    def test_discovery_finds_project_under_tmp(self):
        project = self.root / "tmp/real-project"
        self.git("init", str(project))
        self.assertEqual(gitsafe.find_repos(self.host, [self.root / "tmp"]), [str(project)])
        self.assertIn(str(project), gitsafe.find_repos(self.host, [self.root]))

    def test_nonignored_nested_repo_prevents_parent_cleanup(self):
        nested = self.repo / "data/clone"
        self.git("clone", "--branch", "main", str(self.remote), str(nested))
        self.assertEqual(gitsafe.find_repos(self.host, [self.repo]), [str(self.repo)])
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "blocked")

    def test_clean_pushed_repo_uses_coordinator_listing_and_two_host_scans(self):
        with patch.object(hosts, "run", wraps=hosts.run) as run:
            state = gitsafe.inspect(self.host, self.repo)
        self.assertEqual(state.verdict, "on_github")
        self.assertEqual(state.remote_url, str(self.remote))
        self.assertEqual(state.unpushed_branches, [])
        self.assertEqual(run.call_count, 4)
        listing_call = run.call_args_list[2]
        self.assertEqual(listing_call.args[0], hosts.LOCAL)
        self.assertIn("git ls-remote -- " + shlex.quote(str(self.remote)), listing_call.args[1])
        self.assertIn(b"refs/heads/main", run.call_args_list[3].kwargs["stdin_bytes"])

    def test_wsl_payload_fits_windows_command_line_and_backs_up(self):
        real_run = hosts.run
        wsl = hosts.Host("test-host", "wsl", "fake-windows")

        def run_local(host, script, **kwargs):
            self.assertLess(len(hosts.argv(host, script)[-1]), 8191)
            return real_run(self.host, script, **kwargs)

        with patch.object(hosts, "run", side_effect=run_local):
            self.assertEqual(gitsafe.inspect(wsl, self.repo).verdict, "on_github")
            self.commit()
            (self.repo / "new").write_text("snapshot\n")
            refs = gitsafe.backup(wsl, self.repo, apply=True)
        self.assertEqual(refs[0], "refs/coldcleaner/test-host/main")
        self.assertEqual(self.git("show", refs[1] + ":new", cwd=self.remote), "snapshot")

    def test_unpushed_commit_is_backed_up_under_coldcleaner(self):
        sha = self.commit()
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "backup_needed")
        refs = gitsafe.backup(self.host, self.repo, apply=True)
        self.assertEqual(refs, ["refs/coldcleaner/test-host/main"])
        self.assertEqual(self.git("rev-parse", refs[0], cwd=self.remote), sha)
        self.assertEqual(self.git("rev-parse", "refs/heads/main", cwd=self.remote),
                         self.git("rev-parse", "HEAD^"))
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "on_github")

    def test_snapshot_preserves_worktree_index_and_staged_version(self):
        (self.repo / "tracked").write_text("staged\n")
        self.git("add", "tracked")
        (self.repo / "tracked").write_text("unstaged\n")
        (self.repo / "new file\nwith newline").write_text("untracked\n")
        (self.repo / ".gitignore").write_text("ignored\n")
        (self.repo / "ignored").write_text("ignored contents\n")
        before_index = (self.repo / ".git/index").read_bytes()
        before_files = {p.name: p.read_bytes() for p in self.repo.iterdir() if p.is_file()}
        before_status = self.git("status", "--porcelain=v1", "-z")
        refs = gitsafe.backup(self.host, self.repo, apply=True)
        self.assertEqual(len(refs), 1)
        snapshot = self.git("rev-parse", refs[0], cwd=self.remote)
        self.assertEqual(self.git("show", snapshot + ":tracked", cwd=self.remote), "unstaged")
        self.assertEqual(self.git("show", snapshot + "^2:tracked", cwd=self.remote), "staged")
        self.assertEqual(self.git("show", snapshot + ":new file\nwith newline", cwd=self.remote), "untracked")
        self.assertNotIn("ignored", self.git("ls-tree", "--name-only", snapshot, cwd=self.remote).splitlines())
        self.assertEqual((self.repo / ".git/index").read_bytes(), before_index)
        self.assertEqual({p.name: p.read_bytes() for p in self.repo.iterdir() if p.is_file()}, before_files)
        self.assertEqual(self.git("status", "--porcelain=v1", "-z"), before_status)
        self.assertEqual(self.git("stash", "list"), "")
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "backup_needed")

    def test_secret_blocks_all_pushes_including_unpushed_branch(self):
        self.commit()
        (self.repo / ".env").write_text("private fixture\n")
        before_refs = self.refs()
        state = gitsafe.inspect(self.host, self.repo)
        self.assertEqual(state.verdict, "blocked")
        self.assertIn("Secret-looking", state.reason)
        self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True), ["blocked"])
        self.assertEqual(self.refs(), before_refs)

    def test_oversize_and_secret_directory_are_blocked(self):
        large = self.repo / "large"
        with large.open("wb") as handle:
            handle.truncate(52428801)
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "blocked")
        large.unlink()
        folder = self.repo / "credentials"
        folder.mkdir()
        (folder / "config").write_text("private fixture")
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "blocked")

    def test_no_remote(self):
        self.git("remote", "remove", "origin")
        state = gitsafe.inspect(self.host, self.repo)
        self.assertEqual(state.verdict, "no_remote")
        self.assertFalse(state.has_remote)
        self.assertIn("Could be GitHub", state.reason)
        self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True), [])

    def test_stashes_are_pushed_and_unchanged(self):
        (self.repo / "tracked").write_text("stashed\n")
        (self.repo / "extra").write_text("extra\n")
        self.git("stash", "push", "-u", "-m", "fixture")
        stash = self.git("rev-parse", "stash@{0}")
        self.assertEqual(gitsafe.inspect(self.host, self.repo).stash_count, 1)
        refs = gitsafe.backup(self.host, self.repo, apply=True)
        self.assertEqual(len(refs), 1)
        self.assertIn("/stash/0-", refs[0])
        self.assertEqual(self.git("rev-parse", refs[0], cwd=self.remote), stash)
        self.assertEqual(self.git("show", refs[0] + "^3:extra", cwd=self.remote), "extra")
        self.assertEqual(self.git("rev-parse", "stash@{0}"), stash)
        self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True), [])
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "backup_needed")

    def test_every_stash_is_backed_up(self):
        for number in range(2):
            (self.repo / "tracked").write_text(str(number))
            self.git("stash", "push", "-m", str(number))
        shas = self.git("stash", "list", "--format=%H").splitlines()
        refs = gitsafe.backup(self.host, self.repo, apply=True)
        self.assertEqual(len(refs), 2)
        self.assertEqual([self.git("rev-parse", ref, cwd=self.remote) for ref in refs], shas)

    def test_backup_does_not_follow_tags_or_mirror_other_refs(self):
        self.commit()
        self.git("tag", "-a", "local-tag", "-m", "local tag")
        self.git("config", "push.followTags", "true")
        self.git("config", "remote.origin.mirror", "true")
        self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True),
                         ["refs/coldcleaner/test-host/main", "refs/coldcleaner/test-host/tags/local-tag"])
        self.assertEqual(self.refs(), ["refs/coldcleaner/test-host/main",
                                      "refs/coldcleaner/test-host/tags/local-tag", "refs/heads/main"])
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "on_github")

    def test_secret_in_stash_blocks_before_branch_push(self):
        (self.repo / ".env.local").write_text("private fixture")
        self.git("stash", "push", "-u")
        self.commit()
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "blocked")
        self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True), ["blocked"])
        self.assertEqual(self.refs(), ["refs/heads/main"])

    def test_discovery_includes_nested_worktree_and_skips_exclusions(self):
        worktree = self.repo / ".worktrees/x"
        self.git("worktree", "add", "-b", "work", str(worktree))
        self.git("init", str(self.repo / "node_modules/excluded"))
        self.git("init", str(self.repo / ".venv/excluded"))
        self.git("init", str(self.repo / ".git/hidden"))
        with patch.object(hosts, "run", wraps=hosts.run) as run:
            found = gitsafe.find_repos(self.host, [self.repo, worktree, self.root / "absent"])
        self.assertEqual(found, sorted([str(self.repo), str(worktree)]))
        self.assertEqual(run.call_count, 1)
        state = gitsafe.inspect(self.host, worktree)
        self.assertTrue(state.is_worktree)
        self.assertEqual(state.verdict, "blocked")
        self.assertIn(str(self.repo), state.reason)

    def test_dry_run_does_not_push_or_write_objects_or_index(self):
        self.commit()
        (self.repo / "new").write_text("new\n")
        before_refs = self.refs()
        before_objects = sorted(p.relative_to(self.repo) for p in (self.repo / ".git/objects").rglob("*") if p.is_file())
        before_index = (self.repo / ".git/index").read_bytes()
        refs = gitsafe.backup(self.host, self.repo, apply=False)
        date = datetime.now(timezone.utc).strftime("%Y%m%d")
        self.assertEqual(refs, ["refs/coldcleaner/test-host/main",
                               "refs/coldcleaner/test-host/wip/main/" + date])
        self.assertEqual(self.refs(), before_refs)
        self.assertEqual((self.repo / ".git/index").read_bytes(), before_index)
        self.assertEqual(sorted(p.relative_to(self.repo) for p in (self.repo / ".git/objects").rglob("*") if p.is_file()), before_objects)

    def test_conflicting_backup_ref_uses_suffix_without_force(self):
        first = self.commit("first\n")
        ref = gitsafe.backup(self.host, self.repo, apply=True)[0]
        self.git("reset", "--hard", "HEAD^")
        second = self.commit("second\n")
        self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True), [ref + "-1"])
        self.assertEqual(self.git("rev-parse", ref, cwd=self.remote), first)
        self.assertEqual(self.git("rev-parse", ref + "-1", cwd=self.remote), second)
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "on_github")

    def test_missing_remote_objects_cannot_prove_local_commit(self):
        other = self.root / "other"
        self.git("clone", str(self.remote), str(other), cwd=self.root)
        self.git("checkout", "main", cwd=other)
        self.git("config", "user.name", "Other", cwd=other)
        self.git("config", "user.email", "other@localhost", cwd=other)
        (other / "new").write_text("remote change\n")
        self.git("add", ".", cwd=other)
        self.git("commit", "-m", "remote", cwd=other)
        self.git("push", "origin", "main", cwd=other)
        self.git("config", "remote.origin.promisor", "true")
        state = gitsafe.inspect(self.host, self.repo)
        self.assertEqual(state.verdict, "backup_needed")
        self.assertIn("main", state.unpushed_branches)

    def test_branch_tip_reachable_through_remote_descendant_is_proven(self):
        self.git("branch", "older")
        self.commit()
        self.git("push", "origin", "main")
        state = gitsafe.inspect(self.host, self.repo)
        self.assertEqual(state.verdict, "on_github")
        self.assertEqual(state.unpushed_branches, [])

    def test_detached_head_must_be_proven(self):
        self.git("checkout", "--detach")
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "on_github")
        self.commit()
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "blocked")

    def test_all_local_branches_are_checked(self):
        self.git("checkout", "-b", "local-only")
        self.commit()
        self.git("checkout", "main")
        self.assertEqual(gitsafe.inspect(self.host, self.repo).unpushed_branches, ["local-only"])
        self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True), ["refs/coldcleaner/test-host/local-only"])
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "on_github")

    def test_errors_are_blocked(self):
        state = gitsafe.inspect(self.host, self.root / "not-a-repo")
        self.assertEqual(state.verdict, "blocked")
        self.assertIn("No such file or directory", state.reason)

    def test_hidden_index_changes_are_blocked(self):
        self.git("update-index", "--assume-unchanged", "tracked")
        (self.repo / "tracked").write_text("hidden\n")
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "blocked")
        self.git("update-index", "--no-assume-unchanged", "tracked")
        self.git("update-index", "--skip-worktree", "tracked")
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "blocked")

    def test_staged_file_absent_from_worktree_is_preserved(self):
        (self.repo / "extra").write_text("staged only\n")
        self.git("add", "extra")
        (self.repo / "extra").unlink()
        refs = gitsafe.backup(self.host, self.repo, apply=True)
        self.assertEqual(self.git("show", refs[0] + "^2:extra", cwd=self.remote), "staged only")
        self.assertNotIn("extra", self.git("ls-tree", "--name-only", refs[0], cwd=self.remote).splitlines())

    def test_embedded_repo_and_submodule_are_blocked(self):
        embedded = self.repo / "nested"
        self.git("clone", "--branch", "main", str(self.remote), str(embedded))
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "blocked")
        self.git("add", "nested")
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "blocked")
        self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True), ["blocked"])

    def test_explicit_push_url_cannot_redirect_backup(self):
        self.commit()
        self.git("config", "remote.origin.pushurl", str(self.root / "elsewhere.git"))
        self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True), ["blocked"])
        self.assertEqual(self.refs(), ["refs/heads/main"])

    def test_multiple_origin_urls_cannot_prove_github_reachability(self):
        self.git("config", "remote.origin.url", str(self.remote))
        self.git("config", "--add", "remote.origin.url", "https://github.com/test/x")
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "blocked")
        self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True), ["blocked"])
        self.assertEqual(self.refs(), ["refs/heads/main"])

    def test_utf8_locale_does_not_treat_normal_index_entries_as_hidden(self):
        locales = subprocess.check_output(["locale", "-a"], text=True).splitlines()
        locale = next((value for value in locales if value.lower().startswith("en_us.") and
                       "utf" in value.lower()), None)
        if locale is None:
            self.skipTest("No en_US UTF-8 locale installed")
        real_run = hosts.run

        def localized(host, script, **kwargs):
            return real_run(host, "shopt -u globasciiranges\nexport LC_ALL=" + shlex.quote(locale) + "\n" + script, **kwargs)

        with patch.object(hosts, "run", side_effect=localized):
            self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "on_github")
            self.git("update-index", "--assume-unchanged", "tracked")
            self.assertEqual(gitsafe.inspect(self.host, self.repo).reason,
                             "Index flags can hide local changes")

    def test_host_without_credentials_uses_coordinator_and_reports_failed_push(self):
        fake = self.root / "bin"
        fake.mkdir()
        git = subprocess.check_output(["which", "git"], text=True).strip()
        (fake / "git").write_text("#!/bin/bash\n" +
            "for arg; do case \"$arg\" in ls-remote|push) " +
            "echo \"fatal: could not read Username for 'https://github.com': terminal prompts disabled\" >&2; exit 128 ;; esac; done\n" +
            "exec " + shlex.quote(git) + " \"$@\"\n")
        (fake / "git").chmod(0o755)
        remote_host = hosts.Host("credentialless-host", "posix", "fake")
        real_run = hosts.run
        calls = []

        def credentialless(host, script, **kwargs):
            calls.append((host, script))
            if host == remote_host:
                script = "export PATH=" + shlex.quote(str(fake)) + ":$PATH\n" + script
            return real_run(self.host, script, **kwargs)

        with patch.object(hosts, "run", side_effect=credentialless):
            self.assertEqual(gitsafe.inspect(remote_host, self.repo).verdict, "on_github")
            self.commit()
            before = self.refs()
            self.assertEqual(gitsafe.backup(remote_host, self.repo, apply=True),
                             ["blocked: push failed: no GitHub credentials on credentialless-host"])
            self.assertEqual(self.refs(), before)
        listing_calls = [(host, script) for host, script in calls if "git ls-remote" in script]
        self.assertTrue(listing_calls)
        self.assertTrue(all(host == hosts.LOCAL for host, script in listing_calls))

    def test_non_github_origin_is_never_queried(self):
        self.git("remote", "set-url", "origin", "https://example.invalid/test/x")
        with patch.object(hosts, "run", wraps=hosts.run) as run:
            state = gitsafe.inspect(self.host, self.repo)
        self.assertEqual(state.verdict, "no_remote")
        self.assertTrue(all("git ls-remote" not in call.args[1] for call in run.call_args_list))

    def test_discovery_prunes_repo_data_but_keeps_worktrees(self):
        worktree = self.repo / ".worktrees/x"
        self.git("worktree", "add", "-b", "work", str(worktree))
        self.git("init", str(self.repo / "data/queue/live/fixes/clone"))
        self.git("init", str(worktree / "data/clone"))
        expected = [str(self.repo), str(worktree)]
        for name in [".scratch", "node_modules", ".venv", "venv", ".cache", "tmp", ".tox", "target"]:
            path = self.root / name / "clone"
            self.git("init", str(path))
            if name != "node_modules":
                expected.append(str(path))
        self.assertEqual(gitsafe.find_repos(self.host, [self.root]), sorted(expected))

    def test_unreadable_discovery_is_reported_and_other_repos_still_found(self):
        denied = self.root / "denied"
        denied.mkdir()
        self.addCleanup(denied.chmod, 0o700)
        denied.chmod(0)
        if os.access(denied, os.R_OK):
            self.skipTest("Current user can read mode-000 directories")
        unreadable = []
        self.assertEqual(gitsafe.find_repos(self.host, [denied, self.repo], unreadable), [str(self.repo)])
        self.assertEqual(unreadable, [str(denied)])

    def merged_worktree(self, squash):
        worktree = self.root / "feature"
        self.git("worktree", "add", "-b", "feature", str(worktree))
        for content in ("one\n", "two\n"):
            (worktree / "tracked").write_text(content)
            self.git("commit", "-am", "feature", cwd=worktree)
        if squash:
            self.git("merge", "--squash", "feature")
            self.git("commit", "-m", "squashed feature")
        else:
            self.git("merge", "--ff-only", "feature")
        self.git("push", "origin", "main")
        return worktree

    def test_worktree_check_detects_squash_merge(self):
        worktree = self.merged_worktree(squash=True)
        self.assertEqual(gitsafe.worktree_check(self.host, worktree, 1024), gitsafe.WorktreeCheck(True, "squash", 0))

    def test_worktree_check_detects_ancestor_merge_and_unmerged_work(self):
        worktree = self.merged_worktree(squash=False)
        self.assertEqual(gitsafe.worktree_check(self.host, worktree, 1024).merged, "ancestor")
        (worktree / "tracked").write_text("three\n")
        self.git("commit", "-am", "more", cwd=worktree)
        self.assertEqual(gitsafe.worktree_check(self.host, worktree, 1024).merged, "")

    def test_worktree_check_rejects_reverted_squash(self):
        worktree = self.merged_worktree(squash=True)
        self.git("revert", "--no-edit", "HEAD")
        self.git("push", "origin", "main")
        self.assertEqual(gitsafe.worktree_check(self.host, worktree, 1024).merged, "")

    def test_worktree_check_rejects_whitespace_only_patch_match(self):
        worktree = self.merged_worktree(squash=True)
        (worktree / "tracked").write_text("two \n")
        self.git("commit", "-am", "meaningful whitespace", cwd=worktree)
        self.assertEqual(gitsafe.worktree_check(self.host, worktree, 1024).merged, "")

    def assert_remote_rewind_retains_worktree(self, squash):
        worktree = self.merged_worktree(squash=squash)
        initial = self.git("rev-list", "--max-parents=0", "HEAD")
        self.git("update-ref", "refs/heads/main", initial, cwd=self.remote)
        self.git("checkout", "--detach", initial)
        self.assertEqual(gitsafe.worktree_check(self.host, worktree, 1024).merged, "")
        self.assertTrue(worktree.is_dir())

    def test_worktree_check_rejects_main_rewound_on_remote(self):
        self.assert_remote_rewind_retains_worktree(squash=False)

    def test_worktree_check_rejects_squash_rewound_on_remote(self):
        self.assert_remote_rewind_retains_worktree(squash=True)

    def test_worktree_check_retains_zero_block_ignored_files(self):
        worktree = self.merged_worktree(squash=True)
        (self.repo / ".git/info/exclude").write_text("ignored\n")
        path = worktree / "ignored"
        for size in (0, 1024 * 1024):
            with self.subTest(size=size):
                with path.open('wb') as stream:
                    stream.truncate(size)
                self.assertGreater(gitsafe.worktree_check(self.host, worktree, 1024).ignored_kb, 0)

    def test_worktree_check_reports_dirty_and_ignored_size(self):
        worktree = self.merged_worktree(squash=True)
        (worktree / ".gitignore").write_text("output/\n")
        self.assertFalse(gitsafe.worktree_check(self.host, worktree, 1024).clean)
        (worktree / ".gitignore").unlink()
        (self.repo / ".git/info/exclude").write_text("output/\n")
        (worktree / "output").mkdir()
        bench = worktree / "output/bench.bin"
        bench.write_bytes(os.urandom(3 * 1024 * 1024))
        deadline = time.monotonic() + 30
        while bench.stat().st_blocks * 512 < 3 * 1024 * 1024 and time.monotonic() < deadline:
            time.sleep(0.1)
        check = gitsafe.worktree_check(self.host, worktree, 1024)
        self.assertTrue(check.clean)
        self.assertGreater(check.ignored_kb, 1024)

    def test_origin_changed_to_non_github_during_backup_is_blocked(self):
        self.commit()
        real_run = hosts.run
        scans = 0

        def change_origin(host, script, **kwargs):
            nonlocal scans
            if host == self.host:
                scans += 1
                if scans == 3:
                    self.git("remote", "set-url", "origin", "https://example.invalid/test/x")
            return real_run(host, script, **kwargs)

        with patch.object(hosts, "run", side_effect=change_origin):
            self.assertEqual(gitsafe.backup(self.host, self.repo, apply=True), ["blocked"])
        self.assertEqual(self.refs(), ["refs/heads/main"])

    def test_deep_worktrees_do_not_exhaust_file_descriptors(self):
        expected = [str(self.repo)]
        parent = self.repo
        for number in range(18):
            parent = parent / ".worktrees" / str(number)
            self.git("init", str(parent))
            expected.append(str(parent))
        real_run = hosts.run

        def limited(host, script, **kwargs):
            return real_run(host, "ulimit -n 32\n" + script, **kwargs)

        with patch.object(hosts, "run", side_effect=limited):
            self.assertEqual(gitsafe.find_repos(self.host, [self.repo]), sorted(expected))

    def test_unborn_branch_has_actionable_reason(self):
        unborn = self.root / "unborn"
        self.git("init", "-b", "main", str(unborn))
        state = gitsafe.inspect(self.host, unborn)
        self.assertEqual(state.verdict, "blocked")
        self.assertEqual(state.reason, "No commits on current branch")

    def test_failure_includes_last_stderr_line(self):
        failure = subprocess.CalledProcessError(128, "git", stderr=b"details\nfatal: broken object\n")
        with patch.object(hosts, "run", side_effect=failure):
            state = gitsafe.inspect(self.host, self.repo)
        self.assertEqual(state.verdict, "blocked")
        self.assertEqual(state.reason, "Git inspection failed: fatal: broken object")

    @contextmanager
    def traced(self):
        trace = self.root / "trace"
        real_run = hosts.run

        def run(host, script, **kwargs):
            return real_run(host, f"exec 9>>{shlex.quote(str(trace))}\nBASH_XTRACEFD=9\nset -x\n" + script, **kwargs)

        with patch.object(gitsafe.hosts, "run", run):
            yield lambda: trace.read_text(errors="replace").splitlines()

    def cache_scope(self):
        scope = getattr(gitsafe, "clean_worktree_cache", None)
        return scope(self.host) if scope else nullcontext()

    def traced_inspect(self):
        with self.traced() as lines:
            state = gitsafe.inspect(self.host, self.repo)
        return state, lines()

    def test_scan_shell_work_does_not_grow_with_tracked_file_count(self):
        tracked = 3000
        self.linked_worktree()
        for index in range(tracked):
            (self.repo / f"file{index}").write_text("x")
        self.git("add", ".")
        self.git("commit", "-m", "many files")
        self.git("push", "origin", "main")
        state, lines = self.traced_inspect()
        self.assertEqual(state.verdict, "on_github")
        self.assertLess(len(lines), tracked)

    def test_sibling_worktree_state_is_checked_once_per_cache_scope(self):
        tmp = self.root / "tmp"
        tmp.mkdir()
        worktrees = []
        for index in range(4):
            path = self.repo / f".worktrees/w{index}"
            self.linked_worktree_at(path)
            worktrees.append(path)
        everyone = [self.repo, *worktrees]
        with patch.dict(os.environ, {"TMPDIR": str(tmp)}), self.traced() as lines:
            with self.cache_scope():
                states = [gitsafe.inspect(self.host, path) for path in everyone]
            self.assertEqual(list(tmp.iterdir()), [])
        self.assertEqual({state.verdict for state in states}, {"on_github"})
        self.assertEqual(sum("status --porcelain=v1" in line and " -C " in line for line in lines()), len(everyone))

    def test_dirty_sibling_stays_blocking_and_is_checked_once_per_cache_scope(self):
        worktree = self.linked_worktree()
        (worktree / "tracked").write_text("changed")
        with self.traced() as lines, self.cache_scope():
            for _ in range(3):
                state = gitsafe.inspect(self.host, self.repo)
                self.assertEqual(state.verdict, "blocked")
                self.assertEqual(state.reason, f"Local changes in linked worktree: {worktree}")
            self.assertEqual(sum("status --porcelain=v1" in line and " -C " in line for line in lines()), 1)
        self.assertEqual(gitsafe.inspect(self.host, self.repo).reason, state.reason)
        (worktree / "tracked").write_text("original\n")
        self.assertEqual(gitsafe.inspect(self.host, self.repo).verdict, "on_github")

    def test_ancestor_proof_does_not_spawn_a_process_per_remote_tip(self):
        tips = 5
        ancestors = 30
        for index in range(ancestors):
            self.git("commit", "--allow-empty", "-m", f"chain{index}")
            self.git("branch", f"ancestor{index}", "HEAD")
        tree = self.git("rev-parse", "HEAD^{tree}")
        refspecs = [f"{self.git('commit-tree', tree, '-m', f'side{index}')}:refs/heads/side{index}"
                    for index in range(tips)]
        self.git("push", "origin", "main", *refspecs)
        state, lines = self.traced_inspect()
        self.assertEqual(state.verdict, "on_github")
        self.assertLess(sum("merge-base --is-ancestor" in line for line in lines), ancestors)

    def test_summary_and_github_url_validation(self):
        state = gitsafe.inspect(self.host, self.repo)
        state.path = "a|b\nc"
        self.assertIn("| a\\|b c | on_github | Clean; every local ref and worktree HEAD proven on GitHub |", gitsafe.summary([state]))
        for url in ["https://github.com/test/x", "git@github.com:test/x.git", "ssh://git@github.com/test/x"]:
            self.assertTrue(gitsafe._is_github_url(url))
        for url in ["https://github.com.evil/test/x", "https://github.com@evil/test/x", "file:///github.com/test/x", "/local/repo"]:
            self.assertFalse(gitsafe._is_github_url(url))


if __name__ == "__main__":
    unittest.main()
