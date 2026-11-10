import concurrent.futures
import contextlib
import io
import csv
import os
import shlex
import subprocess
import tarfile
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from coldcleaner import cli, hosts, store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.nas = self.root / "nas"
        self.host = hosts.Host("test-local", "posix")
        self.host_patch = patch.dict(hosts.HOSTS, {self.host.name: self.host, 'winhost-wsl': hosts.Host('winhost-wsl', 'wsl', 'winhost')})
        self.host_patch.start()
        self.addCleanup(self.host_patch.stop)
        self.source = self.root / "source folder's data"
        self.source.mkdir(mode=0o750)
        (self.source / "deep").mkdir()
        (self.source / "deep" / "payload.bin").write_bytes(bytes(range(256)) * 32)
        (self.source / "empty").mkdir(mode=0o700)
        (self.source / "link").symlink_to("deep/payload.bin")
        (self.source / ".hidden").write_bytes(b"hidden\n")
        (self.source / "executable").write_bytes(b"#!/bin/sh\nexit 0\n")
        (self.source / "executable").chmod(0o751)

    def archive(self, **kwargs):
        return store.archive(self.host, self.source, apply=True, nas_root=self.nas, **kwargs)

    def rows(self):
        with (self.nas / "INDEX.csv").open(newline="") as stream:
            return list(csv.DictReader(stream))

    def snapshot(self, root):
        result = {}
        for path in [root, *root.rglob("*")]:
            name = str(path.relative_to(root))
            if path.is_symlink():
                result[name] = ("symlink", os.readlink(path))
            elif path.is_dir():
                result[name] = ("directory", path.stat().st_mode & 0o777)
            else:
                result[name] = ("file", path.stat().st_mode & 0o777, path.read_bytes())
        return result

    def test_archive_round_trip_preserves_bytes_symlink_directories_and_permissions(self):
        expected = self.snapshot(self.source)
        record = self.archive()
        self.assertFalse(self.source.exists())
        self.assertTrue(Path(record.archive_path).is_file())
        self.assertEqual(record.file_count, 7)
        self.assertEqual(record.archive_bytes, Path(record.archive_path).stat().st_size)
        self.assertEqual(self.rows()[0]["status"], "stored")
        restored = store.restore(record.id, self.nas)
        self.assertEqual(restored.status, "restored")
        self.assertEqual(self.snapshot(self.source), expected)
        self.assertEqual(self.rows()[0]["status"], "restored")
        self.assertTrue(Path(record.archive_path).exists())

    def test_legacy_wsl_archive_recovers_to_explicit_posix_host(self):
        expected = self.snapshot(self.source)
        record = replace(self.archive(), host='winhost-wsl')
        store._write_index(self.nas, [record])
        with self.assertRaisesRegex(ValueError, 'Windows WSL execution is retired'):
            store.restore(record.id, self.nas)
        for member in (None, self.source.name + '/deep/payload.bin'):
            with self.subTest(member=member):
                target = self.root / ('whole recovery' if member is None else 'member recovery')
                args = ['restore', record.id, '--to-host', self.host.name, '--to', str(target)]
                if member:
                    args += ['--member', member]
                output = io.StringIO()
                with patch.object(cli.rules, 'load', return_value=dict(nas_root=str(self.nas))), \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                    try:
                        result = cli.main(args)
                    except SystemExit as error:
                        result = error.code
                self.assertEqual(result, 0, output.getvalue())
                self.assertIn('to test-local:' + str(target), output.getvalue())
                if member is None:
                    self.assertEqual(self.snapshot(target), expected)
                else:
                    self.assertEqual((target / 'deep/payload.bin').read_bytes(), bytes(range(256)) * 32)
                    self.assertFalse((target / 'executable').exists())
                self.assertEqual(self.rows()[0]['host'], 'winhost-wsl')
                self.assertEqual(self.rows()[0]['status'], 'restored')
                self.assertTrue(Path(record.archive_path).is_file())

    def test_cross_host_recovery_requires_destination_and_posix_host(self):
        record = replace(self.archive(), host='winhost-wsl')
        store._write_index(self.nas, [record])
        with self.assertRaisesRegex(ValueError, 'explicit destination path'):
            store.restore(record.id, self.nas, to_host=self.host.name)
        with self.assertRaisesRegex(ValueError, 'recovery host must be POSIX'):
            store.restore(record.id, self.nas, to=str(self.root / 'target'), to_host='winhost-wsl')
        self.assertEqual(self.rows()[0]['host'], 'winhost-wsl')
        self.assertEqual(self.rows()[0]['status'], 'stored')
        self.assertFalse((self.root / 'target').exists())
        self.assertTrue(Path(record.archive_path).is_file())

    def test_dry_run_writes_and_deletes_nothing(self):
        expected = self.snapshot(self.source)
        record = store.archive(self.host, self.source, nas_root=self.nas)
        self.assertEqual(record.file_count, 7)
        self.assertGreater(record.original_bytes, 0)
        self.assertEqual(record.archive_bytes, 0)
        self.assertFalse(self.nas.exists())
        self.assertEqual(self.snapshot(self.source), expected)

    def test_missing_source_leaves_no_archive_or_index(self):
        with self.assertRaises(subprocess.CalledProcessError):
            store.archive(self.host, self.root / "missing", apply=True, nas_root=self.nas)
        self.assertFalse(self.nas.exists())
        self.assertTrue(self.source.exists())

    def test_compressor_failure_leaves_source_and_no_index_or_partial(self):
        expected = self.snapshot(self.source)
        original_popen = subprocess.Popen

        def failing_popen(args, **kwargs):
            if args[0] == "zstd" and "-dc" not in args:
                return original_popen(["sh", "-c", "cat >/dev/null; exit 9"], **kwargs)
            return original_popen(args, **kwargs)

        with patch.object(store.subprocess, "Popen", side_effect=failing_popen):
            with self.assertRaisesRegex(RuntimeError, "archive stream failed"):
                self.archive()
        self.assertEqual(self.snapshot(self.source), expected)
        self.assertFalse((self.nas / "INDEX.csv").exists())
        self.assertEqual(list(self.nas.rglob("*.partial")), [])
        self.assertEqual(list(self.nas.rglob("*.tar.zst")), [])
        self.assertEqual(list(self.nas.rglob("*.files.txt")), [])

    def test_compressor_launch_failure_leaves_source_and_no_partial(self):
        original_popen = subprocess.Popen

        def missing_compressor(args, **kwargs):
            if args[0] == "zstd":
                raise FileNotFoundError("zstd is missing")
            return original_popen(args, **kwargs)

        with patch.object(store.subprocess, "Popen", side_effect=missing_compressor):
            with self.assertRaisesRegex(FileNotFoundError, "zstd is missing"):
                self.archive()
        self.assertTrue(self.source.exists())
        self.assertFalse((self.nas / "INDEX.csv").exists())
        self.assertEqual(list(self.nas.rglob("*.partial")), [])

    def test_compressor_launch_failure_is_reported_when_signals_are_denied(self):
        original_popen = subprocess.Popen

        def missing_compressor(args, **kwargs):
            if args[0] == "zstd":
                raise FileNotFoundError("zstd is missing")
            return original_popen(args, **kwargs)

        denied = PermissionError(13, "Permission denied")
        with patch.object(original_popen, "terminate", side_effect=denied), \
                patch.object(store.subprocess, "Popen", side_effect=missing_compressor):
            with self.assertRaises(OSError) as raised:
                self.archive()
        self.assertEqual(str(raised.exception), "zstd is missing")
        self.assertTrue(self.source.exists())
        self.assertFalse((self.nas / "INDEX.csv").exists())
        self.assertEqual(list(self.nas.rglob("*.partial")), [])

    def test_original_bytes_counts_content_not_disk_allocation(self):
        with (self.source / "sparse").open("wb") as stream:
            stream.truncate(4 * 1024 * 1024)
        record = store.archive(self.host, self.source, nas_root=self.nas)
        self.assertGreaterEqual(record.original_bytes, 4 * 1024 * 1024)

    def test_tar_producer_failure_with_successful_compression_keeps_source(self):
        expected = self.snapshot(self.source)
        popen = hosts.popen

        def failing_tar(host, script, **kwargs):
            return popen(host, script + "; exit 9", **kwargs)

        with patch.object(hosts, "popen", side_effect=failing_tar):
            with self.assertRaisesRegex(RuntimeError, "archive stream failed"):
                self.archive()
        self.assertEqual(self.snapshot(self.source), expected)
        self.assertFalse((self.nas / "INDEX.csv").exists())
        self.assertEqual(list(self.nas.rglob("*.partial")), [])
        self.assertEqual(list(self.nas.rglob("*.tar.zst")), [])

    def test_same_size_edit_after_verification_keeps_new_source_and_no_record(self):
        measure = store._measure
        calls = 0

        def edit_after_measure(*args):
            nonlocal calls
            result = measure(*args)
            calls += 1
            if calls == 2:
                (self.source / ".hidden").write_bytes(b"edited\n")
            return result

        with patch.object(store, "_measure", side_effect=edit_after_measure):
            with self.assertRaisesRegex(RuntimeError, "source changed"):
                self.archive()
        self.assertEqual((self.source / ".hidden").read_bytes(), b"edited\n")
        self.assertEqual(store.find("", self.nas), [])
        self.assertEqual(list(self.nas.rglob("*.tar.zst")), [])
        self.assertEqual(list(self.nas.rglob("*.partial")), [])
        self.assertEqual(list(self.root.glob(".coldcleaner-archive.*")), [])

    def test_marker_failure_keeps_source_and_no_record(self):
        run = hosts.run

        def fail_marker(host, script, **kwargs):
            if "mktemp" in script:
                raise subprocess.CalledProcessError(1, script)
            return run(host, script, **kwargs)

        with patch.object(hosts, "run", side_effect=fail_marker):
            with self.assertRaises(subprocess.CalledProcessError):
                self.archive()
        self.assertTrue(self.source.exists())
        self.assertEqual(store.find("", self.nas), [])
        self.assertEqual(list(self.nas.rglob("*.partial")), [])
        self.assertEqual(list(self.nas.rglob("*.tar.zst")), [])

    def test_listing_failure_does_not_delete_source(self):
        with patch.object(store, "_listing", side_effect=RuntimeError("bad archive")):
            with self.assertRaisesRegex(RuntimeError, "bad archive"):
                self.archive()
        self.assertTrue((self.source / "deep" / "payload.bin").exists())
        self.assertFalse((self.nas / "INDEX.csv").exists())
        self.assertEqual(list(self.nas.rglob("*.partial")), [])

    def test_file_count_mismatch_leaves_source(self):
        listing = store._listing
        with patch.object(store, "_listing", side_effect=lambda *args: listing(*args)[:-1]):
            with self.assertRaisesRegex(RuntimeError, "file count"):
                self.archive()
        self.assertTrue(self.source.exists())
        self.assertFalse((self.nas / "INDEX.csv").exists())

    def test_index_failure_leaves_source(self):
        with patch.object(store, "_write_index", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                self.archive()
        self.assertTrue(self.source.exists())
        self.assertFalse((self.nas / "INDEX.csv").exists())
        self.assertEqual(list(self.nas.rglob("*.tar.zst")), [])

    def test_find_folder_and_deep_member_case_insensitively(self):
        record = self.archive()
        self.assertEqual([item.id for item in store.find("FOLDER'S DATA", self.nas)], [record.id])
        found = store.find("PAYLOAD.BIN", self.nas)
        self.assertEqual([item.id for item in found], [record.id])
        self.assertEqual(found[0].matches, (self.source.name + "/deep/payload.bin",))
        self.assertEqual(store.find("does-not-exist", self.nas), [])

    def test_restore_refuses_existing_directory_and_dangling_symlink(self):
        record = self.archive()
        self.source.mkdir()
        (self.source / "keep").write_bytes(b"leave alone")
        with self.assertRaisesRegex(FileExistsError, "restore destination already exists:"):
            store.restore(record.id, self.nas)
        self.assertEqual((self.source / "keep").read_bytes(), b"leave alone")
        target = self.root / "dangling"
        target.symlink_to("missing")
        with self.assertRaisesRegex(FileExistsError, "restore destination already exists:"):
            store.restore(record.id, self.nas, to=str(target))
        self.assertTrue(target.is_symlink())
        target = self.root / "existing file"
        target.write_bytes(b"leave file alone")
        with self.assertRaisesRegex(FileExistsError, "restore destination already exists:"):
            store.restore(record.id, self.nas, to=str(target))
        self.assertEqual(target.read_bytes(), b"leave file alone")
        self.assertEqual(list(self.root.glob(".coldcleaner-restore.*")), [])
        self.assertEqual(self.rows()[0]["status"], "stored")

    def test_restore_names_the_missing_host_table_when_the_archive_host_is_not_configured(self):
        record = self.archive()
        del hosts.HOSTS[self.host.name]
        guidance = r"archive host 'test-local' is not configured; add \[hosts\.test-local\]"
        with self.assertRaisesRegex(LookupError, guidance):
            store.restore(record.id, self.nas)
        Path(record.archive_path).with_suffix('.sha256.json').write_text('{}')
        with self.assertRaisesRegex(LookupError, guidance):
            store.restore(record.id, self.nas)
        self.assertFalse(self.source.exists())
        self.assertEqual(self.rows()[0]["status"], "stored")

    def test_restore_setup_failure_is_not_reported_as_existing_destination(self):
        record = self.archive()
        parent = self.root / "not a directory"
        parent.write_bytes(b"keep")
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            store.restore(record.id, self.nas, to=str(parent / "target"))
        self.assertEqual(raised.exception.returncode, 1)
        self.assertEqual(parent.read_bytes(), b"keep")
        self.assertEqual(self.rows()[0]["status"], "stored")

    def test_member_restore_to_different_root(self):
        expected = (self.source / "deep" / "payload.bin").read_bytes()
        record = self.archive()
        target = self.root / "restored elsewhere"
        store.restore(record.id, self.nas, to=str(target), member=self.source.name + "/deep/payload.bin")
        self.assertEqual((target / "deep" / "payload.bin").read_bytes(), expected)
        self.assertFalse((target / "executable").exists())
        self.assertFalse(self.source.exists())

    def hardlink_archive(self):
        first = self.source / "one" / "payload"
        second = self.source / "two" / "payload"
        first.parent.mkdir()
        second.parent.mkdir()
        first.parent.chmod(0o750)
        second.parent.chmod(0o750)
        first.write_bytes(b"hardlinked payload\n")
        first.chmod(0o640)
        os.link(first, second)
        record = self.archive()
        with tarfile.open(record.archive_path, "r:zst") as archive:
            linked = next(item for item in archive if item.islnk())
        return record, linked.name

    def test_member_restore_hardlink_without_selected_target(self):
        for directory in (False, True):
            with self.subTest(directory=directory):
                self.source.mkdir(exist_ok=True)
                record, linked = self.hardlink_archive()
                member = str(Path(linked).parent) + "/" if directory else linked
                target = self.root / "archive" if directory else self.source
                restored = store.restore(record.id, self.nas, to=str(target), member=member)
                payload = target.joinpath(*Path(linked).parts[1:])
                self.assertEqual(payload.read_bytes(), b"hardlinked payload\n")
                self.assertEqual(payload.stat().st_mode & 0o777, 0o640)
                if directory:
                    self.assertEqual(payload.parent.stat().st_mode & 0o777, 0o750)
                self.assertEqual({str(path.relative_to(target)) for path in target.rglob("*")},
                                 {str(Path(linked).parts[1]), str(Path(*Path(linked).parts[1:]))})
                self.assertEqual(restored.status, "restored")
                self.assertEqual(self.rows()[-1]["status"], "restored")
                self.assertEqual(list(self.root.glob(".coldcleaner-restore.*")), [])
                if not directory:
                    self.source.rename(self.root / "first restore")
                    self.source.mkdir()

    def test_member_hardlink_restore_failure_cleans_staging_and_keeps_status(self):
        record, member = self.hardlink_archive()
        popen = hosts.popen

        def failing_extraction(host, script, **kwargs):
            return popen(host, script + "; exit 9", **kwargs)

        with patch.object(hosts, "popen", side_effect=failing_extraction):
            with self.assertRaisesRegex(RuntimeError, "stream failed"):
                store.restore(record.id, self.nas, member=member)
        self.assertFalse(self.source.exists())
        self.assertEqual(list(self.root.glob(".coldcleaner-restore.*")), [])
        self.assertEqual(self.rows()[0]["status"], "stored")

    def test_member_hardlink_restore_refuses_existing_destination(self):
        record, member = self.hardlink_archive()
        self.source.mkdir()
        (self.source / "keep").write_bytes(b"leave alone")
        with self.assertRaisesRegex(FileExistsError, "restore destination already exists:"):
            store.restore(record.id, self.nas, member=member)
        self.assertEqual(list(self.source.iterdir()), [self.source / "keep"])
        self.assertEqual((self.source / "keep").read_bytes(), b"leave alone")
        self.assertEqual(list(self.root.glob(".coldcleaner-restore.*")), [])
        self.assertEqual(self.rows()[0]["status"], "stored")

    def test_restore_rejects_missing_or_unsafe_member(self):
        record = self.archive()
        for member in ("../outside", "/absolute", self.source.name + "/../outside", self.source.name + "/missing"):
            with self.subTest(member=member), self.assertRaises(ValueError):
                store.restore(record.id, self.nas, member=member)
        self.assertFalse(self.source.exists())

    def test_corrupt_archive_restore_leaves_no_target_or_staging(self):
        record = self.archive()
        Path(record.archive_path).write_bytes(b"not a zstd stream")
        with self.assertRaisesRegex(RuntimeError, "stream failed"):
            store.restore(record.id, self.nas)
        self.assertFalse(self.source.exists())
        self.assertEqual(list(self.root.glob(".coldcleaner-restore.*")), [])
        self.assertEqual(self.rows()[0]["status"], "stored")

    def test_mid_restore_failure_leaves_sibling_and_no_destination(self):
        record = self.archive()
        sibling = self.root / "keep"
        sibling.write_bytes(b"other process")
        popen = hosts.popen

        def failing_extraction(host, script, **kwargs):
            return popen(host, script + "; exit 9", **kwargs)

        with patch.object(hosts, "popen", side_effect=failing_extraction):
            with self.assertRaisesRegex(RuntimeError, "stream failed"):
                store.restore(record.id, self.nas)
        self.assertEqual(sibling.read_bytes(), b"other process")
        self.assertFalse(self.source.exists())
        self.assertEqual(list(self.root.glob(".coldcleaner-restore.*")), [])
        self.assertEqual(self.rows()[0]["status"], "stored")

    def test_publish_race_preserves_other_process_destination(self):
        record = self.archive()
        target = shlex.quote(str(self.source))
        run = hosts.run

        def racing_publish(host, script, **kwargs):
            if script.startswith("set -euo pipefail"):
                script = (f'tar() {{ mkdir -p {target}; printf keep > {target}/foreign; return 9; }}; '
                          f'mv() {{ mkdir -p {target}; printf keep > {target}/foreign; command mv "$@"; }}; '
                          + script)
            return run(host, script, **kwargs)

        with patch.object(hosts, "run", side_effect=racing_publish):
            with self.assertRaises(subprocess.CalledProcessError):
                store.restore(record.id, self.nas)
        self.assertEqual((self.source / "foreign").read_bytes(), b"keep")
        self.assertEqual(list(self.source.iterdir()), [self.source / "foreign"])
        self.assertEqual(list(self.root.glob(".coldcleaner-restore.*")), [])
        self.assertEqual(self.rows()[0]["status"], "stored")

    def test_enforce_cap_oldest_first_and_preserves_unindexed_files(self):
        first = self.archive()
        store.restore(first.id, self.nas)
        second = self.archive()
        untouched = self.nas / "unindexed.tar.zst"
        untouched.write_bytes(b"keep me")
        predicted = store.enforce_cap(self.nas, second.archive_bytes, apply=False)
        self.assertEqual([item.id for item in predicted], [first.id])
        self.assertTrue(Path(first.archive_path).exists())
        expired = store.enforce_cap(self.nas, second.archive_bytes, apply=True)
        self.assertEqual([item.id for item in expired], [first.id])
        self.assertFalse(Path(first.archive_path).exists())
        self.assertTrue(Path(second.archive_path).exists())
        self.assertEqual([row["id"] for row in self.rows()], [first.id, second.id])
        self.assertEqual([row["status"] for row in self.rows()], ["expired", "stored"])
        self.assertEqual(untouched.read_bytes(), b"keep me")
        with self.assertRaisesRegex(ValueError, "expired"):
            store.restore(first.id, self.nas)

    def test_cap_preview_does_not_write_to_empty_read_only_nas(self):
        self.nas.mkdir(mode=0o555)
        self.addCleanup(self.nas.chmod, 0o755)
        self.assertEqual(store.enforce_cap(self.nas, 0), [])
        self.assertEqual(list(self.nas.iterdir()), [])

    def test_cap_preview_preserves_index_and_archives_without_creating_lock(self):
        record = self.archive()
        (self.nas / '.index.lock').unlink()
        before = self.snapshot(self.nas)
        predicted = store.enforce_cap(self.nas, 0)
        self.assertEqual([item.id for item in predicted], [record.id])
        self.assertEqual(predicted[0].status, 'expired')
        self.assertEqual(self.snapshot(self.nas), before)

    def test_concurrent_archives_do_not_lose_index_rows(self):
        sources = [self.root / f"concurrent {index}" for index in range(8)]
        for index, source in enumerate(sources):
            source.mkdir()
            (source / "payload").write_bytes(str(index).encode())
        def archive(source):
            return store.archive(self.host, source, apply=True, nas_root=self.nas)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            records = list(pool.map(archive, sources))
        self.assertEqual(len(self.rows()), 8)
        self.assertEqual({row["id"] for row in self.rows()}, {record.id for record in records})
        self.assertTrue(all(Path(record.archive_path).exists() for record in records))
        self.assertTrue(all(not source.exists() for source in sources))

    def test_expiry_is_recorded_before_interrupted_deletion(self):
        record = self.archive()
        unlink = Path.unlink

        def interrupt(path, **kwargs):
            if str(path) == record.archive_path:
                raise OSError("interrupted deletion")
            return unlink(path, **kwargs)

        with patch.object(Path, "unlink", autospec=True, side_effect=interrupt):
            with self.assertRaisesRegex(OSError, "interrupted deletion"):
                store.enforce_cap(self.nas, 0, apply=True)
        self.assertEqual(self.rows()[0]["status"], "expired")
        self.assertTrue(Path(record.archive_path).exists())

    def test_enforce_cap_retries_expired_files_even_when_under_cap(self):
        record = self.archive()
        with store._index_lock(self.nas):
            store._write_index(self.nas, [replace(record, status="expired")])
        self.assertEqual(store.enforce_cap(self.nas, record.archive_bytes), [])
        self.assertTrue(Path(record.archive_path).exists())
        self.assertEqual(store.enforce_cap(self.nas, record.archive_bytes, apply=True), [])
        self.assertFalse(Path(record.archive_path).exists())
        self.assertFalse(store._manifest_path(Path(record.archive_path)).exists())
        self.assertEqual(self.rows()[0]["status"], "expired")

    def test_expiry_index_failure_keeps_archive_and_manifest(self):
        record = self.archive()
        with patch.object(store, "_write_index", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                store.enforce_cap(self.nas, 0, apply=True)
        self.assertTrue(Path(record.archive_path).exists())
        self.assertTrue(store._manifest_path(Path(record.archive_path)).exists())
        self.assertEqual(self.rows()[0]["status"], "stored")

    def test_slug_collision_gets_numeric_suffix(self):
        first = self.archive()
        store.restore(first.id, self.nas)
        second = self.archive()
        self.assertEqual(second.archive_path, first.archive_path.removesuffix(".tar.zst") + "-2.tar.zst")

    def test_compression_level_uses_bytes_and_case_insensitive_extensions(self):
        self.assertEqual(store.compression_level(self.host, self.source, [".jpg", "gguf"]), 10)
        (self.source / "model.GGUF").write_bytes(b"x" * 16384)
        self.assertEqual(store.compression_level(self.host, self.source, [".jpg", "gguf"]), 1)
        record = self.archive(level=1)
        self.assertGreater(record.archive_bytes, 0)

    def test_rejects_powershell_and_unsafe_paths_before_writing(self):
        with self.assertRaisesRegex(ValueError, "PowerShell"):
            store.archive(hosts.Host("winhost", "powershell", "winhost"), self.source, nas_root=self.nas)
        for path in ("/", "relative", "/a/../b"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                store.archive(self.host, path, nas_root=self.nas)
        self.assertFalse(self.nas.exists())

    def test_archive_path_cannot_escape_nas(self):
        record = self.archive()
        outside = self.root / "outside.tar.zst"
        outside.write_bytes(b"do not delete")
        with store._index_lock(self.nas):
            store._write_index(self.nas, [replace(record, archive_path=str(outside))])
        with self.assertRaisesRegex(ValueError, "escapes"):
            store.enforce_cap(self.nas, 0, apply=True)
        self.assertEqual(outside.read_bytes(), b"do not delete")


if __name__ == "__main__":
    unittest.main()
