import hashlib
import io
import json
import os
import shutil
import socketserver
import tarfile
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import space_guard_agent as guard


class DataSafetyLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.vault = self.root / "vault"
        self.vault.mkdir()
        for name, value in [
            ("STATE_DIR", self.state),
            ("CONFIG_FILE", self.state / "config.json"),
            ("LEDGER_FILE", self.state / "ledger.json"),
        ]:
            p = patch.object(guard, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(
            guard,
            "discover_cloud_providers",
            return_value=[{"id": "test", "name": "Test Vault", "vault_path": str(self.vault)}],
        )
        p.start()
        self.addCleanup(p.stop)

    def test_interrupted_copy_preserves_source_and_leaves_no_receipt(self):
        src = self.root / "important.dat"
        src.write_bytes(b"A" * 1024 * 1024)
        receipt = Path(str(src) + ".cloudstub")

        def fail_copy(source, target):
            target.write(source.read(512))
            raise IOError("Simulated disk error or process interruption during copy")

        with patch("shutil.copyfileobj", side_effect=fail_copy):
            res = guard.verify_and_offload_file(str(src), "test", leave_stub=True)

        self.assertFalse(res["ok"])
        self.assertIn("Simulated disk error", res["error"])
        self.assertTrue(res["source_retained"])
        self.assertTrue(src.exists())
        self.assertEqual(src.read_bytes(), b"A" * 1024 * 1024)
        self.assertFalse(receipt.exists(), "Receipt must never be created if copy fails")
        # Partial copy path is recorded for manual recovery if created
        if res.get("partial_copy"):
            partial = Path(res["partial_copy"])
            self.assertTrue(partial.exists(), "Partial file is preserved for manual recovery")

    def test_interrupted_archive_preserves_source_and_leaves_no_receipt(self):
        src = self.root / "proj"
        src.mkdir()
        (src / "code.py").write_text("print('hello')")
        receipt = Path(str(src) + ".cloudstub")

        def fail_add(self, name, arcname=None, recursive=True, *, filter=None):
            raise IOError("Simulated archive interruption")

        with patch.object(tarfile.TarFile, "add", fail_add):
            res = guard.verify_and_offload_file(str(src), "test", leave_stub=True)

        self.assertFalse(res["ok"])
        self.assertIn("Simulated archive interruption", res["error"])
        self.assertTrue(res["source_retained"])
        self.assertTrue(src.exists())
        self.assertTrue((src / "code.py").exists())
        self.assertFalse(receipt.exists())

    def test_corrupted_archive_rejected_on_restore_without_creating_destination(self):
        src = self.root / "corrupt_proj"
        src.mkdir()
        (src / "data.txt").write_text("data")
        res = guard.verify_and_offload_file(str(src), "test", leave_stub=True)
        self.assertTrue(res["ok"])
        vault_path = Path(res["entry"]["cloud_destination"])
        stub_path = Path(str(src) + ".cloudstub")

        # Corrupt the archive by flipping bytes
        raw = vault_path.read_bytes()
        vault_path.write_bytes(raw[:100] + b"\x00" * 50 + raw[150:])

        # Remove source to test restore
        shutil.rmtree(src)
        r = guard.restore_from_stub(str(stub_path))
        self.assertFalse(r["ok"])
        self.assertIn("SHA-256 mismatch", r["error"])
        self.assertFalse(src.exists(), "Destination must not be created on corrupted restore")
        self.assertTrue(stub_path.exists(), "Receipt must be preserved when restore fails")

    def test_concurrent_source_modification_during_copy_aborts(self):
        src = self.root / "concurrent_file.txt"
        src.write_text("original content")
        receipt = Path(str(src) + ".cloudstub")

        real_compute = guard.compute_sha256
        calls = []

        def modify_on_second_hash(path, chunk_size=4 * 1024 * 1024):
            digest = real_compute(path, chunk_size)
            calls.append(path)
            if len(calls) == 2:  # After copy, modify the source
                src.write_text("tampered content")
            return digest

        with patch.object(guard, "compute_sha256", side_effect=modify_on_second_hash):
            res = guard.verify_and_offload_file(str(src), "test", leave_stub=True)

        self.assertFalse(res["ok"])
        self.assertIn("changed during verification", res["error"])
        self.assertTrue(src.exists())
        self.assertFalse(receipt.exists())

    def test_missing_provider_aborts_without_touching_source(self):
        src = self.root / "solo.txt"
        src.write_text("solo")
        res = guard.verify_and_offload_file(str(src), "non_existent_provider")
        self.assertFalse(res["ok"])
        self.assertIn("Unknown cloud provider", res["error"])
        self.assertTrue(src.exists())

    def test_restore_when_existing_directory_blocks_and_preserves_existing(self):
        src = self.root / "preserve_proj"
        src.mkdir()
        (src / "v1.txt").write_text("v1")
        res = guard.verify_and_offload_file(str(src), "test", leave_stub=True)
        self.assertTrue(res["ok"])
        stub_path = Path(str(src) + ".cloudstub")

        # Now replace with new work (v2)
        (src / "v1.txt").write_text("v2 - new work")
        (src / "v2.txt").write_text("extra work")

        r = guard.restore_from_stub(str(stub_path))
        self.assertFalse(r["ok"])
        self.assertIn("Restore destination already exists", r["error"])
        self.assertEqual((src / "v1.txt").read_text(), "v2 - new work", "Existing work must never be overwritten")
        self.assertTrue((src / "v2.txt").exists())
        self.assertTrue(stub_path.exists())

    def test_bulk_clean_endpoint_disabled_fail_closed(self):
        server = socketserver.TCPServer(("127.0.0.1", 0), guard.SpaceGuardRequestHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/clean-all-safe",
                data=b"{}",
                headers={
                    "Content-Type": "application/json",
                    "Origin": f"http://127.0.0.1:{port}",
                },
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as err:
                urllib.request.urlopen(req, timeout=5)
            try:
                self.assertEqual(err.exception.code, 403)
                payload = json.loads(err.exception.read().decode("utf-8"))
            finally:
                err.exception.close()
            self.assertFalse(payload["ok"])
            self.assertIn("disabled", payload["error"].lower())
        finally:
            server.shutdown()
            server.server_close()

    def test_risky_caches_marked_review_and_rejected_by_clean_safe_cache(self):
        fake_home = self.root / "fake_home"
        xdg_cache = fake_home / ".cache"
        xdg_cache.mkdir(parents=True)
        (xdg_cache / "session.bin").write_bytes(b"X" * (2 * 1024 * 1024))

        proj_dir = fake_home / "Projects" / "demo_app"
        nm_dir = proj_dir / "node_modules"
        target_dir = proj_dir / "target"
        nm_dir.mkdir(parents=True)
        target_dir.mkdir(parents=True)
        (nm_dir / "dep.js").write_bytes(b"Y" * (11 * 1024 * 1024))
        (target_dir / "app.bin").write_bytes(b"Z" * (11 * 1024 * 1024))

        with patch.object(Path, "home", return_value=fake_home):
            caches = {c["id"]: c for c in guard.scan_system_caches(force_refresh=True)}
            for risky_id in ("linux_xdg_cache", "projects_node_modules", "projects_rust_targets"):
                self.assertIn(risky_id, caches)
                self.assertEqual(caches[risky_id]["safe_level"], "review")
                res = guard.clean_safe_cache(risky_id)
                self.assertFalse(res["ok"])
                self.assertIn("manual review", res["error"].lower())

        self.assertTrue((xdg_cache / "session.bin").exists())
        self.assertTrue((nm_dir / "dep.js").exists())
        self.assertTrue((target_dir / "app.bin").exists())

    def test_non_normalized_archive_paths_rejected_on_restore(self):
        target = self.root / "proj"
        for bad_name in ("proj/./secret.txt", "proj\\evil.txt"):
            vault_archive = self.vault / f"{bad_name.replace('/', '_').replace(chr(92), '_')}.tar.gz"
            with tarfile.open(vault_archive, "w:gz") as tar:
                root_info = tarfile.TarInfo("proj")
                root_info.type = tarfile.DIRTYPE
                tar.addfile(root_info)
                file_info = tarfile.TarInfo(bad_name)
                payload = b"bad"
                file_info.size = len(payload)
                tar.addfile(file_info, io.BytesIO(payload))

            stub_path = self.root / f"bad_{abs(hash(bad_name))}.cloudstub"
            stub_path.write_text(
                json.dumps(
                    {
                        "original_path": str(target),
                        "cloud_vault_path": str(vault_archive),
                        "sha256": guard.compute_sha256(vault_archive),
                        "is_directory_archive": True,
                    }
                ),
                encoding="utf-8",
            )
            res = guard.restore_from_stub(str(stub_path))
            self.assertFalse(res["ok"], f"Non-normalized archive member {bad_name} must be rejected")
            self.assertFalse(target.exists())
            self.assertTrue(stub_path.exists())

    def test_clean_safe_cache_measures_actual_freed_bytes(self):
        cache_dir = self.root / "mock_npm_cache"
        cache_dir.mkdir()
        (cache_dir / "pkg1.tgz").write_bytes(b"A" * 51200)
        sub = cache_dir / "nested"
        sub.mkdir()
        (sub / "pkg2.tgz").write_bytes(b"B" * 40960)
        expected_size = guard.dir_size_bytes(cache_dir)

        mock_caches = [
            {
                "id": "npm_cache",
                "name": "Node.js npm Package Cache",
                "path": str(cache_dir),
                "category": "Developer Cache",
                "safe_level": "safe",
                "clean_cmd": "npm cache clean --force",
                "description": "Test cache",
                "size_bytes": expected_size + 999999,  # Stale estimate must not be trusted
            }
        ]
        with patch.object(guard, "scan_system_caches", return_value=mock_caches):
            res = guard.clean_safe_cache("npm_cache")

        actual_after = guard.dir_size_bytes(cache_dir)
        self.assertTrue(res["ok"], f"clean_safe_cache failed: {res}")
        self.assertEqual(res["after_bytes"], actual_after)
        self.assertEqual(res["freed_bytes"], max(0, expected_size - actual_after))
        self.assertGreater(res["freed_bytes"], 0)
        self.assertNotEqual(res["freed_bytes"], mock_caches[0]["size_bytes"])
        self.assertEqual(list(cache_dir.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
