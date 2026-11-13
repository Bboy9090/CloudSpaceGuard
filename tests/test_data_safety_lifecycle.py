import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
