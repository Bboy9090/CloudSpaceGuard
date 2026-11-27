"""Read-only desktop adapter tests; no deletion, offload, or real cloud operations."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "desktop_suite"))
import app_engine

class DesktopReadOnlyContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name)
        (self.bundle / "web").mkdir()
        (self.bundle / "web" / "index.html").write_text("<html>isolated fixture</html>", encoding="utf-8")
        self.agent = MagicMock()
        self.agent.APP_VERSION = "fixture"
        self.agent.get_disk_telemetry.return_value = {"free_gb": 12, "total_gb": 20}
        self.agent.load_config.return_value = {}
        self.agent.discover_cloud_providers.return_value = []
        self.agent.load_ledger.return_value = [{"receipt": "fixture"}]
        self.agent.scan_system_caches.return_value = []
        self.agent.scan_offload_candidates.return_value = []
        with patch.object(app_engine, "_load_agent", return_value=self.agent):
            self.app = app_engine.create_app(self.bundle, {"title": "Test fixture"})
        self.client = self.app.test_client()

    def test_missing_agent_fails_startup(self):
        with patch.object(app_engine, "_load_agent", return_value=None):
            with self.assertRaises(RuntimeError):
                app_engine.create_app(self.bundle, {"title": "Test fixture"})

    def test_health_discloses_mutation_disabled(self):
        r = self.client.get("/api/health")
        self.assertTrue(r.json["real_agent"])
        self.assertIs(r.json["mutation_enabled"], False)

    def test_read_only_routes(self):
        for path in ("/api/caches", "/api/ledger", "/api/candidates?min_mb=25"):
            with self.subTest(path=path):
                r = self.client.get(path)
                self.assertEqual(r.status_code, 200)
                self.assertIs(r.json["ok"], True)
        self.agent.scan_offload_candidates.assert_called_once_with(min_size_mb=25.0)

    def test_status_uses_agent_telemetry(self):
        with patch.object(app_engine.platform_exclusive, "scan_storage_exclusive", return_value={}):
            r = self.client.get("/api/status")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json["telemetry"], {"free_gb": 12, "total_gb": 20})
        self.assertIs(r.json["mutation_enabled"], False)
        self.agent.get_disk_telemetry.assert_called_once()

    def test_invalid_candidate_size_rejected(self):
        for val in ("nan", "inf", "-1", "bad"):
            with self.subTest(val=val):
                self.assertEqual(self.client.get("/api/candidates?min_mb=" + val).status_code, 400)
        self.agent.scan_offload_candidates.assert_not_called()

    def test_mutating_routes_blocked_before_agent(self):
        for path in ("/api/offload", "/api/restore", "/api/clean-cache", "/api/clean-all-safe", "/api/config", "/api/providers/custom"):
            with self.subTest(path=path):
                r = self.client.post(path, json={})
                self.assertEqual(r.status_code, 403)
                self.assertIs(r.json["ok"], False)
        self.agent.verify_and_offload_file.assert_not_called()
        self.agent.restore_from_stub.assert_not_called()
        self.agent.clean_safe_cache.assert_not_called()
        self.agent.save_config.assert_not_called()

    def test_cross_origin_and_nonlocal_host_rejected(self):
        self.assertEqual(self.client.get("/api/ledger", headers={"Origin": "https://example.invalid"}).status_code, 403)
        self.assertEqual(self.client.get("/api/ledger", headers={"Host": "example.invalid"}).status_code, 403)
        self.agent.load_ledger.assert_not_called()

if __name__ == "__main__":
    unittest.main()
