#!/usr/bin/env python3
"""
End-to-End Functional, Cryptographic, Security & Store-Readiness Test Suite
for Cloud Space Guard (macOS App Store & Microsoft Store Audit)
"""

import hashlib
import io
import json
import os
import plistlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

import space_guard_agent as csg

BASE_DIR = Path(__file__).resolve().parent


class TestCloudSpaceGuardEndToEnd(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="csg_audit_"))
        self.vault_dir = self.temp_dir / "MockCloudVault"
        self.vault_dir.mkdir(parents=True, exist_ok=True)

        cfg = csg.load_config()
        self.orig_cfg = json.loads(json.dumps(cfg))
        cfg["custom_providers"] = [
            {
                "id": "audit_vault",
                "name": "Audit Test Cloud Vault",
                "tier": "Test Tier",
                "type": "local-mount",
                "vault_path": str(self.vault_dir),
                "account_hint": "Automated Store Audit",
            }
        ]
        csg.save_config(cfg)

    def tearDown(self) -> None:
        csg.save_config(self.orig_cfg)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_telemetry_and_target_math(self) -> None:
        telemetry = csg.get_disk_telemetry(74.0)
        self.assertIn("total_gb", telemetry)
        self.assertIn("free_gb", telemetry)
        self.assertEqual(telemetry["target_free_gb"], 74.0)
        expected_deficit = round(max(0.0, 74.0 - telemetry["free_gb"]), 2)
        self.assertAlmostEqual(telemetry["deficit_gb"], expected_deficit, places=1)

    def test_02_provider_discovery(self) -> None:
        providers = csg.discover_cloud_providers()
        ids = {p["id"] for p in providers}
        self.assertIn("gdrive", ids)
        self.assertIn("icloud", ids)
        self.assertIn("onedrive", ids)
        self.assertIn("dropbox", ids)
        self.assertIn("s3_rclone", ids)
        self.assertIn("audit_vault", ids)

    def test_03_single_file_verify_offload_and_restore(self) -> None:
        sample_file = self.temp_dir / "boot_image_test.bin"
        payload = os.urandom(256 * 1024)
        sample_file.write_bytes(payload)
        expected_sha = hashlib.sha256(payload).hexdigest()

        dry = csg.verify_and_offload_file(str(sample_file), provider_id="audit_vault", dry_run=True)
        self.assertTrue(dry["ok"])
        self.assertEqual(dry["local_sha256"], expected_sha)
        self.assertTrue(sample_file.exists(), "Dry run must never remove the local file")

        res = csg.verify_and_offload_file(str(sample_file), provider_id="audit_vault", leave_stub=True, dry_run=False)
        self.assertTrue(res["ok"], f"Offload failed: {res}")
        self.assertFalse(sample_file.exists(), "Original file should be evicted after SHA-256 verification")

        stub_path = Path(f"{sample_file}.cloudstub")
        self.assertTrue(stub_path.exists(), ".cloudstub receipt must be created")
        stub_meta = json.loads(stub_path.read_text(encoding="utf-8"))
        self.assertEqual(stub_meta["sha256"], expected_sha)
        self.assertTrue(Path(stub_meta["cloud_vault_path"]).exists())

        restored = csg.restore_from_stub(str(stub_path))
        self.assertTrue(restored["ok"], f"Restore failed: {restored}")
        self.assertTrue(sample_file.exists(), "Original file must be restored")
        self.assertFalse(stub_path.exists(), "Stub must be removed after successful restore")
        self.assertEqual(sample_file.read_bytes(), payload)

    def test_04_directory_archive_offload_and_restore(self) -> None:
        proj_dir = self.temp_dir / "SampleProject"
        (proj_dir / "src").mkdir(parents=True)
        (proj_dir / "target" / "debug").mkdir(parents=True)
        (proj_dir / "node_modules" / "pkg").mkdir(parents=True)

        main_rs = proj_dir / "src" / "main.rs"
        main_rs.write_text('fn main() { println!("Hello Store Audit"); }\n', encoding="utf-8")
        (proj_dir / "target" / "debug" / "heavy.bin").write_bytes(b"X" * 100000)
        (proj_dir / "node_modules" / "pkg" / "index.js").write_text("module.exports = {};", encoding="utf-8")

        res = csg.verify_and_offload_file(str(proj_dir), provider_id="audit_vault", leave_stub=True, dry_run=False)
        self.assertTrue(res["ok"], f"Directory offload failed: {res}")
        self.assertFalse(proj_dir.exists(), "Project directory should be removed after archive verification")

        stub_path = Path(f"{proj_dir}.cloudstub")
        self.assertTrue(stub_path.exists())

        restored = csg.restore_from_stub(str(stub_path))
        self.assertTrue(restored["ok"], f"Directory restore failed: {restored}")
        self.assertTrue(main_rs.exists(), "Source file src/main.rs must be restored intact")
        self.assertFalse((proj_dir / "target").exists(), "Excluded target/ cache should not be in cloud archive")
        self.assertFalse((proj_dir / "node_modules").exists(), "Excluded node_modules/ should not be in cloud archive")

    def test_05_tampered_cloud_file_blocks_restore(self) -> None:
        sample_file = self.temp_dir / "critical_doc.pdf"
        sample_file.write_bytes(b"IMPORTANT_PDF_CONTENT_12345")

        res = csg.verify_and_offload_file(str(sample_file), provider_id="audit_vault", leave_stub=True, dry_run=False)
        self.assertTrue(res["ok"])
        stub_path = Path(f"{sample_file}.cloudstub")
        stub_meta = json.loads(stub_path.read_text(encoding="utf-8"))

        cloud_path = Path(stub_meta["cloud_vault_path"])
        cloud_path.write_bytes(b"CORRUPTED_REMOTE_BYTES")

        restored = csg.restore_from_stub(str(stub_path))
        self.assertFalse(restored["ok"], "Tampered cloud file MUST fail SHA-256 verification on restore")
        self.assertIn("SHA-256 mismatch", restored["error"])
        self.assertTrue(stub_path.exists(), "Stub must be preserved when restore verification fails")

    def test_06_live_http_api_endpoints(self) -> None:
        import socketserver
        import threading

        server = socketserver.TCPServer(("127.0.0.1", 0), csg.SpaceGuardRequestHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status?target_gb=74", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(data["ok"])
                self.assertEqual(data["telemetry"]["target_free_gb"], 74.0)

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/ledger", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(data["ok"])
        finally:
            server.shutdown()
            server.server_close()

    def test_07_tar_slip_path_traversal_blocked(self) -> None:
        evil_tar_path = self.temp_dir / "evil.tar.gz"
        with tarfile.open(evil_tar_path, "w:gz") as tar:
            info = tarfile.TarInfo(name="../../escaped_evil.txt")
            payload = b"malicious"
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))

        with tarfile.open(evil_tar_path, "r:gz") as tar:
            with self.assertRaises(ValueError):
                csg._safe_extract_tar(tar, self.temp_dir / "extract_target")

    def test_08_offline_store_ui_no_external_cdn(self) -> None:
        html = (BASE_DIR / "web" / "index.html").read_text(encoding="utf-8")
        external_scripts = re.findall(r'<script[^>]+src=["\']https?://', html, flags=re.I)
        external_links = re.findall(r'<link[^>]+href=["\']https?://', html, flags=re.I)
        self.assertEqual(external_scripts, [], "Store UI must not load external CDN scripts")
        self.assertEqual(external_links, [], "Store UI must not load external CDN stylesheets")

    def test_09_macos_app_store_bundle_and_privacy_manifest(self) -> None:
        app_bundle = BASE_DIR / "CloudSpaceGuard.app"
        self.assertTrue(app_bundle.exists(), "CloudSpaceGuard.app bundle must exist")

        info_plist = app_bundle / "Contents" / "Info.plist"
        with info_plist.open("rb") as f:
            plist = plistlib.load(f)
        self.assertEqual(plist["CFBundleIdentifier"], "com.cloudspaceguard.desktop")
        self.assertEqual(plist["LSApplicationCategoryType"], "public.app-category.utilities")
        self.assertIs(plist["ITSAppUsesNonExemptEncryption"], False)

        # Verify Universal 2 (x86_64 + arm64) binary for Apple Silicon + Intel Macs
        bin_path = app_bundle / "Contents" / "MacOS" / "CloudSpaceGuard"
        lipo_proc = subprocess.run(["lipo", "-archs", str(bin_path)], capture_output=True, text=True)
        self.assertIn("x86_64", lipo_proc.stdout)
        self.assertIn("arm64", lipo_proc.stdout)

        priv_manifest = app_bundle / "Contents" / "Resources" / "PrivacyInfo.xcprivacy"
        with priv_manifest.open("rb") as f:
            priv = plistlib.load(f)
        api_types = {item["NSPrivacyAccessedAPIType"] for item in priv["NSPrivacyAccessedAPITypes"]}
        self.assertIn("NSPrivacyAccessedAPICategoryDiskSpace", api_types)
        self.assertIn("NSPrivacyAccessedAPICategoryFileTimestamp", api_types)

        verify_proc = subprocess.run(
            ["codesign", "--verify", "--deep", "--strict", str(app_bundle)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(verify_proc.returncode, 0, f"codesign verification failed: {verify_proc.stderr}")

    def test_10_microsoft_store_msix_manifest(self) -> None:
        manifest_path = BASE_DIR / "store_packaging" / "windows" / "AppxManifest.xml"
        self.assertTrue(manifest_path.exists())
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        xml_str = manifest_path.read_text(encoding="utf-8")
        self.assertIn("Windows.FullTrustApplication", xml_str)
        self.assertIn("runFullTrust", xml_str)
        self.assertIsNotNone(root)

        assets_dir = BASE_DIR / "store_packaging" / "windows" / "Assets"
        for required_png in [
            "StoreLogo.png",
            "Square44x44Logo.png",
            "Square150x150Logo.png",
            "Wide310x150Logo.png",
            "Square310x310Logo.png",
            "SplashScreen.png",
            "SplashScreen.scale-200.png",
        ]:
            self.assertTrue((assets_dir / required_png).exists(), f"Missing MSIX visual asset: {required_png}")
        self.assertTrue((BASE_DIR / "store_packaging" / "windows" / "cloud_space_guard.ico").exists())
        self.assertTrue((BASE_DIR / "store_packaging" / "cloud_space_guard_icon.svg").exists())
        self.assertTrue((BASE_DIR / "store_packaging" / "splash" / "cloud_space_guard_splash_1280x720.png").exists())

    def test_11_bobfwtools_studio_macos_and_microsoft_store_readiness(self) -> None:
        bob_dir = Path("/Users/bj23/Documents/antigravity/silly-galileo")
        self.assertFalse((bob_dir / "cloud-space-guard").exists(), "Cloud Space Guard must not be inside BobFWTools folder")

        bob_app = bob_dir / "BobFWTools.app"
        self.assertTrue(bob_app.exists(), "BobFWTools.app must exist")

        info_plist = bob_app / "Contents" / "Info.plist"
        with info_plist.open("rb") as f:
            plist = plistlib.load(f)
        self.assertEqual(plist["CFBundleIdentifier"], "com.bobbyblanco.bobfwtools.studio")
        self.assertEqual(plist["LSApplicationCategoryType"], "public.app-category.utilities")
        self.assertIs(plist["ITSAppUsesNonExemptEncryption"], False)

        priv_manifest = bob_app / "Contents" / "Resources" / "PrivacyInfo.xcprivacy"
        self.assertTrue(priv_manifest.exists(), "BobFWTools.app must include PrivacyInfo.xcprivacy")
        with priv_manifest.open("rb") as f:
            priv = plistlib.load(f)
        api_types = {item["NSPrivacyAccessedAPIType"] for item in priv["NSPrivacyAccessedAPITypes"]}
        self.assertIn("NSPrivacyAccessedAPICategoryDiskSpace", api_types)
        self.assertIn("NSPrivacyAccessedAPICategoryFileTimestamp", api_types)

        bob_bin = bob_app / "Contents" / "MacOS" / "BobFWTools"
        lipo_proc = subprocess.run(["lipo", "-archs", str(bob_bin)], capture_output=True, text=True)
        self.assertIn("x86_64", lipo_proc.stdout)
        self.assertIn("arm64", lipo_proc.stdout)

        verify_proc = subprocess.run(
            ["codesign", "--verify", "--deep", "--strict", str(bob_app)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(verify_proc.returncode, 0, f"BobFWTools codesign failed: {verify_proc.stderr}")

        bob_win_manifest = bob_dir / "store_packaging" / "windows" / "AppxManifest.xml"
        self.assertTrue(bob_win_manifest.exists(), "BobFWTools Microsoft Store AppxManifest.xml must exist")
        ET.parse(bob_win_manifest)
        for required_png in [
            "StoreLogo.png",
            "Square44x44Logo.png",
            "Square150x150Logo.png",
            "Wide310x150Logo.png",
            "Square310x310Logo.png",
            "SplashScreen.png",
            "SplashScreen.scale-200.png",
        ]:
            self.assertTrue((bob_dir / "store_packaging" / "windows" / "Assets" / required_png).exists())
        self.assertTrue((bob_dir / "store_packaging" / "windows" / "bob_fw_tools.ico").exists())
        self.assertTrue((bob_dir / "store_packaging" / "bob_fw_tools_icon.svg").exists())
        self.assertTrue((bob_dir / "store_packaging" / "splash" / "bob_fw_tools_splash_1280x720.png").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
