"""Isolated negative controls for the product identity gate."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("identity_gate", ROOT / "scripts/verify_product_identity.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ProductIdentityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.meta = self.root / "desktop_suite/app_meta.json"
        self.meta.parent.mkdir()
        self.contract = self.root / "product-identity.json"
        self.meta.write_bytes((ROOT / "desktop_suite/app_meta.json").read_bytes())
        self.contract.write_bytes((ROOT / "product-identity.json").read_bytes())
        self.ui = self.root / "desktop_suite/ui/index.html"
        self.ui.parent.mkdir(exist_ok=True)
        self.ui.write_bytes((ROOT / "desktop_suite/ui/index.html").read_bytes())
        for relative in ["web/index.html","store_packaging/windows/AppxManifest.xml","store_packaging/linux/com.cloudspaceguard.desktop.desktop","build_macos_app.sh"]:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())

    def test_current_source(self):
        self.assertEqual(gate.verify(ROOT), 8)

    def test_old_name(self):
        data = json.loads(self.meta.read_text())
        data["title"] = "Cloud Space Guard"
        self.meta.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "Identity mismatch"):
            gate.verify(self.root)

    def test_changed_slug(self):
        data = json.loads(self.meta.read_text())
        data["slug"] = "new-slug"
        self.meta.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "Identity mismatch"):
            gate.verify(self.root)

    def test_missing_source(self):
        self.meta.unlink()
        with self.assertRaisesRegex(ValueError, "Missing metadata"):
            gate.verify(self.root)

    def test_missing_check(self):
        data = json.loads(self.contract.read_text())
        data["checks"].pop()
        self.contract.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "Required identity checks missing"):
            gate.verify(self.root)

    def test_duplicate_key(self):
        self.meta.write_text('{"title":"Legacy","title":"CloudSpaceGuard"}')
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            gate.verify(self.root)

    def test_contract_rename(self):
        data = json.loads(self.contract.read_text())
        data["public_name"] = "Cloud Space Guard"
        self.contract.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "Unresolved or changed"):
            gate.verify(self.root)

    def test_old_ui_title(self):
        self.ui.write_text("<title>Cloud Space Guard</title>")
        with self.assertRaisesRegex(ValueError, "Display surface mismatch"):
            gate.verify(self.root)

    def test_missing_ui(self):
        self.ui.unlink()
        with self.assertRaisesRegex(ValueError, "Missing or unsafe"):
            gate.verify(self.root)

    def test_legacy_packaging_display_name(self):
        p = self.root / "store_packaging/windows/AppxManifest.xml"
        p.write_text(p.read_text().replace("<DisplayName>CloudSpaceGuard</DisplayName>", "<DisplayName>Cloud Space Guard</DisplayName>"))
        with self.assertRaisesRegex(ValueError, "Display surface mismatch"):
            gate.verify(self.root)

    def test_legacy_web_title(self):
        p = self.root / "web/index.html"
        p.write_text(p.read_text().replace("<title>CloudSpaceGuard", "<title>Cloud Space Guard"))
        with self.assertRaisesRegex(ValueError, "Display surface mismatch"):
            gate.verify(self.root)

    def test_changed_windows_package_identity(self):
        p = self.root / "store_packaging/windows/AppxManifest.xml"
        p.write_text(p.read_text().replace('Name="BobbyBlanco.CloudSpaceGuard"', 'Name="Different.Package"'))
        with self.assertRaisesRegex(ValueError, "Display surface mismatch"):
            gate.verify(self.root)


if __name__ == "__main__":
    unittest.main()
