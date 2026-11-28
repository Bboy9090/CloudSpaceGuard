import base64
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import pro_capacity_report as report
import space_guard_agent as agent

class CapacityLicenseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root=Path(cls.tmp.name)
        # Mandatory real crypto test; unavailable OpenSSL fails qualification.
        cls.openssl=shutil.which("openssl")
        if not cls.openssl: raise RuntimeError("OpenSSL required for license qualification")
        cls.key=cls.root/"fixture-private.pem"
        cls.pub=cls.root/"fixture-public.pem"
        subprocess.run([cls.openssl,"genpkey","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:2048","-out",str(cls.key)],check=True,capture_output=True)
        subprocess.run([cls.openssl,"pkey","-in",str(cls.key),"-pubout","-out",str(cls.pub)],check=True,capture_output=True)
    def setUp(self):
        self.payload={"schema":"workshop-license-v1","product":"cloudspaceguard","capability":"capacity-report-v1","channel":"direct-desktop","environment":"production","issuer":"fixture","license_id":"synthetic-license"}
        self.license=self.root/"fixture.json"
        self.trust=patch.object(report,"TRUSTED_ISSUERS",{"fixture":self.pub.read_bytes()})
        self.trust.start()
        self.addCleanup(self.trust.stop)
    def signed(self, payload=None):
        p=self.payload if payload is None else payload
        data=json.dumps(p,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
        signature=subprocess.run([self.openssl,"dgst","-sha256","-sign",str(self.key)],input=data,capture_output=True,check=True).stdout
        return json.dumps({"payload":p,"signature":base64.b64encode(signature).decode("ascii")}).encode()
    def test_valid_signature_exact_byte_math(self):
        self.license.write_bytes(self.signed())
        with patch.object(report.shutil,"disk_usage",return_value=shutil._ntuple_diskusage(100*(1024**3),90*(1024**3),10*(1024**3)-1)):
            r=report.create_capacity_report(self.license,[10,101])
        self.assertEqual(r["scenarios"][0]["deficit_bytes"],1)
        self.assertFalse(r["scenarios"][0]["target_met"])
        self.assertFalse(r["scenarios"][1]["within_total_capacity"])
        self.assertNotIn("hostname",r)
    def test_unenrolled_default_rejects_before_disk(self):
        with patch.object(report,"TRUSTED_ISSUERS",{}),patch.object(report.shutil,"disk_usage") as disk:
            with self.assertRaisesRegex(report.LicenseError,"issuer not enrolled"): report.create_capacity_report(self.license,[1])
            disk.assert_not_called()
    def test_tampered_signature(self):
        doc=json.loads(self.signed());doc["payload"]["license_id"]="edited"
        with self.assertRaisesRegex(report.LicenseError,"signature rejected"): report.verify_license(json.dumps(doc).encode())
    def test_wrong_product_channel_sandbox(self):
        for changes in ({"product":"other"},{"environment":"sandbox"},{"channel":"app-store"},{"capability":"other"}):
            with self.subTest(changes=changes), self.assertRaises(report.LicenseError): report.verify_license(self.signed(self.payload|changes))
    def test_duplicate_key_and_oversized_reject(self):
        for raw in (b'{"payload":{},"payload":{},"signature":""}',b'x'*16385):
            with self.assertRaises(report.LicenseError): report.verify_license(raw)
    def test_missing_crypto_reject(self):
        raw=self.signed()
        with patch.object(report.shutil,"which",return_value=None),self.assertRaisesRegex(report.LicenseError,"unavailable"): report.verify_license(raw)
    def test_unknown_issuer_and_extra_fields_reject(self):
        for changes in ({"issuer":"untrusted"},{"customer_email":"fixture@example.invalid"}):
            with self.assertRaises(report.LicenseError): report.verify_license(self.signed(self.payload|changes))
    def test_invalid_targets_reject(self):
        self.license.write_bytes(self.signed())
        for values in ([0],[1,1],[],[True],[1048577]):
            with self.assertRaises(report.LicenseError): report.create_capacity_report(self.license,values)
    def test_cli_actual_local_measurement_with_synthetic_issuer(self):
        self.license.write_bytes(self.signed())
        with patch.object(sys,"argv",["space_guard_agent.py","pro-capacity-report","--license",str(self.license),"--target-gib","1"]), contextlib.redirect_stdout(io.StringIO()) as out:
            agent.main()
        r=json.loads(out.getvalue());self.assertEqual(r["schema"],"csg-capacity-report-v1")
        self.assertGreater(r["total_bytes"],0)
        self.assertEqual(r["scenarios"][0]["deficit_bytes"],max(0,1024**3-r["free_bytes"]))
        self.assertEqual(r["provider_requests"],0)
    def test_cli_default_closed_and_free_status_unchanged(self):
        with patch.object(report,"TRUSTED_ISSUERS",{}),patch.object(sys,"argv",["space_guard_agent.py","pro-capacity-report","--license","missing","--target-gib","1"]),contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as error: agent.main()
            self.assertEqual(error.exception.code,2)
        self.assertEqual(json.loads(out.getvalue())["code"],"PRO_REPORT_UNAVAILABLE")
        with patch.object(sys,"argv",["space_guard_agent.py","status"]),patch.object(agent,"get_disk_telemetry",return_value={"fixture":True}),patch.object(agent,"discover_cloud_providers",return_value=[]),contextlib.redirect_stdout(io.StringIO()) as free:
            agent.main()
        self.assertEqual(json.loads(free.getvalue())["telemetry"],{"fixture":True})

if __name__=="__main__":
    unittest.main()
