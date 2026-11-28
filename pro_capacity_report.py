"""Candidate optional direct-desktop license and read-only capacity report.

No issuer is enrolled. Never use fixture signing keys in a release.
No checkout, payment collection, network, file cleanup or restore authority.
"""
import base64
import binascii
import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Build-owned trust roots only. Empty until a separately approved issuer exists.
TRUSTED_ISSUERS = {}
CAPABILITY = "capacity-report-v1"
MAX_LICENSE_BYTES = 16384

class LicenseError(ValueError):
    pass

def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LicenseError("duplicate license field")
        result[key] = value
    return result

def verify_license(raw):
    if not TRUSTED_ISSUERS:
        raise LicenseError("license issuer not enrolled")
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_LICENSE_BYTES:
        raise LicenseError("invalid license size")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        if type(doc) is not dict or set(doc) != {"payload", "signature"}:
            raise LicenseError("invalid license envelope")
        p = doc["payload"]
        if type(p) is not dict or set(p) != {"schema","product","capability","channel","environment","issuer","license_id"}:
            raise LicenseError("invalid license payload")
        if (p["schema"], p["product"], p["capability"], p["channel"], p["environment"]) != ("workshop-license-v1", "cloudspaceguard", CAPABILITY, "direct-desktop", "production"):
            raise LicenseError("wrong product, capability, channel or environment")
        for field in ("issuer", "license_id"):
            if type(p[field]) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", p[field]):
                raise LicenseError("invalid license identifier")
        pem = TRUSTED_ISSUERS.get(p["issuer"])
        if not isinstance(pem, bytes):
            raise LicenseError("unknown license issuer")
        if type(doc["signature"]) is not str:
            raise LicenseError("invalid signature")
        signature = base64.b64decode(doc["signature"], validate=True)
        if len(signature) not in (256,384,512):
            raise LicenseError("invalid RSA signature length")
        data = json.dumps(p,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
    except (UnicodeError, json.JSONDecodeError, binascii.Error, TypeError) as exc:
        raise LicenseError("invalid license encoding") from exc
    openssl = shutil.which("openssl")
    if not openssl:
        raise LicenseError("signature verifier unavailable")
    try:
        with tempfile.TemporaryDirectory(prefix="csg-license-") as tmp:
            root=Path(tmp)
            (root/"issuer.pem").write_bytes(pem)
            (root/"signature").write_bytes(signature)
            result=subprocess.run([openssl,"dgst","-sha256","-verify",str(root/"issuer.pem"),"-signature",str(root/"signature")],input=data,capture_output=True,timeout=5,check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LicenseError("signature verification unavailable") from exc
    if result.returncode != 0 or result.stdout.strip() != b"Verified OK":
        raise LicenseError("license signature rejected")

def create_capacity_report(license_path, targets):
    # Read the bounded license before accessing capacity; no network, no store write.
    if not TRUSTED_ISSUERS:
        raise LicenseError("license issuer not enrolled")
    try:
        with open(license_path,"rb") as f:
            verify_license(f.read(MAX_LICENSE_BYTES+1))
    except OSError as exc:
        raise LicenseError("license file unavailable") from exc
    if not isinstance(targets,(list,tuple)) or not 1<=len(targets)<=12 or any(type(x) is not int or not 1<=x<=1048576 for x in targets) or len(set(targets))!=len(targets):
        raise LicenseError("use one to twelve unique positive integer GiB targets")
    usage=shutil.disk_usage(Path.home())
    total,free=usage.total,usage.free
    if type(total) is not int or type(free) is not int or not 0<=free<=total or total==0:
        raise LicenseError("invalid filesystem measurement")
    return {"schema":"csg-capacity-report-v1","measured_at_utc":datetime.now(timezone.utc).isoformat(),
            "measurement_scope":"home filesystem; not reclaimable-space or quota estimate",
            "total_bytes":total,"free_bytes":free,
            "scenarios":[{"target_gib":x,"target_bytes":x*(1024**3),"deficit_bytes":max(0,x*(1024**3)-free),"target_met":free>=x*(1024**3),"within_total_capacity":x*(1024**3)<=total} for x in targets],
            "modifies_files":False,"provider_requests":0}
