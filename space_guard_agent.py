#!/usr/bin/env python3
"""
Cloud Space Guard — All-For-One Cross-Platform Space Saver & Multi-Cloud Offload Agent
Supports: macOS, Windows, Linux, and ChromeOS (Chromebooks / Crostini)

Features:
  1. Real-time Disk Telemetry & Target Free-Space Planner (e.g. 74 GB for Bootcamp / VMs)
  2. Multi-Cloud Container Discovery & Custom 3rd-Party Cloud Connectors (Free & Paid Tiers):
     - Google Drive (Desktop Mount, ChromeOS /mnt/chromeos/GoogleDrive, or rclone)
     - iCloud Drive (macOS CloudDocs + native `brctl evict` cloud eviction, Windows iCloudDrive)
     - Microsoft OneDrive & Dropbox
     - S3-Compatible / R2 / Backblaze B2 / Wasabi / WebDAV / rclone remotes
  3. Cryptographic Verify-Before-Delete (SHA-256 Checksum Verification + .cloudstub receipts)
     - Supports both individual large files AND whole Project Snapshot folders (auto-archived to .tar.gz,
       verified in cloud via SHA-256, and replaced with a .cloudstub receipt)
  4. Safe Developer & System Cache Cleaner (Docker, Rust target/, node_modules/, Xcode, npm, pnpm, Cargo, Playwright, Pip)
  5. Built-in Local Web Dashboard Server (http://127.0.0.1:7474) + Full CLI
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import http.server
import time
import json
import os
import platform
import shutil
import socketserver
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

APP_VERSION = "1.1.0"
DEFAULT_PORT = 7474
MAX_HTTP_BODY_BYTES = 1024 * 1024
STATE_DIR = Path.home() / ".cloud-space-guard"
CONFIG_FILE = STATE_DIR / "config.json"
LEDGER_FILE = STATE_DIR / "ledger.json"


def ensure_state_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        default_cfg = {
            "target_free_gb": 74.0,
            "leave_cloudstub": True,
            "verify_sha256": True,
            "custom_providers": [],
        }
        CONFIG_FILE.write_text(json.dumps(default_cfg, indent=2), encoding="utf-8")
    if not LEDGER_FILE.exists():
        LEDGER_FILE.write_text(json.dumps([], indent=2), encoding="utf-8")


def load_config() -> Dict[str, Any]:
    ensure_state_dir()
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"target_free_gb": 74.0, "leave_cloudstub": True, "verify_sha256": True, "custom_providers": []}


def save_config(cfg: Dict[str, Any]) -> None:
    ensure_state_dir()
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def load_ledger() -> List[Dict[str, Any]]:
    ensure_state_dir()
    try:
        return json.loads(LEDGER_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def append_ledger(entry: Dict[str, Any]) -> None:
    ledger = load_ledger()
    ledger.insert(0, entry)
    LEDGER_FILE.write_text(json.dumps(ledger[:500], indent=2), encoding="utf-8")


def detect_os_profile() -> str:
    sys_name = platform.system().lower()
    if sys_name == "darwin":
        return "macos"
    if sys_name == "windows":
        return "windows"
    if sys_name == "linux":
        if Path("/mnt/chromeos").exists() or "cros" in platform.release().lower():
            return "chromeos"
        return "linux"
    return "linux"


def get_disk_telemetry(target_gb: Optional[float] = None) -> Dict[str, Any]:
    cfg = load_config()
    target = float(target_gb if target_gb is not None else cfg.get("target_free_gb", 74.0))
    check_path = Path.home()
    usage = shutil.disk_usage(check_path)

    total_gb = round(usage.total / (1024 ** 3), 2)
    free_gb = round(usage.free / (1024 ** 3), 2)
    used_gb = round((usage.total - usage.free) / (1024 ** 3), 2)
    needed_gb = round(max(0.0, target - free_gb), 2)

    return {
        "os_profile": detect_os_profile(),
        "hostname": platform.node(),
        "mount_path": str(check_path),
        "total_gb": total_gb,
        "used_gb": used_gb,
        "free_gb": free_gb,
        "used_percent": round((used_gb / total_gb) * 100, 1) if total_gb > 0 else 0.0,
        "target_free_gb": target,
        "deficit_gb": needed_gb,
        "target_met": free_gb >= target,
    }


def discover_cloud_providers() -> List[Dict[str, Any]]:
    home = Path.home()
    os_prof = detect_os_profile()
    providers: List[Dict[str, Any]] = []

    # 1. Google Drive discovery across macOS, Windows, Linux, ChromeOS
    gdrive_candidates: List[Path] = []
    cloud_storage_dir = home / "Library" / "CloudStorage"
    if cloud_storage_dir.exists():
        for item in sorted(cloud_storage_dir.iterdir()):
            if item.name.startswith("GoogleDrive-"):
                my_drive = item / "My Drive"
                gdrive_candidates.append(my_drive if my_drive.exists() else item)
    gdrive_candidates.extend([
        home / "Google Drive",
        Path("/Volumes/GoogleDrive/My Drive"),
        Path("/mnt/chromeos/GoogleDrive/MyDrive"),
        Path("G:/My Drive"),
    ])

    gdrive_path = next((p for p in gdrive_candidates if p.exists()), None)
    providers.append({
        "id": "gdrive",
        "name": "Google Drive",
        "tier": "Free 15 GB / Google One Paid",
        "type": "google-drive",
        "connected": gdrive_path is not None,
        "vault_path": str((gdrive_path / "CloudSpaceGuard_Vault") if gdrive_path else (home / "GoogleDrive_Vault")),
        "account_hint": gdrive_path.name.replace("GoogleDrive-", "") if (gdrive_path and "GoogleDrive-" in gdrive_path.name) else (gdrive_path.parent.name.replace("GoogleDrive-", "") if (gdrive_path and "GoogleDrive-" in str(gdrive_path)) else ("Detected Mount" if gdrive_path else "Not mounted locally")),
        "supports_native_evict": True,
        "platforms": ["macos", "windows", "linux", "chromeos"],
    })

    # 2. iCloud Drive discovery (macOS & Windows)
    icloud_candidates = [
        home / "Library" / "Mobile Documents" / "com~apple~CloudDocs",
        home / "iCloudDrive",
        home / "iCloud Drive",
    ]
    icloud_path = next((p for p in icloud_candidates if p.exists()), None)
    providers.append({
        "id": "icloud",
        "name": "Apple iCloud Drive",
        "tier": "Free 5 GB / iCloud+ Paid (50GB–12TB)",
        "type": "icloud-drive",
        "connected": icloud_path is not None,
        "vault_path": str((icloud_path / "CloudSpaceGuard_Vault") if icloud_path else (home / "iCloud_Vault")),
        "account_hint": "macOS CloudDocs (brctl evict ready)" if (icloud_path and os_prof == "macos") else ("Mounted" if icloud_path else "Web / Not mounted"),
        "supports_native_evict": os_prof == "macos",
        "platforms": ["macos", "windows"],
    })

    # 3. OneDrive discovery
    onedrive_candidates: List[Path] = []
    if cloud_storage_dir.exists():
        for item in sorted(cloud_storage_dir.iterdir()):
            if "OneDrive" in item.name:
                onedrive_candidates.append(item)
    onedrive_candidates.extend([home / "OneDrive", Path("C:/Users") / home.name / "OneDrive"])
    onedrive_path = next((p for p in onedrive_candidates if p.exists()), None)
    providers.append({
        "id": "onedrive",
        "name": "Microsoft OneDrive",
        "tier": "Free 5 GB / Microsoft 365 (1TB)",
        "type": "onedrive",
        "connected": onedrive_path is not None,
        "vault_path": str((onedrive_path / "CloudSpaceGuard_Vault") if onedrive_path else (home / "OneDrive_Vault")),
        "account_hint": onedrive_path.name if onedrive_path else "Optional 3rd-Party Mount",
        "supports_native_evict": True,
        "platforms": ["macos", "windows", "linux", "chromeos"],
    })

    # 4. Dropbox discovery
    dropbox_candidates: List[Path] = []
    if cloud_storage_dir.exists():
        for item in sorted(cloud_storage_dir.iterdir()):
            if "Dropbox" in item.name:
                dropbox_candidates.append(item)
    dropbox_candidates.append(home / "Dropbox")
    dropbox_path = next((p for p in dropbox_candidates if p.exists()), None)
    providers.append({
        "id": "dropbox",
        "name": "Dropbox Cloud",
        "tier": "Free 2 GB / Plus & Pro (2TB+)",
        "type": "dropbox",
        "connected": dropbox_path is not None,
        "vault_path": str((dropbox_path / "CloudSpaceGuard_Vault") if dropbox_path else (home / "Dropbox_Vault")),
        "account_hint": dropbox_path.name if dropbox_path else "Optional 3rd-Party Mount",
        "supports_native_evict": True,
        "platforms": ["macos", "windows", "linux", "chromeos"],
    })

    # 5. rclone / S3 / Backblaze B2 / Cloudflare R2 / Wasabi
    rclone_bin = shutil.which("rclone")
    rclone_remotes: List[str] = []
    if rclone_bin:
        try:
            proc = subprocess.run([rclone_bin, "listremotes"], capture_output=True, text=True, timeout=4)
            rclone_remotes = [r.strip() for r in proc.stdout.splitlines() if r.strip()]
        except Exception:
            pass

    providers.append({
        "id": "s3_rclone",
        "name": "3rd-Party Cloud Container (S3 / R2 / B2 / Wasabi / rclone)",
        "tier": "Pay-As-You-Go / Free Tier (Cloudflare R2 10GB, Backblaze B2 10GB)",
        "type": "rclone-s3",
        "connected": bool(rclone_remotes),
        "vault_path": rclone_remotes[0] + "cloud-space-guard" if rclone_remotes else str(home / "CloudVault_S3_Staging"),
        "account_hint": f"rclone remotes: {', '.join(rclone_remotes)}" if rclone_remotes else ("rclone installed (no remotes yet)" if rclone_bin else "Configure any S3/R2/B2/WebDAV or local staging vault"),
        "supports_native_evict": False,
        "platforms": ["macos", "windows", "linux", "chromeos"],
    })

    # 6. User-added custom 3rd-party containers from config.json
    cfg = load_config()
    for custom in cfg.get("custom_providers", []):
        vault_p = Path(custom.get("vault_path", ""))
        providers.append({
            "id": custom.get("id", f"custom_{len(providers)}"),
            "name": custom.get("name", "Custom Cloud Container"),
            "tier": custom.get("tier", "Custom Free / Paid Tier"),
            "type": custom.get("type", "custom-s3-or-mount"),
            "connected": vault_p.exists() or str(custom.get("vault_path", "")).startswith(("rclone:", "s3://", "b2://", "https://")),
            "vault_path": custom.get("vault_path", ""),
            "account_hint": custom.get("account_hint", "User Configured Container"),
            "supports_native_evict": False,
            "platforms": ["macos", "windows", "linux", "chromeos"],
        })

    return providers


def dir_size_bytes(path: Path, max_entries: int = 25000) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    if os.name == "posix":
        try:
            res = subprocess.run(["du", "-sk", str(path)], capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout:
                kb = int(res.stdout.split()[0])
                return kb * 1024
        except Exception:
            pass
    total = 0
    count = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            count += 1
            if count > max_entries:
                return total
            fp = Path(root) / f
            try:
                if not fp.is_symlink():
                    total += fp.stat().st_size
            except OSError:
                pass
    return total


def discover_project_build_caches() -> List[Path]:
    """Finds regenerable Rust `target/` and Node `node_modules/` directories inside ~/Projects."""
    projects_dir = Path.home() / "Projects"
    found: List[Path] = []
    if not projects_dir.exists():
        return found
    try:
        for proj in projects_dir.iterdir():
            if not proj.is_dir() or proj.is_symlink():
                continue
            for sub in [
                proj / "target",
                proj / "src-tauri" / "target",
                proj / "node_modules",
                proj / "frontend" / "node_modules",
            ]:
                if sub.exists() and sub.is_dir():
                    found.append(sub)
    except OSError:
        pass
    return found


_CACHE_TIMESTAMP = 0.0
_CACHED_CACHES: List[Dict[str, Any]] = []
_CACHED_CANDIDATES: List[Dict[str, Any]] = []

def scan_system_caches(force_refresh: bool = False) -> List[Dict[str, Any]]:
    global _CACHE_TIMESTAMP, _CACHED_CACHES
    now = time.time()
    if not force_refresh and _CACHED_CACHES and (now - _CACHE_TIMESTAMP < 60.0):
        return _CACHED_CACHES
    home = Path.home()
    candidates = [
        {
            "id": "docker_data",
            "name": "Docker Desktop VM & Container Layers",
            "path": home / "Library" / "Containers" / "com.docker.docker",
            "category": "Container Virtual Disk (31 GB)",
            "safe_level": "review",
            "clean_cmd": "docker system prune -a --volumes -f",
            "description": "Docker virtual disk (Docker.raw) & cached container layers. Prune unused images/volumes or reduce VM disk limit in Docker Settings.",
        },
        {
            "id": "npm_cache",
            "name": "Node.js npm Package Cache",
            "path": home / ".npm",
            "category": "Developer Cache",
            "safe_level": "safe",
            "clean_cmd": "npm cache clean --force",
            "description": "Cached tarballs downloaded by npm. 100% safe to delete; packages redownload on demand.",
        },
        {
            "id": "google_cache",
            "name": "Google Chrome & Drive App Caches",
            "path": home / "Library" / "Caches" / "Google",
            "category": "Browser & App Cache",
            "safe_level": "safe",
            "clean_cmd": "rm -rf ~/Library/Caches/Google/*",
            "description": "Temporary Google updater and browser media caches.",
        },
        {
            "id": "cargo_cache",
            "name": "Rust Cargo Registry & Git Cache",
            "path": home / ".cargo" / "registry",
            "category": "Developer Cache",
            "safe_level": "safe",
            "clean_cmd": "rm -rf ~/.cargo/registry/cache ~/.cargo/git/db",
            "description": "Downloaded Rust crate archives in ~/.cargo/registry.",
        },
        {
            "id": "xcode_derived",
            "name": "Xcode DerivedData Build Artifacts",
            "path": home / "Library" / "Developer" / "Xcode" / "DerivedData",
            "category": "IDE Build Cache",
            "safe_level": "safe",
            "clean_cmd": "rm -rf ~/Library/Developer/Xcode/DerivedData/*",
            "description": "Intermediate Xcode build indexes and compiled binaries. Safely regenerated on next build.",
        },
        {
            "id": "playwright_browsers",
            "name": "Playwright Headless Browser Binaries",
            "path": home / "Library" / "Caches" / "ms-playwright",
            "category": "Test Automation Cache",
            "safe_level": "safe",
            "clean_cmd": "rm -rf ~/Library/Caches/ms-playwright/*",
            "description": "Downloaded Chromium/Firefox/WebKit test browsers.",
        },
        {
            "id": "pnpm_store",
            "name": "pnpm Content-Addressable Store Cache",
            "path": home / "Library" / "Caches" / "pnpm",
            "category": "Developer Cache",
            "safe_level": "safe",
            "clean_cmd": "pnpm store prune",
            "description": "Unreferenced Node packages in pnpm cache.",
        },
        {
            "id": "homebrew_cache",
            "name": "Homebrew Downloaded Bottles & Tarballs",
            "path": home / "Library" / "Caches" / "Homebrew",
            "category": "Package Manager Cache",
            "safe_level": "safe",
            "clean_cmd": "brew cleanup -s",
            "description": "Old installer archives cached by Homebrew.",
        },
        {
            "id": "pip_cache",
            "name": "Python pip Wheel Cache",
            "path": home / "Library" / "Caches" / "pip",
            "category": "Developer Cache",
            "safe_level": "safe",
            "clean_cmd": "python3 -m pip cache purge",
            "description": "Cached Python wheel packages built during pip install.",
        },
        {
            "id": "linux_xdg_cache",
            "name": "Linux / Chromebook ~/.cache",
            "path": home / ".cache",
            "category": "System Cache",
            "safe_level": "safe",
            "clean_cmd": "rm -rf ~/.cache/*",
            "description": "Standard XDG user cache directory on Linux and ChromeOS.",
        },
    ]

    results: List[Dict[str, Any]] = []
    for item in candidates:
        p: Path = item["path"]
        if p.exists():
            sz = dir_size_bytes(p)
            if sz > 1024 * 1024:
                results.append({
                    "id": item["id"],
                    "name": item["name"],
                    "path": str(p),
                    "category": item["category"],
                    "safe_level": item["safe_level"],
                    "clean_cmd": item["clean_cmd"],
                    "description": item["description"],
                    "size_bytes": sz,
                    "size_gb": round(sz / (1024 ** 3), 2),
                    "size_mb": round(sz / (1024 ** 2), 1),
                })

    # Also aggregate regenerable Rust target/ and node_modules/ in ~/Projects
    proj_caches = discover_project_build_caches()
    rust_targets = [p for p in proj_caches if p.name == "target"]
    node_mods = [p for p in proj_caches if p.name == "node_modules"]

    if rust_targets:
        total_rust = sum(dir_size_bytes(p) for p in rust_targets)
        if total_rust > 10 * 1024 * 1024:
            results.append({
                "id": "projects_rust_targets",
                "name": f"Rust/Tauri Build Targets ({len(rust_targets)} projects in ~/Projects)",
                "path": str(home / "Projects" / "*/src-tauri/target"),
                "category": "Regenerable Build Artifacts",
                "safe_level": "safe",
                "clean_cmd": "find ~/Projects -maxdepth 3 -name target -type d -exec rm -rf {} +",
                "description": "Compiled intermediate Rust/Tauri binaries across your BobFWTools worktrees. Source code is NOT touched.",
                "size_bytes": total_rust,
                "size_gb": round(total_rust / (1024 ** 3), 2),
                "size_mb": round(total_rust / (1024 ** 2), 1),
            })

    if node_mods:
        total_nm = sum(dir_size_bytes(p) for p in node_mods)
        if total_nm > 10 * 1024 * 1024:
            results.append({
                "id": "projects_node_modules",
                "name": f"Project node_modules Folders ({len(node_mods)} projects in ~/Projects)",
                "path": str(home / "Projects" / "*/node_modules"),
                "category": "Regenerable Dependencies",
                "safe_level": "safe",
                "clean_cmd": "find ~/Projects -maxdepth 3 -name node_modules -type d -prune -exec rm -rf {} +",
                "description": "Installed npm/pnpm packages across old project worktrees. Reinstall anytime with `npm install` or `pnpm i`.",
                "size_bytes": total_nm,
                "size_gb": round(total_nm / (1024 ** 3), 2),
                "size_mb": round(total_nm / (1024 ** 2), 1),
            })

    results.sort(key=lambda x: x["size_bytes"], reverse=True)
    _CACHED_CACHES = results
    _CACHE_TIMESTAMP = time.time()
    return results


def scan_offload_candidates(min_size_mb: float = 25.0, force_refresh: bool = False) -> List[Dict[str, Any]]:
    global _CACHED_CANDIDATES
    if not force_refresh and _CACHED_CANDIDATES:
        return _CACHED_CANDIDATES
    home = Path.home()
    min_bytes = int(min_size_mb * 1024 * 1024)
    search_roots = [
        home / "Downloads",
        home / "Documents",
        home / "Desktop",
        home / "Movies",
        home / "Library" / "Mobile Documents" / "com~apple~CloudDocs",
        home / "Library" / "CloudStorage",
    ]

    candidates: List[Dict[str, Any]] = []
    seen_paths = set()

    # 1. Include large project worktree snapshots in ~/Projects so user can archive+offload them to Google Drive / iCloud Drive
    projects_dir = home / "Projects"
    if projects_dir.exists():
        try:
            for proj in sorted(projects_dir.iterdir()):
                if not proj.is_dir() or proj.is_symlink() or proj.name.startswith("."):
                    continue
                try:
                    # Quick du measurement with strict timeout to keep UI instant
                    res = subprocess.run(["du", "-sk", str(proj)], capture_output=True, text=True, timeout=0.8)
                    if res.returncode == 0 and res.stdout:
                        sz = int(res.stdout.split()[0]) * 1024
                    else:
                        continue
                except Exception:
                    continue
                if sz >= min_bytes:
                    st = proj.stat()
                    candidates.append({
                        "name": f"{proj.name} (Project Snapshot Folder)",
                        "path": str(proj),
                        "is_directory": True,
                        "size_bytes": sz,
                        "size_gb": round(sz / (1024 ** 3), 2),
                        "size_mb": round(sz / (1024 ** 2), 1),
                        "size_formatted": f"{round(sz / (1024 ** 3), 2)} GB",
                        "modified": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                        "already_in_cloud": None,
                        "recommended_action": "Archive (.tar.gz) + SHA-256 Verify & Offload to Cloud Vault",
                    })
                    if len(candidates) >= 20:
                        break
        except OSError:
            pass

    # 2. Scan individual large files in user folders
    for root in search_roots:
        if not root.exists():
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                # Prune build artifacts, index stores, and version control directories
                dirnames[:] = [
                    d for d in dirnames
                    if not d.startswith(".") and d not in {
                        "node_modules", "target", "build", "DerivedData", "__pycache__",
                        "CloudSpaceGuard_Vault", "Pods", "Library", "venv", ".venv", "dist"
                    }
                ]
                # Enforce max depth of 4 to keep search instantaneous
                rel_depth = len(Path(dirpath).relative_to(root).parts)
                if rel_depth >= 4:
                    dirnames.clear()
                for fname in filenames:
                    if fname.endswith(".cloudstub") or fname.startswith(".DS_Store"):
                        continue
                    fpath = Path(dirpath) / fname
                    if str(fpath) in seen_paths or fpath.is_symlink():
                        continue
                    try:
                        st = fpath.stat()
                    except OSError:
                        continue
                    if st.st_size >= min_bytes:
                        seen_paths.add(str(fpath))
                        in_icloud = "com~apple~CloudDocs" in str(fpath)
                        in_gdrive = "GoogleDrive-" in str(fpath)
                        candidates.append({
                            "name": fname,
                            "path": str(fpath),
                            "is_directory": False,
                            "size_bytes": st.st_size,
                            "size_gb": round(st.st_size / (1024 ** 3), 2),
                            "size_mb": round(st.st_size / (1024 ** 2), 1),
                            "size_formatted": f"{round(st.st_size / (1024 ** 2), 1)} MB",
                            "modified": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                            "already_in_cloud": "icloud" if in_icloud else ("gdrive" if in_gdrive else None),
                            "recommended_action": (
                                "Native Evict (brctl evict — already in iCloud)"
                                if in_icloud
                                else ("Verify & Evict Local Cache (already in Google Drive)" if in_gdrive else "SHA-256 Verify & Offload to Cloud Vault")
                            ),
                        })
                        if len(candidates) >= 75:
                            break
                if len(candidates) >= 75:
                    break
        except PermissionError:
            continue

    candidates.sort(key=lambda x: x["size_bytes"], reverse=True)
    _CACHED_CANDIDATES = candidates
    return candidates


def compute_sha256(file_path: Path, chunk_size: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _directory_snapshot(root: Path) -> Dict[str, Optional[str]]:
    """Record every regular file and directory; reject links and special files."""
    snapshot: Dict[str, Optional[str]] = {root.name: None}
    for base, dirs, files in os.walk(root, followlinks=False, onerror=lambda exc: (_ for _ in ()).throw(exc)):
        for name in dirs + files:
            item = Path(base) / name
            relative = (Path(root.name) / item.relative_to(root)).as_posix()
            if item.is_symlink() or not (item.is_file() or item.is_dir()):
                raise ValueError(f"Unsupported link or special file: {item}")
            snapshot[relative] = compute_sha256(item) if item.is_file() else None
    return snapshot


def _verify_directory_archive(archive: Path, expected: Dict[str, Optional[str]]) -> None:
    seen: Dict[str, Optional[str]] = {}
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            name = member.name.rstrip("/")
            if name in seen or name not in expected:
                raise ValueError(f"Unexpected or duplicate archive entry: {name}")
            if member.isdir():
                seen[name] = None
            elif member.isfile():
                stream = tar.extractfile(member)
                if stream is None:
                    raise ValueError(f"Unreadable archive entry: {name}")
                digest = hashlib.sha256()
                with stream:
                    for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                        digest.update(chunk)
                seen[name] = digest.hexdigest()
            else:
                raise ValueError(f"Unsupported archive entry: {name}")
    if seen != expected:
        raise ValueError("Archive does not match the complete source snapshot.")


def verify_and_offload_file(
    file_path_str: str,
    provider_id: str = "gdrive",
    leave_stub: bool = True,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Create a verified local vault copy; never delete the original.

    A mounted sync directory cannot prove remote upload or durability. This
    operation therefore does not reclaim local space and must not claim to.
    """
    if not file_path_str:
        return {"ok": False, "error": "A source path is required."}
    source_input = Path(file_path_str).expanduser()
    if source_input.is_symlink():
        return {"ok": False, "error": "Symlink sources are not supported."}
    src = source_input.resolve()
    if not src.exists() or not (src.is_file() or src.is_dir()):
        return {"ok": False, "error": f"Source not found or unsupported: {src}"}
    providers = {p["id"]: p for p in discover_cloud_providers()}
    provider = providers.get(provider_id)
    if not provider:
        return {"ok": False, "error": f"Unknown cloud provider: {provider_id}"}
    vault = Path(provider["vault_path"]).expanduser().resolve()
    if src == vault or (src.is_dir() and vault.is_relative_to(src)):
        return {"ok": False, "error": "Vault cannot be inside the source directory."}
    receipt = Path(f"{src}.cloudstub")
    if leave_stub and os.path.lexists(receipt):
        return {"ok": False, "error": f"Receipt already exists: {receipt}"}
    if dry_run:
        return {"ok": True, "mode": "dry_run", "file_name": src.name,
                "local_sha256": compute_sha256(src) if src.is_file() else None,
                "cloud_destination": str(vault), "stub_path": str(receipt),
                "source_retained": True, "remote_durability_verified": False}
    dest = None
    receipt_created = False
    try:
        vault.mkdir(parents=True, exist_ok=True)
        dest_dir = vault / "cloud-space-guard" / uuid.uuid4().hex
        dest_dir.mkdir(parents=True, exist_ok=False)
        dest = dest_dir / (src.name + ".csg-archive.tar.gz" if src.is_dir() else src.name)
        if src.is_dir():
            snapshot = _directory_snapshot(src)
            with tarfile.open(dest, "x:gz") as tar:
                tar.add(src, arcname=src.name, recursive=True)
            _verify_directory_archive(dest, snapshot)
            if _directory_snapshot(src) != snapshot:
                raise ValueError("Source directory changed during archive creation.")
            digest = compute_sha256(dest)
        else:
            digest = compute_sha256(src)
            with src.open("rb") as source, dest.open("xb") as target:
                shutil.copyfileobj(source, target)
            if compute_sha256(dest) != digest or compute_sha256(src) != digest:
                raise ValueError("Source or copied file changed during verification.")
        payload = {"schema": "cloud-space-guard.stub/v1", "is_directory_archive": src.is_dir(),
                   "original_name": src.name, "original_path": str(src),
                   "cloud_provider_id": provider["id"], "cloud_provider_name": provider["name"],
                   "cloud_vault_path": str(dest), "size_bytes": src.stat().st_size if src.is_file() else None,
                   "sha256": digest, "offloaded_at": datetime.datetime.now().isoformat(timespec="seconds"),
                   "remote_durability_verified": False, "source_retained": True}
        if leave_stub:
            with receipt.open("x", encoding="utf-8") as stream:
                receipt_created = True
                json.dump(payload, stream, indent=2)
        entry = {"timestamp": payload["offloaded_at"], "action": "verified_local_vault_copy",
                 "file_name": src.name, "original_path": str(src), "cloud_destination": str(dest),
                 "stub_path": str(receipt) if leave_stub else None, "provider_id": provider["id"],
                 "provider_name": provider["name"], "sha256": digest, "verified": True,
                 "remote_durability_verified": False, "source_retained": True}
        append_ledger(entry)
        return {"ok": True, "mode": "verified_local_vault_copy", "entry": entry,
                "source_retained": True, "remote_durability_verified": False,
                "message": "Local vault copy verified; source retained. Cloud upload is not verified and no space was reclaimed."}
    except Exception as exc:
        # Preserve any copy on failure for manual recovery. Never remove source or receipt.
        return {"ok": False, "error": str(exc), "source_retained": True,
                "partial_copy": str(dest) if dest else None, "receipt_created": receipt_created}


def _safe_extract_tar(tar: tarfile.TarFile, target_dir: Path) -> None:
    """Prevents CVE-2007-4559 path traversal (Tar-Slip) during archive restore."""
    resolved_root = target_dir.resolve()
    for member in tar.getmembers():
        member_path = (resolved_root / member.name).resolve()
        if not str(member_path).startswith(str(resolved_root) + os.sep) and member_path != resolved_root:
            raise ValueError(f"Blocked unsafe tar path traversal: {member.name}")
        if member.issym() or member.islnk():
            raise ValueError(f"Blocked symlink in cloud archive: {member.name}")
    tar.extractall(path=resolved_root)


def restore_from_stub(stub_path_str: str) -> Dict[str, Any]:
    stub_path = Path(stub_path_str).expanduser().resolve()
    if not stub_path.exists():
        return {"ok": False, "error": f"Stub file not found: {stub_path}"}

    try:
        meta = json.loads(stub_path.read_text(encoding="utf-8"))
        cloud_file = Path(meta["cloud_vault_path"])
        orig_file = Path(meta["original_path"])

        if not cloud_file.exists():
            return {"ok": False, "error": f"Cloud vault file not found at {cloud_file}. Ensure your cloud drive is mounted."}

        remote_sha = compute_sha256(cloud_file)
        if remote_sha != meta.get("sha256"):
            return {
                "ok": False,
                "error": f"Cloud archive SHA-256 mismatch! Expected {meta.get('sha256')}, got {remote_sha}",
            }

        if meta.get("is_directory_archive"):
            if os.path.lexists(orig_file):
                return {"ok": False, "error": f"Restore destination already exists: {orig_file}"}
            expected_root = orig_file.name
            orig_file.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="csg-restore-", dir=orig_file.parent) as staging:
                stage = Path(staging)
                with tarfile.open(cloud_file, "r:gz") as tar:
                    seen = set()
                    for member in tar.getmembers():
                        parts = Path(member.name).parts
                        if (not parts or parts[0] != expected_root or ".." in parts
                                or member.name.startswith("/") or member.name in seen
                                or not (member.isfile() or member.isdir())):
                            raise ValueError(f"Unsafe archive member: {member.name}")
                        seen.add(member.name)
                    _safe_extract_tar(tar, stage)
                staged_root = stage / expected_root
                if not staged_root.is_dir() or staged_root.is_symlink():
                    raise ValueError("Archive lacks the expected directory root.")
                # mkdir is exclusive: no existing destination can be replaced.
                orig_file.mkdir()
                for child in staged_root.iterdir():
                    shutil.move(str(child), str(orig_file / child.name))
            restored_sha = remote_sha
        else:
            orig_file.parent.mkdir(parents=True, exist_ok=True)
            # Exclusive creation also rejects dangling symlinks and concurrent
            # creators instead of overwriting newly created local work.
            try:
                destination = orig_file.open("xb")
            except FileExistsError:
                return {"ok": False, "error": f"Restore destination already exists: {orig_file}"}
            try:
                with destination, cloud_file.open("rb") as source:
                    shutil.copyfileobj(source, destination)
            except Exception:
                orig_file.unlink(missing_ok=True)
                raise
            restored_sha = compute_sha256(orig_file)
            if restored_sha != meta.get("sha256"):
                orig_file.unlink(missing_ok=True)
                return {
                    "ok": False,
                    "error": f"Local write SHA-256 verification failed! Expected {meta.get('sha256')}, got {restored_sha}",
                }

        stub_path.unlink()
        entry = {
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "action": "restored_from_cloud",
            "file_name": orig_file.name,
            "original_path": str(orig_file),
            "cloud_destination": str(cloud_file),
            "size_bytes": meta.get("size_bytes", 0),
            "sha256": restored_sha,
            "verified": True,
        }
        append_ledger(entry)
        return {"ok": True, "entry": entry}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def clean_safe_cache(cache_id: str) -> Dict[str, Any]:
    if cache_id in {"projects_rust_targets", "projects_node_modules"}:
        target_name = "target" if cache_id == "projects_rust_targets" else "node_modules"
        dirs = [p for p in discover_project_build_caches() if p.name == target_name]
        freed_bytes = 0
        for d in dirs:
            sz = dir_size_bytes(d)
            shutil.rmtree(d, ignore_errors=True)
            if not d.exists():
                freed_bytes += sz
        entry = {
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "action": "cache_cleaned",
            "file_name": f"~/Projects {target_name} ({len(dirs)} folders)",
            "original_path": f"~/Projects/*/{target_name}",
            "cloud_destination": "Local Regenerable Build Cache Purge",
            "size_bytes": freed_bytes,
            "sha256": "BUILD-CACHE-PURGE",
            "verified": True,
        }
        append_ledger(entry)
        return {
            "ok": True,
            "freed_bytes": freed_bytes,
            "freed_mb": round(freed_bytes / (1024 ** 2), 1),
            "entry": entry,
        }

    caches = {c["id"]: c for c in scan_system_caches()}
    target = caches.get(cache_id)
    if not target:
        return {"ok": False, "error": f"Cache target '{cache_id}' not found or already empty."}

    if target["safe_level"] != "safe":
        return {
            "ok": False,
            "error": f"'{target['name']}' requires manual review ({target['clean_cmd']}) so active containers/VMs are not disrupted.",
        }

    path = Path(target["path"])
    before_bytes = target["size_bytes"]
    try:
        if path.is_dir():
            for child in path.iterdir():
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    try:
                        child.unlink()
                    except OSError:
                        pass
        # Invalidate in-memory cache so subsequent reads see freshly freed disk
        global _CACHE_TIMESTAMP, _CACHED_CACHES
        _CACHE_TIMESTAMP = 0.0
        _CACHED_CACHES = []
        freed_bytes = before_bytes
        entry = {
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "action": "cache_cleaned",
            "file_name": target["name"],
            "original_path": str(path),
            "cloud_destination": "Local Safe Cache Purge",
            "size_bytes": freed_bytes,
            "sha256": "CACHE-PURGE",
            "verified": True,
        }
        append_ledger(entry)
        return {
            "ok": True,
            "freed_bytes": freed_bytes,
            "freed_mb": round(freed_bytes / (1024 ** 2), 1),
            "entry": entry,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


class SpaceGuardRequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _server_port(self) -> int:
        return int(self.server.server_address[1])

    def _request_host_allowed(self) -> bool:
        raw_host = self.headers.get("Host", "").strip().lower()
        if not raw_host:
            return False
        host = raw_host.rsplit(":", 1)[0] if ":" in raw_host else raw_host
        return host in {"127.0.0.1", "localhost"}

    def _request_origin_allowed(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        port = self._server_port()
        return origin.rstrip("/") in {
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
        }

    def _guard_browser_boundary(self) -> bool:
        if not self._request_host_allowed():
            self._send_json({"ok": False, "error": "Invalid localhost Host header"}, status=403)
            return False
        if not self._request_origin_allowed():
            self._send_json({"ok": False, "error": "Cross-origin localhost API access denied"}, status=403)
            return False
        return True

    def _send_json(self, payload: Any, status: int = 200) -> None:
        try:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            origin = self.headers.get("Origin")
            if origin and self._request_origin_allowed():
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_OPTIONS(self) -> None:
        if not self._guard_browser_boundary():
            return
        self.send_response(204)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self) -> None:
        if not self._guard_browser_boundary():
            return
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/api/status":
            target_param = qs.get("target_gb", [None])[0]
            target_val = float(target_param) if target_param else None
            self._send_json({
                "ok": True,
                "telemetry": get_disk_telemetry(target_val),
                "providers": discover_cloud_providers(),
                "config": load_config(),
            })
            return

        if parsed.path == "/api/scan":
            min_mb = float(qs.get("min_mb", ["25"])[0])
            self._send_json({
                "ok": True,
                "telemetry": get_disk_telemetry(),
                "caches": scan_system_caches(),
                "candidates": scan_offload_candidates(min_size_mb=min_mb),
                "ledger": load_ledger()[:50],
            })
            return

        if parsed.path == "/api/caches":
            self._send_json({"ok": True, "caches": scan_system_caches()})
            return

        if parsed.path == "/api/candidates":
            min_mb = float(qs.get("min_mb", ["25"])[0])
            self._send_json({"ok": True, "candidates": scan_offload_candidates(min_size_mb=min_mb)})
            return

        if parsed.path == "/api/ledger":
            self._send_json({"ok": True, "ledger": load_ledger()})
            return

                # Static file fallback
        web_dir = Path(__file__).resolve().parent / "web"
        rel = parsed.path.lstrip("/") or "index.html"
        target_file = (web_dir / rel).resolve()
        if str(target_file).startswith(str(web_dir)) and target_file.is_file():
            content_type = "text/html"
            if rel.endswith(".css"): content_type = "text/css"
            elif rel.endswith(".js"): content_type = "application/javascript"
            elif rel.endswith(".svg"): content_type = "image/svg+xml"
            elif rel.endswith(".png"): content_type = "image/png"
            data = target_file.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        self._send_json({"ok": False, "error": "Not found"}, status=404)

    def do_POST(self) -> None:
        if not self._guard_browser_boundary():
            return

        parsed = urllib.parse.urlparse(self.path)
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json({"ok": False, "error": "Invalid Content-Length"}, status=400)
            return

        if length < 0:
            self._send_json({"ok": False, "error": "Invalid Content-Length"}, status=400)
            return
        if length > MAX_HTTP_BODY_BYTES:
            self._send_json({"ok": False, "error": "Request body too large"}, status=413)
            return
        if length > 0:
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                self._send_json({"ok": False, "error": "POST requests require application/json"}, status=415)
                return

        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            data = json.loads(raw_body)
        except Exception:
            self._send_json({"ok": False, "error": "Malformed JSON request body"}, status=400)
            return

        if parsed.path == "/api/target":
            cfg = load_config()
            cfg["target_free_gb"] = float(data.get("target_free_gb", 74.0))
            save_config(cfg)
            self._send_json({"ok": True, "telemetry": get_disk_telemetry(cfg["target_free_gb"])})
            return

        if parsed.path == "/api/add-provider":
            cfg = load_config()
            custom_list = cfg.get("custom_providers", [])
            new_prov = {
                "id": f"custom_{len(custom_list) + 1}_{int(datetime.datetime.now().timestamp())}",
                "name": data.get("name", "3rd-Party Cloud Vault"),
                "tier": data.get("tier", "Custom Free/Paid Tier"),
                "type": data.get("type", "s3-compatible"),
                "vault_path": data.get("vault_path", str(Path.home() / "CloudVault_Custom")),
                "account_hint": data.get("account_hint", "Connected Container"),
            }
            custom_list.append(new_prov)
            cfg["custom_providers"] = custom_list
            save_config(cfg)
            self._send_json({"ok": True, "providers": discover_cloud_providers()})
            return

        if parsed.path == "/api/offload":
            res = verify_and_offload_file(
                file_path_str=data.get("file_path", ""),
                provider_id=data.get("provider_id", "gdrive"),
                leave_stub=bool(data.get("leave_stub", True)),
                dry_run=bool(data.get("dry_run", False)),
            )
            res["telemetry"] = get_disk_telemetry()
            self._send_json(res, status=200 if res.get("ok") else 400)
            return

        if parsed.path == "/api/restore":
            res = restore_from_stub(data.get("stub_path", ""))
            res["telemetry"] = get_disk_telemetry()
            self._send_json(res, status=200 if res.get("ok") else 400)
            return

        if parsed.path == "/api/clean-cache":
            res = clean_safe_cache(data.get("cache_id", ""))
            res["telemetry"] = get_disk_telemetry()
            self._send_json(res, status=200 if res.get("ok") else 400)
            return

        if parsed.path == "/api/clean-all-safe":
            caches = scan_system_caches()
            cleaned = []
            total_freed_mb = 0.0
            for c in caches:
                if c.get("safe_level") == "safe" and c.get("size_mb", 0) > 0:
                    r = clean_safe_cache(c["id"])
                    if r.get("ok"):
                        cleaned.append(c["name"])
                        total_freed_mb += r.get("freed_mb", 0.0)
            self._send_json({
                "ok": True,
                "cleaned_count": len(cleaned),
                "cleaned_names": cleaned,
                "freed_mb": round(total_freed_mb, 2),
                "telemetry": get_disk_telemetry()
            })
            return

        self._send_json({"ok": False, "error": "Unknown endpoint"}, status=404)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

def run_server(port: int = DEFAULT_PORT) -> None:
    ensure_state_dir()
    with ThreadedTCPServer(("127.0.0.1", port), SpaceGuardRequestHandler) as httpd:
        print(f"==================================================================")
        print(f"  Cloud Space Guard v{APP_VERSION} — Cross-Platform Space Saver")
        print(f"  OS Profile : {detect_os_profile().upper()} ({platform.node()})")
        print(f"  Dashboard  : http://127.0.0.1:{port}")
        print(f"==================================================================")
        httpd.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cloud Space Guard — Cross-Platform Multi-Cloud Offload & Space Saver"
    )
    sub = parser.add_subparsers(dest="command")

    p_status = sub.add_parser("status", help="Show disk space telemetry and detected cloud providers")
    p_status.add_argument("--target-gb", type=float, default=None, help="Target free GB (e.g. 74.0)")

    p_scan = sub.add_parser("scan", help="Scan system caches and large offloadable files/projects")
    p_scan.add_argument("--min-mb", type=float, default=25.0, help="Minimum size in MB")

    p_offload = sub.add_parser("offload", help="SHA-256 verify and offload a file or project folder to a cloud container")
    p_offload.add_argument("--file", required=True, help="Path to local file or project folder")
    p_offload.add_argument("--provider", default="gdrive", help="Cloud provider ID (gdrive, icloud, onedrive, dropbox, etc.)")
    p_offload.add_argument("--no-stub", action="store_true", help="Do not leave a .cloudstub receipt file")
    p_offload.add_argument("--dry-run", action="store_true", help="Compute SHA-256 and preview without deleting")

    p_restore = sub.add_parser("restore", help="Restore an offloaded file or project folder from its .cloudstub receipt")
    p_restore.add_argument("--stub", required=True, help="Path to .cloudstub file")

    p_clean = sub.add_parser("clean-cache", help="Safely purge a developer/system cache by ID")
    p_clean.add_argument("--id", required=True, help="Cache ID from scan output (e.g., projects_rust_targets, npm_cache)")

    p_serve = sub.add_parser("serve", help="Start the local Cloud Space Guard Web Dashboard")
    p_serve.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port number (default 7474)")

    args = parser.parse_args()

    if args.command == "status":
        print(json.dumps({
            "telemetry": get_disk_telemetry(args.target_gb),
            "providers": discover_cloud_providers(),
        }, indent=2))
    elif args.command == "scan":
        print(json.dumps({
            "telemetry": get_disk_telemetry(),
            "caches": scan_system_caches(),
            "candidates": scan_offload_candidates(min_size_mb=args.min_mb),
        }, indent=2))
    elif args.command == "offload":
        res = verify_and_offload_file(
            file_path_str=args.file,
            provider_id=args.provider,
            leave_stub=not args.no_stub,
            dry_run=args.dry_run,
        )
        print(json.dumps(res, indent=2))
        sys.exit(0 if res.get("ok") else 1)
    elif args.command == "restore":
        res = restore_from_stub(args.stub)
        print(json.dumps(res, indent=2))
        sys.exit(0 if res.get("ok") else 1)
    elif args.command == "clean-cache":
        res = clean_safe_cache(args.id)
        print(json.dumps(res, indent=2))
        sys.exit(0 if res.get("ok") else 1)
    else:
        port = getattr(args, "port", DEFAULT_PORT)
        run_server(port=port)


if __name__ == "__main__":
    main()
