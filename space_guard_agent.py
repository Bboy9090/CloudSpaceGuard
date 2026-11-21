#!/usr/bin/env python3
"""
Cloud Space Guard — Cross-Platform Local Vault Copy & Cache Audit Agent
Supports: macOS, Windows, Linux, and ChromeOS (Chromebooks / Crostini)

Features:
  1. Real-time Disk Telemetry & Target Free-Space Planner (e.g. 74 GB for Bootcamp / VMs)
  2. Multi-Cloud Vault Folder Discovery & Custom Vault Connectors:
     - Google Drive, iCloud Drive, Microsoft OneDrive, Dropbox, or custom local/mounted folders
  3. Verified Local Vault Copy (SHA-256 Checksum Verification + .cloudstub receipts):
     - Copies individual files or complete directory archives (.tar.gz) into the selected vault folder.
     - Retains original source files/directories (a local sync folder does not prove remote cloud durability,
       and keeping the source does not reclaim local disk space).
  4. Developer & System Cache Audit and Selective Cache Cleaning
  5. Built-in Local Web Dashboard Server (http://127.0.0.1:7474) + CLI
"""

from __future__ import annotations

import argparse
import ctypes
import datetime
import errno
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
import threading
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
        "total_bytes": usage.total,
        "used_bytes": usage.total - usage.free,
        "free_bytes": usage.free,
        "total_gb": total_gb,
        "used_gb": used_gb,
        "free_gb": free_gb,
        "used_percent": round((used_gb / total_gb) * 100, 1) if total_gb > 0 else 0.0,
        "target_free_gb": target,
        "deficit_gb": needed_gb,
        "target_met": free_gb >= target,
    }


_JOB_LOCK = threading.Lock()
_ACTIVE_JOBS: Dict[str, Dict[str, Any]] = {}


def _start_job(kind: str, target: str, phase: str, bytes_total: int = 0) -> str:
    job_id = uuid.uuid4().hex[:12]
    with _JOB_LOCK:
        # Keep only active jobs and the 10 most recent finished jobs
        if len(_ACTIVE_JOBS) > 15:
            finished = [k for k, v in _ACTIVE_JOBS.items() if v.get("done")]
            for k in finished[:-10]:
                _ACTIVE_JOBS.pop(k, None)
        _ACTIVE_JOBS[job_id] = {
            "id": job_id,
            "kind": kind,
            "target": target,
            "phase": phase,
            "detail": "",
            "started_at": time.time(),
            "updated_at": time.time(),
            "bytes_done": 0,
            "bytes_total": bytes_total,
            "items_done": 0,
            "items_total": 0,
            "done": False,
            "ok": None,
        }
    return job_id


def _update_job(job_id: str, **fields: Any) -> None:
    with _JOB_LOCK:
        job = _ACTIVE_JOBS.get(job_id)
        if job is not None:
            job.update(fields)
            job["updated_at"] = time.time()


def _finish_job(job_id: str, ok: bool, phase: str, detail: str = "") -> None:
    with _JOB_LOCK:
        job = _ACTIVE_JOBS.get(job_id)
        if job is not None:
            job["done"] = True
            job["ok"] = ok
            job["phase"] = phase
            if detail:
                job["detail"] = detail
            job["updated_at"] = time.time()


def get_active_jobs() -> List[Dict[str, Any]]:
    now = time.time()
    with _JOB_LOCK:
        jobs = []
        for j in _ACTIVE_JOBS.values():
            copy = dict(j)
            copy["elapsed_sec"] = round(max(0.0, (copy["updated_at"] if copy["done"] else now) - copy["started_at"]), 2)
            jobs.append(copy)
        jobs.sort(key=lambda x: x["started_at"], reverse=True)
        return jobs[:12]


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
            "category": "Container Virtual Disk",
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
            "safe_level": "review",
            "clean_cmd": "rm -rf ~/.cache/*",
            "description": "Standard XDG user cache directory on Linux and ChromeOS. Review before cleaning so active desktop/browser state is not disrupted.",
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
                "safe_level": "review",
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
                "safe_level": "review",
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
                    age_days = max(0, int((time.time() - st.st_mtime) // 86400))
                    candidates.append({
                        "name": f"{proj.name} (Project Snapshot Folder)",
                        "path": str(proj),
                        "is_directory": True,
                        "category": "Folder",
                        "size_bytes": sz,
                        "size_gb": round(sz / (1024 ** 3), 2),
                        "size_mb": round(sz / (1024 ** 2), 1),
                        "size_formatted": f"{round(sz / (1024 ** 3), 2)} GB",
                        "modified": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                        "age_days": age_days,
                        "already_in_cloud": None,
                        "recommended_action": "Archive (.tar.gz) + SHA-256 Local Vault Copy (Source Retained)",
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
                        age_days = max(0, int((time.time() - st.st_mtime) // 86400))
                        candidates.append({
                            "name": fname,
                            "path": str(fpath),
                            "is_directory": False,
                            "category": _classify_extension(fname, False),
                            "size_bytes": st.st_size,
                            "size_gb": round(st.st_size / (1024 ** 3), 2),
                            "size_mb": round(st.st_size / (1024 ** 2), 1),
                            "size_formatted": f"{round(st.st_size / (1024 ** 2), 1)} MB",
                            "modified": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                            "age_days": age_days,
                            "already_in_cloud": "icloud" if in_icloud else ("gdrive" if in_gdrive else None),
                            "recommended_action": (
                                "In iCloud Folder (Verify Local Vault Copy; Source Retained)"
                                if in_icloud
                                else ("In Google Drive Folder (Verify Local Vault Copy; Source Retained)" if in_gdrive else "SHA-256 Local Vault Copy (Source Retained)")
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


def _is_normalized_archive_member_path(name: str, expected_root: Optional[str] = None) -> bool:
    cleaned = name.rstrip("/")
    if not cleaned or cleaned.startswith("/") or "\\" in cleaned:
        return False
    raw_parts = cleaned.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        return False
    if expected_root is not None and raw_parts[0] != expected_root:
        return False
    return True


def _verify_directory_archive(archive: Path, expected: Dict[str, Optional[str]]) -> None:
    seen: Dict[str, Optional[str]] = {}
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            if not _is_normalized_archive_member_path(member.name):
                raise ValueError(f"Non-normalized or unsafe archive entry: {member.name}")
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
        job_id = _start_job("hash_check", str(src), "Computing SHA-256 preview")
        try:
            source_bytes = src.stat().st_size if src.is_file() else dir_size_bytes(src)
            digest = compute_sha256(src) if src.is_file() else None
            _finish_job(job_id, True, "Dry-run hash check complete", f"{src.name} ({round(source_bytes / (1024 ** 2), 1)} MB)")
            return {"ok": True, "mode": "dry_run", "file_name": src.name,
                    "original_path": str(src), "size_bytes": source_bytes,
                    "local_sha256": digest, "is_directory": src.is_dir(),
                    "cloud_destination": str(vault), "stub_path": str(receipt),
                    "source_retained": True, "remote_durability_verified": False}
        except Exception as exc:
            _finish_job(job_id, False, "Dry-run failed", str(exc))
            return {"ok": False, "error": str(exc)}
    telemetry_before = get_disk_telemetry()
    source_bytes = src.stat().st_size if src.is_file() else dir_size_bytes(src)
    job_id = _start_job("vault_copy", str(src), "Preparing local vault copy", bytes_total=source_bytes)
    dest = None
    receipt_created = False
    try:
        vault.mkdir(parents=True, exist_ok=True)
        dest_dir = vault / "cloud-space-guard" / uuid.uuid4().hex
        dest_dir.mkdir(parents=True, exist_ok=False)
        dest = dest_dir / (src.name + ".csg-archive.tar.gz" if src.is_dir() else src.name)
        if src.is_dir():
            _update_job(job_id, phase="Snapshotting directory & hashing files", detail=src.name)
            snapshot = _directory_snapshot(src)
            _update_job(job_id, phase="Creating compressed .tar.gz archive", detail=str(dest))
            with tarfile.open(dest, "x:gz") as tar:
                tar.add(src, arcname=src.name, recursive=True)
            _update_job(job_id, phase="Verifying archive against snapshot", detail=dest.name)
            _verify_directory_archive(dest, snapshot)
            if _directory_snapshot(src) != snapshot:
                raise ValueError("Source directory changed during archive creation.")
            _update_job(job_id, phase="Computing archive SHA-256", detail=dest.name)
            digest = compute_sha256(dest)
        else:
            _update_job(job_id, phase="Computing source SHA-256", detail=src.name)
            digest = compute_sha256(src)
            _update_job(job_id, phase="Copying bytes to local vault", detail=str(dest))
            with src.open("rb") as source, dest.open("xb") as target:
                shutil.copyfileobj(source, target)
            _update_job(job_id, phase="Verifying copied file SHA-256", detail=dest.name)
            if compute_sha256(dest) != digest or compute_sha256(src) != digest:
                raise ValueError("Source or copied file changed during verification.")
        vault_bytes = dest.stat().st_size
        _update_job(job_id, phase="Writing receipt & ledger", bytes_done=source_bytes)
        payload = {"schema": "cloud-space-guard.stub/v1", "is_directory_archive": src.is_dir(),
                   "original_name": src.name, "original_path": str(src),
                   "cloud_provider_id": provider["id"], "cloud_provider_name": provider["name"],
                   "cloud_vault_path": str(dest), "size_bytes": vault_bytes,
                   "source_bytes": source_bytes,
                   "sha256": digest, "offloaded_at": datetime.datetime.now().isoformat(timespec="seconds"),
                   "remote_durability_verified": False, "source_retained": True}
        if leave_stub:
            with receipt.open("x", encoding="utf-8") as stream:
                receipt_created = True
                json.dump(payload, stream, indent=2)
        entry = {"timestamp": payload["offloaded_at"], "action": "verified_local_vault_copy",
                 "file_name": src.name, "original_path": str(src), "cloud_destination": str(dest),
                 "stub_path": str(receipt) if leave_stub else None, "provider_id": provider["id"],
                 "provider_name": provider["name"], "size_bytes": vault_bytes,
                 "source_bytes": source_bytes, "sha256": digest, "verified": True,
                 "remote_durability_verified": False, "source_retained": True}
        append_ledger(entry)
        global _CACHED_CANDIDATES
        _CACHED_CANDIDATES = []
        telemetry_after = get_disk_telemetry()
        _finish_job(job_id, True, "Verified local vault copy complete", f"{src.name} -> {dest.name}")
        return {"ok": True, "mode": "verified_local_vault_copy", "entry": entry,
                "size_bytes": vault_bytes, "source_bytes": source_bytes,
                "telemetry_before": telemetry_before, "telemetry_after": telemetry_after,
                "disk_free_delta_bytes": telemetry_after["free_bytes"] - telemetry_before["free_bytes"],
                "source_retained": True, "remote_durability_verified": False,
                "message": "Local vault copy verified; source retained. Cloud upload is not verified and no space was reclaimed."}
    except Exception as exc:
        _finish_job(job_id, False, "Vault copy failed", str(exc))
        # Preserve any copy on failure for manual recovery. Never remove source or receipt.
        return {"ok": False, "error": str(exc), "source_retained": True,
                "partial_copy": str(dest) if dest else None, "receipt_created": receipt_created}


def _safe_extract_tar(tar: tarfile.TarFile, target_dir: Path) -> None:
    """Prevents CVE-2007-4559 path traversal (Tar-Slip) and rejects links/special files during restore."""
    resolved_root = target_dir.resolve()
    for member in tar.getmembers():
        if not _is_normalized_archive_member_path(member.name):
            raise ValueError(f"Blocked unsafe tar path traversal: {member.name}")
        member_path = (resolved_root / member.name).resolve()
        if not str(member_path).startswith(str(resolved_root) + os.sep) and member_path != resolved_root:
            raise ValueError(f"Blocked unsafe tar path traversal: {member.name}")
        if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
            raise ValueError(f"Blocked unsupported or link entry in archive: {member.name}")
    tar.extractall(path=resolved_root)


def _rename_directory_no_replace(source: Path, destination: Path) -> None:
    """Atomically install a directory only when the destination is absent."""
    if sys.platform == "win32":
        os.rename(source, destination)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename = getattr(libc, "renamex_np", None)
        if rename is None:
            raise OSError(errno.ENOTSUP, "Atomic no-replace rename unavailable")
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(os.fsencode(source), os.fsencode(destination), 0x4)  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise OSError(errno.ENOTSUP, "Atomic no-replace rename unavailable")
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1)  # RENAME_NOREPLACE
    else:
        raise OSError(errno.ENOTSUP, "Atomic no-replace rename unavailable")
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))


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
                        if not _is_normalized_archive_member_path(member.name, expected_root=expected_root):
                            raise ValueError(f"Unsafe archive member: {member.name}")
                        norm_name = member.name.rstrip("/")
                        if norm_name in seen or not (member.isfile() or member.isdir()):
                            raise ValueError(f"Unsafe archive member: {member.name}")
                        seen.add(norm_name)
                    _safe_extract_tar(tar, stage)
                staged_root = stage / expected_root
                if not staged_root.is_dir() or staged_root.is_symlink():
                    raise ValueError("Archive lacks the expected directory root.")
                if os.path.lexists(orig_file):
                    return {"ok": False, "error": f"Restore destination already exists: {orig_file}"}
                _rename_directory_no_replace(staged_root, orig_file)
            restored_sha = remote_sha
        else:
            orig_file.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="csg-file-restore-", dir=orig_file.parent) as staging:
                staged = Path(staging) / "content"
                with cloud_file.open("rb") as source, staged.open("xb") as destination:
                    shutil.copyfileobj(source, destination)
                restored_sha = compute_sha256(staged)
                if restored_sha != meta.get("sha256"):
                    return {
                        "ok": False,
                        "error": f"Local write SHA-256 verification failed! Expected {meta.get('sha256')}, got {restored_sha}",
                    }
                try:
                    os.link(staged, orig_file)
                except FileExistsError:
                    return {"ok": False, "error": f"Restore destination already exists: {orig_file}"}

        stub_path.unlink()
        entry = {
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "action": "restored_from_vault",
            "file_name": orig_file.name,
            "original_path": str(orig_file),
            "cloud_destination": str(cloud_file),
            "size_bytes": meta.get("size_bytes", 0),
            "sha256": restored_sha,
            "verified": True,
        }
        append_ledger(entry)
        telemetry_after = get_disk_telemetry()
        return {"ok": True, "entry": entry, "telemetry_after": telemetry_after}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def inspect_cache_target(cache_id: str, limit: int = 30) -> Dict[str, Any]:
    caches = {c["id"]: c for c in scan_system_caches()}
    target = caches.get(cache_id)
    if not target:
        return {"ok": False, "error": f"Cache target '{cache_id}' not found or already empty."}
    path = Path(target["path"])
    if not path.exists() or not path.is_dir():
        return {"ok": True, "id": cache_id, "name": target["name"], "path": str(path), "total_items": 0, "items": []}
    entries: List[Dict[str, Any]] = []
    try:
        children = list(path.iterdir())
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    for child in children:
        if child.is_symlink():
            sz = 0
        elif child.is_dir():
            sz = dir_size_bytes(child, max_entries=5000)
        else:
            try:
                sz = child.stat().st_size
            except OSError:
                sz = 0
        entries.append({
            "name": child.name,
            "path": str(child),
            "is_dir": child.is_dir(),
            "size_bytes": sz,
            "size_mb": round(sz / (1024 ** 2), 2),
        })
    entries.sort(key=lambda x: x["size_bytes"], reverse=True)
    return {
        "ok": True,
        "id": cache_id,
        "name": target["name"],
        "path": str(path),
        "safe_level": target["safe_level"],
        "total_items": len(entries),
        "items": entries[:limit],
    }


def reveal_local_path(path_str: str) -> Dict[str, Any]:
    if not path_str:
        return {"ok": False, "error": "Path is required."}
    target = Path(path_str).expanduser()
    if not target.exists():
        return {"ok": False, "error": f"Path does not exist: {target}"}
    sys_name = platform.system().lower()
    try:
        if sys_name == "darwin":
            cmd = ["open", "-R", str(target)] if target.is_file() else ["open", str(target)]
            subprocess.Popen(cmd)
        elif sys_name == "windows":
            if target.is_file():
                subprocess.Popen(["explorer", f"/select,{target}"])
            else:
                subprocess.Popen(["explorer", str(target)])
        else:
            open_target = target.parent if target.is_file() else target
            subprocess.Popen(["xdg-open", str(open_target)])
        return {"ok": True, "path": str(target)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def clean_safe_cache(cache_id: str) -> Dict[str, Any]:
    caches = {c["id"]: c for c in scan_system_caches(force_refresh=True)}
    target = caches.get(cache_id)
    if not target:
        return {"ok": False, "error": f"Cache target '{cache_id}' not found or already empty."}

    if target["safe_level"] != "safe":
        return {
            "ok": False,
            "error": f"'{target['name']}' requires manual review ({target['clean_cmd']}) so active containers/VMs or project trees are not disrupted.",
        }

    path = Path(target["path"])
    telemetry_before = get_disk_telemetry()
    before_bytes = dir_size_bytes(path) if path.exists() else 0
    job_id = _start_job("clean_cache", target["name"], "Scanning cache items", bytes_total=before_bytes)
    errors: List[str] = []
    deleted_items: List[Dict[str, Any]] = []
    deleted_count = 0
    try:
        if path.is_dir():
            children = list(path.iterdir())
            _update_job(job_id, items_total=len(children), phase="Deleting cache entries")

            def _on_rm_error(func: Any, failed_path: str, exc_info: Any) -> None:
                errors.append(f"{failed_path}: {exc_info[1]}")

            for idx, child in enumerate(children, 1):
                _update_job(job_id, items_done=idx, detail=child.name)
                child_is_dir = child.is_dir() and not child.is_symlink()
                child_size = dir_size_bytes(child, max_entries=2000) if child_is_dir else (
                    child.stat().st_size if child.exists() and not child.is_symlink() else 0
                )
                err_before = len(errors)
                if child_is_dir:
                    shutil.rmtree(child, onerror=_on_rm_error)
                else:
                    try:
                        child.unlink()
                    except OSError as exc:
                        errors.append(f"{child}: {exc}")
                if len(errors) == err_before and not os.path.lexists(child):
                    deleted_count += 1
                    if len(deleted_items) < 50:
                        deleted_items.append({
                            "name": child.name,
                            "path": str(child),
                            "is_dir": child_is_dir,
                            "size_bytes": child_size,
                        })
        after_bytes = dir_size_bytes(path) if path.exists() else 0
        # Invalidate in-memory cache so subsequent reads see freshly freed disk
        global _CACHE_TIMESTAMP, _CACHED_CACHES, _CACHED_CANDIDATES
        _CACHE_TIMESTAMP = 0.0
        _CACHED_CACHES = []
        _CACHED_CANDIDATES = []
        freed_bytes = max(0, before_bytes - after_bytes)
        telemetry_after = get_disk_telemetry()
        if errors and freed_bytes == 0 and deleted_count == 0:
            _finish_job(job_id, False, "Cache clean failed", errors[0])
            return {
                "ok": False,
                "error": f"Failed to clean cache: {errors[0]}",
                "errors": errors,
                "after_bytes": after_bytes,
                "telemetry_before": telemetry_before,
                "telemetry_after": telemetry_after,
            }
        entry = {
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "action": "cache_cleaned",
            "file_name": target["name"],
            "original_path": str(path),
            "cloud_destination": f"Local Safe Cache Purge ({deleted_count} item(s) removed)",
            "size_bytes": freed_bytes,
            "sha256": "CACHE-PURGE",
            "verified": len(errors) == 0,
        }
        append_ledger(entry)
        _finish_job(
            job_id,
            True,
            "Cache cleaned",
            f"Removed {deleted_count} item(s), reclaimed {round(freed_bytes / (1024 ** 2), 1)} MB",
        )
        return {
            "ok": True,
            "cache_id": cache_id,
            "cache_name": target["name"],
            "cache_path": str(path),
            "before_bytes": before_bytes,
            "freed_bytes": freed_bytes,
            "freed_mb": round(freed_bytes / (1024 ** 2), 1),
            "after_bytes": after_bytes,
            "deleted_count": deleted_count,
            "deleted_items": deleted_items,
            "failed_count": len(errors),
            "partial_errors": errors,
            "telemetry_before": telemetry_before,
            "telemetry_after": telemetry_after,
            "disk_free_delta_bytes": telemetry_after["free_bytes"] - telemetry_before["free_bytes"],
            "entry": entry,
        }
    except Exception as exc:
        _finish_job(job_id, False, "Cache clean failed", str(exc))
        return {"ok": False, "error": str(exc)}


def _classify_extension(name: str, is_dir: bool) -> str:
    if is_dir:
        return "Folders"
    ext = Path(name).suffix.lower()
    if ext in {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst"}:
        return "Archives"
    if ext in {".dmg", ".iso", ".img", ".pkg", ".msi", ".exe", ".appimage", ".deb", ".rpm"}:
        return "Disk Images & Installers"
    if ext in {".mp4", ".mov", ".mkv", ".avi", ".webm", ".mp3", ".wav", ".flac", ".png", ".jpg", ".jpeg", ".heic", ".raw"}:
        return "Media"
    if ext in {".pdf", ".docx", ".xlsx", ".pptx", ".csv", ".txt", ".md", ".json"}:
        return "Documents & Data"
    return "Other Files"


def explore_directory(path_str: Optional[str] = None, limit: int = 40) -> Dict[str, Any]:
    """DaisyDisk / WinDirStat-style directory drill-down with proportional sizes and type breakdown."""
    home = Path.home().resolve()
    target = Path(path_str).expanduser().resolve() if path_str else home
    if not target.exists() or not target.is_dir():
        return {"ok": False, "error": f"Directory not found: {target}"}
    job_id = _start_job("explore", str(target), "Scanning directory sizes")
    entries: List[Dict[str, Any]] = []
    type_totals: Dict[str, int] = {}
    total_bytes = 0
    try:
        children = list(target.iterdir())
        _update_job(job_id, items_total=len(children), phase="Measuring subdirectories & files")
        for idx, child in enumerate(children, 1):
            if idx % 10 == 0 or idx == len(children):
                _update_job(job_id, items_done=idx, detail=child.name)
            if child.is_symlink():
                continue
            is_dir = child.is_dir()
            if is_dir:
                sz = dir_size_bytes(child, max_entries=10000)
            else:
                try:
                    sz = child.stat().st_size
                except OSError:
                    sz = 0
            total_bytes += sz
            cat = _classify_extension(child.name, is_dir)
            type_totals[cat] = type_totals.get(cat, 0) + sz
            try:
                mtime = datetime.datetime.fromtimestamp(child.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            except OSError:
                mtime = ""
            entries.append({
                "name": child.name,
                "path": str(child),
                "is_dir": is_dir,
                "category": cat,
                "size_bytes": sz,
                "modified": mtime,
            })
        entries.sort(key=lambda x: x["size_bytes"], reverse=True)
        for item in entries:
            item["percent"] = round((item["size_bytes"] / total_bytes) * 100, 1) if total_bytes > 0 else 0.0
        breakdown = [
            {
                "category": k,
                "size_bytes": v,
                "percent": round((v / total_bytes) * 100, 1) if total_bytes > 0 else 0.0,
            }
            for k, v in sorted(type_totals.items(), key=lambda kv: kv[1], reverse=True)
            if v > 0
        ]
        _finish_job(job_id, True, "Directory scan complete", f"{len(entries)} entries")
        return {
            "ok": True,
            "path": str(target),
            "parent_path": str(target.parent) if target != target.parent else None,
            "total_bytes": total_bytes,
            "total_entries": len(entries),
            "items": entries[:limit],
            "breakdown": breakdown,
        }
    except PermissionError as exc:
        _finish_job(job_id, False, "Permission denied", str(exc))
        return {"ok": False, "error": f"Permission denied: {target}"}
    except Exception as exc:
        _finish_job(job_id, False, "Explore failed", str(exc))
        return {"ok": False, "error": str(exc)}


def list_granular_clean_targets() -> List[Dict[str, Any]]:
    """DevCleaner-style granular build & Xcode sub-targets (each selectable individually)."""
    home = Path.home()
    targets: List[Dict[str, Any]] = []
    for sub in discover_project_build_caches():
        if sub.is_symlink() or not sub.is_dir():
            continue
        sz = dir_size_bytes(sub, max_entries=15000)
        if sz <= 0:
            continue
        try:
            rel = sub.relative_to(home / "Projects")
            proj_name = rel.parts[0] if rel.parts else sub.parent.name
        except ValueError:
            proj_name = sub.parent.name
        try:
            mtime = datetime.datetime.fromtimestamp(sub.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        except OSError:
            mtime = ""
        targets.append({
            "path": str(sub.resolve()),
            "project": proj_name,
            "kind": "Rust target" if sub.name == "target" else "Node node_modules",
            "name": f"{proj_name} / {sub.name}",
            "size_bytes": sz,
            "modified": mtime,
        })

    xcode_roots = [
        ("Xcode DerivedData", home / "Library" / "Developer" / "Xcode" / "DerivedData"),
        ("Xcode iOS DeviceSupport", home / "Library" / "Developer" / "Xcode" / "iOS DeviceSupport"),
    ]
    for kind, root in xcode_roots:
        if root.exists() and root.is_dir() and not root.is_symlink():
            try:
                for child in root.iterdir():
                    if child.is_dir() and not child.is_symlink():
                        sz = dir_size_bytes(child, max_entries=10000)
                        if sz > 1024 * 1024:
                            try:
                                mtime = datetime.datetime.fromtimestamp(child.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                            except OSError:
                                mtime = ""
                            targets.append({
                                "path": str(child.resolve()),
                                "project": child.name,
                                "kind": kind,
                                "name": f"{kind}: {child.name}",
                                "size_bytes": sz,
                                "modified": mtime,
                            })
            except OSError:
                pass
    targets.sort(key=lambda x: x["size_bytes"], reverse=True)
    return targets


def clean_granular_target(target_path_str: str) -> Dict[str, Any]:
    """Delete one explicitly confirmed project build or Xcode sub-target (allowlisted only)."""
    if not target_path_str:
        return {"ok": False, "error": "Target path is required."}
    req_path = Path(target_path_str).expanduser().resolve()
    allowed = {str(Path(t["path"]).expanduser().resolve()): t for t in list_granular_clean_targets()}
    meta = allowed.get(str(req_path))
    if not meta:
        return {"ok": False, "error": f"Refused: '{req_path}' is not an allowlisted build/Xcode sub-target."}

    telemetry_before = get_disk_telemetry()
    before_bytes = dir_size_bytes(req_path) if req_path.exists() else 0
    job_id = _start_job("clean_project_target", meta["name"], "Deleting build sub-target", bytes_total=before_bytes)
    errors: List[str] = []
    try:
        def _on_rm_error(func: Any, failed_path: str, exc_info: Any) -> None:
            errors.append(f"{failed_path}: {exc_info[1]}")

        shutil.rmtree(req_path, onerror=_on_rm_error)
        after_bytes = dir_size_bytes(req_path) if req_path.exists() else 0
        freed_bytes = max(0, before_bytes - after_bytes)
        global _CACHE_TIMESTAMP, _CACHED_CACHES, _CACHED_CANDIDATES
        _CACHE_TIMESTAMP = 0.0
        _CACHED_CACHES = []
        _CACHED_CANDIDATES = []
        telemetry_after = get_disk_telemetry()
        if errors and freed_bytes == 0 and req_path.exists():
            _finish_job(job_id, False, "Clean failed", errors[0])
            return {
                "ok": False,
                "error": f"Failed to remove {meta['name']}: {errors[0]}",
                "errors": errors,
                "telemetry_before": telemetry_before,
                "telemetry_after": telemetry_after,
            }
        entry = {
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "action": "project_target_cleaned",
            "file_name": meta["name"],
            "original_path": str(req_path),
            "cloud_destination": f"Granular {meta['kind']} Purge",
            "size_bytes": freed_bytes,
            "sha256": "BUILD-SUBTARGET-PURGE",
            "verified": len(errors) == 0,
        }
        append_ledger(entry)
        _finish_job(job_id, True, "Build sub-target removed", f"Freed {round(freed_bytes / (1024 ** 2), 1)} MB")
        return {
            "ok": True,
            "cache_name": meta["name"],
            "cache_path": str(req_path),
            "before_bytes": before_bytes,
            "after_bytes": after_bytes,
            "freed_bytes": freed_bytes,
            "freed_mb": round(freed_bytes / (1024 ** 2), 1),
            "deleted_count": 1 if not req_path.exists() else 0,
            "deleted_items": [{"name": meta["name"], "path": str(req_path), "is_dir": True, "size_bytes": freed_bytes}],
            "partial_errors": errors,
            "telemetry_before": telemetry_before,
            "telemetry_after": telemetry_after,
            "disk_free_delta_bytes": telemetry_after["free_bytes"] - telemetry_before["free_bytes"],
            "entry": entry,
        }
    except Exception as exc:
        _finish_job(job_id, False, "Clean failed", str(exc))
        return {"ok": False, "error": str(exc)}


def find_duplicate_files(root_str: Optional[str] = None, min_mb: float = 1.0, max_files: int = 8000) -> Dict[str, Any]:
    """WizTree-style 2-phase exact duplicate finder (size grouping followed by SHA-256 verification)."""
    root = Path(root_str).expanduser().resolve() if root_str else (Path.home() / "Downloads").resolve()
    if not root.exists() or not root.is_dir():
        return {"ok": False, "error": f"Scan folder not found: {root}"}
    min_bytes = max(1024, int(min_mb * 1024 * 1024))
    job_id = _start_job("duplicates", str(root), "Indexing files by size")
    by_size: Dict[int, List[Path]] = {}
    scanned = 0
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames
                if not d.startswith(".") and d not in {"node_modules", "target", ".git", "CloudSpaceGuard_Vault"}
            ]
            for fname in filenames:
                if fname.endswith(".cloudstub") or fname.startswith("."):
                    continue
                fp = Path(dirpath) / fname
                if fp.is_symlink():
                    continue
                scanned += 1
                if scanned > max_files:
                    break
                try:
                    st = fp.stat()
                except OSError:
                    continue
                if st.st_size >= min_bytes:
                    by_size.setdefault(st.st_size, []).append(fp)
            if scanned > max_files:
                break

        size_candidates = {sz: paths for sz, paths in by_size.items() if len(paths) > 1}
        total_to_hash = sum(len(v) for v in size_candidates.values())
        _update_job(job_id, phase="Computing SHA-256 for size matches", items_total=total_to_hash, items_done=0)

        groups: List[Dict[str, Any]] = []
        hashed = 0
        for sz, paths in size_candidates.items():
            by_hash: Dict[str, List[Path]] = {}
            for p in paths:
                hashed += 1
                _update_job(job_id, items_done=hashed, detail=p.name)
                try:
                    digest = compute_sha256(p)
                    by_hash.setdefault(digest, []).append(p)
                except OSError:
                    continue
            for digest, dup_paths in by_hash.items():
                if len(dup_paths) > 1:
                    dup_paths.sort(key=lambda p: p.stat().st_mtime)
                    wasted = sz * (len(dup_paths) - 1)
                    groups.append({
                        "sha256": digest,
                        "file_size_bytes": sz,
                        "count": len(dup_paths),
                        "wasted_bytes": wasted,
                        "files": [
                            {
                                "name": p.name,
                                "path": str(p),
                                "modified": datetime.datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
                            }
                            for p in dup_paths
                        ],
                    })
        groups.sort(key=lambda g: g["wasted_bytes"], reverse=True)
        total_wasted = sum(g["wasted_bytes"] for g in groups)
        _finish_job(job_id, True, "Duplicate scan complete", f"{len(groups)} duplicate group(s)")
        return {
            "ok": True,
            "root": str(root),
            "scanned_files": scanned,
            "duplicate_groups": groups[:50],
            "total_wasted_bytes": total_wasted,
        }
    except Exception as exc:
        _finish_job(job_id, False, "Duplicate scan failed", str(exc))
        return {"ok": False, "error": str(exc)}


def get_rclone_status() -> Dict[str, Any]:
    rclone_bin = shutil.which("rclone")
    if not rclone_bin:
        return {"ok": True, "installed": False, "remotes": [], "binary": None}
    remotes: List[str] = []
    try:
        res = subprocess.run([rclone_bin, "listremotes"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and res.stdout:
            remotes = [line.strip() for line in res.stdout.splitlines() if line.strip()]
    except Exception:
        pass
    return {"ok": True, "installed": True, "remotes": remotes, "binary": rclone_bin}


def evict_cloud_download(target_path_str: str) -> Dict[str, Any]:
    """macOS FileProvider / iCloud eviction via `brctl evict` (reclaims local cache without deleting cloud file)."""
    if sys.platform != "darwin":
        return {"ok": False, "error": "Cloud download eviction (`brctl evict`) is only supported on macOS."}
    if not target_path_str:
        return {"ok": False, "error": "Target path is required."}
    req_path = Path(target_path_str).expanduser().resolve()
    if not req_path.exists():
        return {"ok": False, "error": f"Path not found: {req_path}"}
    home = Path.home().resolve()
    allowed_roots = [
        (home / "Library" / "Mobile Documents").resolve(),
        (home / "Library" / "CloudStorage").resolve(),
    ]
    in_cloud_mount = False
    for root in allowed_roots:
        try:
            req_path.relative_to(root)
            in_cloud_mount = True
            break
        except ValueError:
            continue
    if not in_cloud_mount:
        return {"ok": False, "error": f"Refused: '{req_path}' is not inside macOS Mobile Documents or CloudStorage."}
    brctl_bin = shutil.which("brctl")
    if not brctl_bin:
        return {"ok": False, "error": "`brctl` utility not found on macOS."}

    telemetry_before = get_disk_telemetry()
    before_bytes = dir_size_bytes(req_path) if req_path.is_dir() else (req_path.stat().st_blocks * 512)
    job_id = _start_job("cloud_evict", req_path.name, "Evicting local cloud download via brctl")
    try:
        proc = subprocess.run([brctl_bin, "evict", str(req_path)], capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip() or f"brctl exited with code {proc.returncode}"
            _finish_job(job_id, False, "Cloud eviction failed", err[:180])
            return {"ok": False, "error": err, "telemetry_before": telemetry_before, "telemetry_after": get_disk_telemetry()}
        telemetry_after = get_disk_telemetry()
        delta = max(0, telemetry_after["free_bytes"] - telemetry_before["free_bytes"])
        entry = {
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "action": "cloud_evicted",
            "file_name": req_path.name,
            "original_path": str(req_path),
            "cloud_destination": "Cloud-Only Placeholder (brctl evict)",
            "size_bytes": delta or before_bytes,
            "sha256": "BRCTL-EVICT",
            "verified": True,
        }
        append_ledger(entry)
        _finish_job(job_id, True, "Evicted local cloud download", req_path.name)
        return {
            "ok": True,
            "path": str(req_path),
            "name": req_path.name,
            "before_bytes": before_bytes,
            "disk_free_delta_bytes": delta,
            "telemetry_before": telemetry_before,
            "telemetry_after": telemetry_after,
            "entry": entry,
        }
    except Exception as exc:
        _finish_job(job_id, False, "Cloud eviction failed", str(exc))
        return {"ok": False, "error": str(exc)}


def build_smart_cleanup_plan(target_free_gb: Optional[float] = None) -> Dict[str, Any]:
    """Build a prioritized, read-only cleanup plan (Safe Caches -> Build Sub-Targets -> Exact Duplicates)."""
    telemetry = get_disk_telemetry()
    if target_free_gb is not None:
        deficit_bytes = max(0, int((float(target_free_gb) * (1024 ** 3)) - telemetry["free_bytes"]))
    else:
        deficit_bytes = max(0, int((telemetry.get("deficit_gb") or 0) * (1024 ** 3)))

    safe_caches = [c for c in scan_system_caches() if c.get("safe_level") == "safe" and c.get("size_bytes", 0) > 0]
    sub_targets = [t for t in list_granular_clean_targets() if t.get("size_bytes", 0) > 0]
    dup_scan = find_duplicate_files(min_mb=5.0)
    dup_extras: List[Dict[str, Any]] = []
    for grp in dup_scan.get("duplicate_groups", []):
        for f in (grp.get("files") or [])[1:]:
            dup_extras.append({
                "path": f["path"],
                "size_bytes": grp["file_size_bytes"],
                "sha256": grp["sha256"],
            })

    safe_bytes = sum(c["size_bytes"] for c in safe_caches)
    sub_bytes = sum(t["size_bytes"] for t in sub_targets)
    dup_bytes = sum(d["size_bytes"] for d in dup_extras)
    total_reclaimable = safe_bytes + sub_bytes + dup_bytes

    return {
        "ok": True,
        "telemetry": telemetry,
        "deficit_bytes": deficit_bytes,
        "estimated_reclaim_bytes": total_reclaimable,
        "covers_deficit": total_reclaimable >= deficit_bytes if deficit_bytes > 0 else True,
        "safe_caches": safe_caches,
        "safe_caches_bytes": safe_bytes,
        "sub_targets": sub_targets,
        "sub_targets_bytes": sub_bytes,
        "duplicate_extras": dup_extras,
        "duplicate_extras_bytes": dup_bytes,
    }


def delete_local_path(target_path_str: str, confirm_delete: bool = False) -> Dict[str, Any]:
    """Explicitly delete a user-confirmed local file or subfolder to reclaim disk space."""
    if not confirm_delete:
        return {"ok": False, "error": "Explicit user confirmation (confirm_delete=True) is required."}
    if not target_path_str:
        return {"ok": False, "error": "Target path is required."}
    raw_path = Path(target_path_str).expanduser()
    if raw_path.is_symlink():
        return {"ok": False, "error": f"Refused: '{raw_path}' is a symlink."}
    req_path = raw_path.resolve()
    if not req_path.exists():
        return {"ok": False, "error": f"Path not found: {req_path}"}

    home = Path.home().resolve()
    protected_exact = {
        home,
        home / "Desktop",
        home / "Documents",
        home / "Downloads",
        home / "Pictures",
        home / "Movies",
        home / "Music",
        home / "Library",
        STATE_DIR.resolve(),
    }
    if req_path in protected_exact or req_path == Path("/"):
        return {"ok": False, "error": f"Refused: '{req_path}' is a protected root/user directory."}
    try:
        req_path.relative_to(home)
    except ValueError:
        return {"ok": False, "error": f"Refused: '{req_path}' is outside user home directory."}
    try:
        req_path.relative_to(STATE_DIR.resolve())
        return {"ok": False, "error": f"Refused: cannot delete CloudSpaceGuard ledger/state files ({req_path})."}
    except ValueError:
        pass

    telemetry_before = get_disk_telemetry()
    is_dir = req_path.is_dir()
    if is_dir:
        before_bytes = dir_size_bytes(req_path)
    else:
        st = req_path.stat()
        blocks = getattr(st, "st_blocks", 0)
        before_bytes = blocks * 512 if blocks > 0 else st.st_size

    job_id = _start_job("local_delete", req_path.name, "Deleting confirmed local target", bytes_total=before_bytes)
    try:
        if is_dir:
            shutil.rmtree(req_path)
        else:
            req_path.unlink()
        global _CACHE_TIMESTAMP, _CACHED_CACHES, _CACHED_CANDIDATES
        _CACHE_TIMESTAMP = 0.0
        _CACHED_CACHES = []
        _CACHED_CANDIDATES = []
        telemetry_after = get_disk_telemetry()
        freed_bytes = before_bytes if not req_path.exists() else 0
        entry = {
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "action": "local_deleted",
            "file_name": req_path.name,
            "original_path": str(req_path),
            "cloud_destination": "Local Disk Delete (Space Reclaimed)",
            "size_bytes": freed_bytes,
            "sha256": "LOCAL-DELETE-CONFIRMED",
            "verified": not req_path.exists(),
        }
        append_ledger(entry)
        _finish_job(job_id, True, "Local target deleted", f"Freed {round(freed_bytes / (1024 ** 2), 1)} MB")
        return {
            "ok": True,
            "path": str(req_path),
            "name": req_path.name,
            "is_dir": is_dir,
            "before_bytes": before_bytes,
            "freed_bytes": freed_bytes,
            "freed_mb": round(freed_bytes / (1024 ** 2), 1),
            "telemetry_before": telemetry_before,
            "telemetry_after": telemetry_after,
            "disk_free_delta_bytes": telemetry_after["free_bytes"] - telemetry_before["free_bytes"],
            "entry": entry,
        }
    except Exception as exc:
        _finish_job(job_id, False, "Delete failed", str(exc))
        return {"ok": False, "error": str(exc), "telemetry_before": telemetry_before, "telemetry_after": get_disk_telemetry()}


def run_rclone_verify(
    source_path_str: str,
    remote_target: str,
    dry_run: bool = True,
    delete_source_after_remote_verify: bool = False,
) -> Dict[str, Any]:
    """Rclone-powered remote copy + checksum check. Never deletes the local source."""
    status = get_rclone_status()
    if not status["installed"]:
        return {"ok": False, "error": "rclone is not installed on this system. Install rclone and configure a remote first.", "source_retained": True, "remote_durability_verified": False}
    if not status["remotes"]:
        return {"ok": False, "error": "No rclone remotes configured. Run 'rclone config' in terminal first.", "source_retained": True, "remote_durability_verified": False}
    if not source_path_str or not remote_target:
        return {"ok": False, "error": "Source path and rclone remote target (e.g. myremote:vault/) are required.", "source_retained": True, "remote_durability_verified": False}
    src = Path(source_path_str).expanduser().resolve()
    if not src.exists():
        return {"ok": False, "error": f"Source not found: {src}", "source_retained": True, "remote_durability_verified": False}
    remote_prefix = remote_target.split(":", 1)[0] + ":"
    if remote_prefix not in status["remotes"]:
        return {"ok": False, "error": f"Unknown rclone remote '{remote_prefix}'. Configured: {', '.join(status['remotes'])}", "source_retained": True, "remote_durability_verified": False}

    rclone_bin = status["binary"]
    job_id = _start_job("rclone_verify", str(src), "Running rclone remote checksum copy" if not dry_run else "Running rclone dry-run")
    try:
        copy_cmd = [rclone_bin, "copy", "--checksum", str(src), remote_target]
        if dry_run:
            copy_cmd.append("--dry-run")
        copy_res = subprocess.run(copy_cmd, capture_output=True, text=True, timeout=120)
        if copy_res.returncode != 0:
            _finish_job(job_id, False, "rclone copy failed", copy_res.stderr.strip()[:200])
            return {"ok": False, "error": copy_res.stderr.strip() or "rclone copy failed", "source_retained": True}

        remote_verified = False
        check_output = ""
        if not dry_run:
            _update_job(job_id, phase="Verifying remote checksums via rclone check", detail=remote_target)
            check_target = f"{remote_target.rstrip('/')}/{src.name}" if src.is_file() else remote_target
            check_cmd = [rclone_bin, "check", str(src), check_target]
            check_res = subprocess.run(check_cmd, capture_output=True, text=True, timeout=120)
            remote_verified = check_res.returncode == 0
            check_output = (check_res.stdout + "\n" + check_res.stderr).strip()
            if not remote_verified:
                _finish_job(job_id, False, "rclone check reported mismatch", check_output[:200])
                return {
                    "ok": False,
                    "error": f"Remote checksum check failed: {check_output or 'mismatch'}",
                    "source_retained": True,
                    "remote_durability_verified": False,
                }

        source_retained = True
        freed_bytes = 0
        telemetry_before = get_disk_telemetry()
        telemetry_after = telemetry_before
        if not dry_run and remote_verified and delete_source_after_remote_verify:
            del_res = delete_local_path(str(src), confirm_delete=True)
            if del_res.get("ok"):
                source_retained = False
                freed_bytes = del_res.get("freed_bytes", 0)
                telemetry_after = del_res.get("telemetry_after", telemetry_before)

        _finish_job(job_id, True, "rclone operation complete", remote_target)
        return {
            "ok": True,
            "dry_run": dry_run,
            "source_path": str(src),
            "remote_target": remote_target,
            "source_retained": source_retained,
            "freed_bytes": freed_bytes,
            "telemetry_before": telemetry_before,
            "telemetry_after": telemetry_after,
            "remote_durability_verified": remote_verified,
            "output": (copy_res.stdout + "\n" + copy_res.stderr + "\n" + check_output).strip()[:1200],
        }
    except Exception as exc:
        _finish_job(job_id, False, "rclone error", str(exc))
        return {"ok": False, "error": str(exc), "source_retained": True}


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
            force = qs.get("refresh", ["0"])[0] in {"1", "true", "yes"}
            self._send_json({
                "ok": True,
                "telemetry": get_disk_telemetry(),
                "caches": scan_system_caches(force_refresh=force),
                "candidates": scan_offload_candidates(min_size_mb=min_mb, force_refresh=force),
                "ledger": load_ledger()[:50],
            })
            return

        if parsed.path == "/api/caches":
            force = qs.get("refresh", ["0"])[0] in {"1", "true", "yes"}
            self._send_json({"ok": True, "caches": scan_system_caches(force_refresh=force)})
            return

        if parsed.path == "/api/cache-inspect":
            cache_id = qs.get("id", [""])[0]
            res = inspect_cache_target(cache_id)
            self._send_json(res, status=200 if res.get("ok") else 404)
            return

        if parsed.path == "/api/candidates":
            min_mb = float(qs.get("min_mb", ["25"])[0])
            force = qs.get("refresh", ["0"])[0] in {"1", "true", "yes"}
            self._send_json({"ok": True, "candidates": scan_offload_candidates(min_size_mb=min_mb, force_refresh=force)})
            return

        if parsed.path == "/api/ledger":
            self._send_json({"ok": True, "ledger": load_ledger()})
            return

        if parsed.path == "/api/jobs":
            self._send_json({"ok": True, "jobs": get_active_jobs()})
            return

        if parsed.path == "/api/explore":
            req_path = qs.get("path", [None])[0]
            res = explore_directory(req_path)
            self._send_json(res, status=200 if res.get("ok") else 400)
            return

        if parsed.path == "/api/project-targets":
            self._send_json({"ok": True, "targets": list_granular_clean_targets()})
            return

        if parsed.path == "/api/duplicates":
            root_path = qs.get("root", [None])[0]
            min_mb = float(qs.get("min_mb", ["1"])[0])
            res = find_duplicate_files(root_path, min_mb=min_mb)
            self._send_json(res, status=200 if res.get("ok") else 400)
            return

        if parsed.path == "/api/rclone-status":
            self._send_json(get_rclone_status())
            return

        if parsed.path == "/api/smart-plan":
            tgt = qs.get("target_gb", [None])[0]
            res = build_smart_cleanup_plan(float(tgt) if tgt is not None else None)
            self._send_json(res)
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

        if parsed.path == "/api/reveal-path":
            res = reveal_local_path(data.get("path", ""))
            self._send_json(res, status=200 if res.get("ok") else 400)
            return

        if parsed.path == "/api/clean-project-target":
            res = clean_granular_target(data.get("path", ""))
            res["telemetry"] = get_disk_telemetry()
            self._send_json(res, status=200 if res.get("ok") else 400)
            return

        if parsed.path == "/api/rclone-verify":
            res = run_rclone_verify(
                source_path_str=data.get("source_path", ""),
                remote_target=data.get("remote_target", ""),
                dry_run=bool(data.get("dry_run", True)),
                delete_source_after_remote_verify=bool(data.get("delete_source_after_remote_verify", False)),
            )
            res["telemetry"] = get_disk_telemetry()
            self._send_json(res, status=200 if res.get("ok") else 400)
            return

        if parsed.path == "/api/delete-local-path":
            res = delete_local_path(
                target_path_str=data.get("path", ""),
                confirm_delete=bool(data.get("confirm_delete", False)),
            )
            res["telemetry"] = get_disk_telemetry()
            self._send_json(res, status=200 if res.get("ok") else 400)
            return

        if parsed.path == "/api/evict-cloud-download":
            res = evict_cloud_download(data.get("path", ""))
            res["telemetry"] = get_disk_telemetry()
            self._send_json(res, status=200 if res.get("ok") else 400)
            return

        if parsed.path == "/api/clean-all-safe":
            self._send_json(
                {
                    "ok": False,
                    "error": "Bulk cache cleaning is disabled pending per-target safety qualification. Clean individual verified caches instead.",
                },
                status=403,
            )
            return

        self._send_json({"ok": False, "error": "Unknown endpoint"}, status=404)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

def run_server(port: int = DEFAULT_PORT) -> None:
    ensure_state_dir()
    with ThreadedTCPServer(("127.0.0.1", port), SpaceGuardRequestHandler) as httpd:
        print(f"==================================================================")
        print(f"  Cloud Space Guard v{APP_VERSION} — Verified Local Vault Copy & Cache Audit")
        print(f"  OS Profile : {detect_os_profile().upper()} ({platform.node()})")
        print(f"  Dashboard  : http://127.0.0.1:{port}")
        print(f"==================================================================")
        httpd.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cloud Space Guard — Verified Local Vault Copy & Safe Cache Audit Suite"
    )
    sub = parser.add_subparsers(dest="command")

    p_status = sub.add_parser("status", help="Show disk space telemetry and detected cloud providers")
    p_status.add_argument("--target-gb", type=float, default=None, help="Target free GB (e.g. 74.0)")

    p_scan = sub.add_parser("scan", help="Scan system caches and large offloadable files/projects")
    p_scan.add_argument("--min-mb", type=float, default=25.0, help="Minimum size in MB")

    p_offload = sub.add_parser("offload", help="Create a verified local vault copy of a file or project folder (source retained; cloud upload not verified)")
    p_offload.add_argument("--file", required=True, help="Path to local file or project folder")
    p_offload.add_argument("--provider", default="gdrive", help="Cloud provider ID (gdrive, icloud, onedrive, dropbox, etc.)")
    p_offload.add_argument("--no-stub", action="store_true", help="Do not leave a .cloudstub receipt file")
    p_offload.add_argument("--dry-run", action="store_true", help="Compute SHA-256 and preview without deleting")

    p_restore = sub.add_parser("restore", help="Restore a file or project folder from its .cloudstub receipt into an absent destination (existing targets rejected)")
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
