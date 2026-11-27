"""CloudSpaceGuard — Launches Bobby's ACTUAL space_guard_agent.py + web/index.html natively."""
from __future__ import annotations
import sys
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory
import platform_exclusive

def _load_agent(bundle_root: Path):
    for cand in [bundle_root, bundle_root.parent]:
        if (cand / "space_guard_agent.py").exists():
            if str(cand) not in sys.path:
                sys.path.insert(0, str(cand))
            import space_guard_agent
            return space_guard_agent
    return None

def start_server(port: int, bundle_root: Path, meta: dict):
    agent = _load_agent(bundle_root)
    web_dir = bundle_root / "web"
    if not (web_dir / "index.html").exists():
        web_dir = bundle_root.parent / "web"
    app = Flask(__name__)

    @app.route("/")
    def index():
        return send_from_directory(web_dir, "index.html")

    @app.route("/assets/<path:f>")
    def assets(f):
        return send_from_directory(bundle_root / "assets", f)

    @app.route("/api/health")
    def health():
        return jsonify({"ok": True, "app": meta["title"], "real_agent": agent is not None})

    @app.route("/api/platform")
    def plat():
        return jsonify(platform_exclusive.get_system_overview())

    @app.route("/api/status")
    def api_status():
        return jsonify({
            "version": agent.APP_VERSION,
            "telemetry": agent.get_disk_telemetry(),
            "config": agent.load_config(),
            "providers": agent.discover_cloud_providers(),
            "ledger": agent.load_ledger()[:30],
            "exclusive": platform_exclusive.scan_storage_exclusive(),
        })

    @app.route("/api/scan")
    def api_scan():
        min_mb = float(request.args.get("min_mb", "25"))
        return jsonify({
            "telemetry": agent.get_disk_telemetry(),
            "caches": agent.scan_system_caches(),
            "candidates": agent.scan_offload_candidates(min_size_mb=min_mb),
        })

    @app.route("/api/config", methods=["POST"])
    def api_config():
        data = request.get_json(force=True, silent=True) or {}
        cfg = agent.load_config()
        if "target_free_gb" in data:
            cfg["target_free_gb"] = max(1.0, float(data["target_free_gb"]))
        if "leave_cloudstub" in data:
            cfg["leave_cloudstub"] = bool(data["leave_cloudstub"])
        if "verify_sha256" in data:
            cfg["verify_sha256"] = bool(data["verify_sha256"])
        agent.save_config(cfg)
        return jsonify({"ok": True, "config": cfg, "telemetry": agent.get_disk_telemetry()})

    @app.route("/api/providers/custom", methods=["POST"])
    def api_add_prov():
        data = request.get_json(force=True, silent=True) or {}
        return jsonify(agent.add_custom_provider(data.get("name",""), data.get("path",""), data.get("tier","custom"), data.get("notes","")))

    @app.route("/api/offload", methods=["POST"])
    def api_offload():
        data = request.get_json(force=True, silent=True) or {}
        res = agent.verify_and_offload_file(
            file_path_str=data.get("path", ""),
            provider_id=data.get("provider", "gdrive"),
            leave_stub=bool(data.get("leave_stub", True)),
            dry_run=bool(data.get("dry_run", False)),
        )
        res["telemetry"] = agent.get_disk_telemetry()
        return jsonify(res), (200 if res.get("ok") else 400)

    @app.route("/api/restore", methods=["POST"])
    def api_restore():
        data = request.get_json(force=True, silent=True) or {}
        res = agent.restore_from_stub(data.get("stub_path", ""))
        res["telemetry"] = agent.get_disk_telemetry()
        return jsonify(res), (200 if res.get("ok") else 400)

    @app.route("/api/clean-cache", methods=["POST"])
    def api_clean():
        data = request.get_json(force=True, silent=True) or {}
        res = agent.clean_safe_cache(data.get("cache_id", ""))
        res["telemetry"] = agent.get_disk_telemetry()
        return jsonify(res), (200 if res.get("ok") else 400)

    @app.route("/api/clean-all-safe", methods=["POST"])
    def api_clean_all():
        caches = agent.scan_system_caches()
        cleaned, total_mb = [], 0.0
        for c in caches:
            if c.get("safe_level") == "safe" and c.get("size_mb", 0) > 0:
                r = agent.clean_safe_cache(c["id"])
                if r.get("ok"):
                    cleaned.append(c["name"])
                    total_mb += r.get("freed_mb", 0.0)
        return jsonify({"ok": True, "cleaned_count": len(cleaned), "cleaned_names": cleaned, "freed_mb": round(total_mb, 2), "telemetry": agent.get_disk_telemetry()})

    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
