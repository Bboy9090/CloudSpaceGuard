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

def create_app(bundle_root: Path, meta: dict):
    agent = _load_agent(bundle_root)
    web_dir = bundle_root / "web"
    if not (web_dir / "index.html").exists():
        web_dir = bundle_root.parent / "web"
    if agent is None:
        raise RuntimeError("Required CloudSpaceGuard agent is unavailable")
    if not (web_dir / "index.html").is_file():
        raise FileNotFoundError("CloudSpaceGuard dashboard missing")
    app = Flask(__name__)

    @app.before_request
    def qualification_boundary():
        # The desktop adapter must not bypass the core agent safety lifecycle.
        # Keep mutations unavailable until guarded integration is qualified.
        if request.method not in ("GET", "HEAD"):
            return jsonify({"ok": False, "error": "Desktop mutation unavailable pending safety qualification"}), 403
        if request.host.split(":", 1)[0] not in ("127.0.0.1", "localhost"):
            return jsonify({"ok": False, "error": "Local host required"}), 403
        origin = request.headers.get("Origin")
        if origin and origin != request.host_url.rstrip("/"):
            return jsonify({"ok": False, "error": "Cross-origin request rejected"}), 403


    @app.route("/")
    def index():
        return send_from_directory(web_dir, "index.html")

    @app.route("/assets/<path:f>")
    def assets(f):
        return send_from_directory(bundle_root / "assets", f)

    @app.route("/api/health")
    def health():
        return jsonify({"ok": True, "app": meta["title"], "real_agent": True, "mutation_enabled": False})

    @app.route("/api/platform")
    def plat():
        return jsonify(platform_exclusive.get_system_overview())

    @app.route("/api/status")
    def api_status():
        return jsonify({
            "ok": True,
            "mutation_enabled": False,
            "version": agent.APP_VERSION,
            "telemetry": agent.get_disk_telemetry(),
            "config": agent.load_config(),
            "providers": agent.discover_cloud_providers(),
            "ledger": agent.load_ledger()[:30],
            "exclusive": platform_exclusive.scan_storage_exclusive(),
        })

    @app.route("/api/caches")
    def api_caches():
        return jsonify({"ok": True, "caches": agent.scan_system_caches()})

    @app.route("/api/ledger")
    def api_ledger():
        return jsonify({"ok": True, "ledger": agent.load_ledger()})

    @app.route("/api/candidates")
    def api_candidates():
        try:
            min_mb = float(request.args.get("min_mb", "25"))
            if not 1 <= min_mb <= 1_000_000:
                raise ValueError("out of range")
        except (ValueError, TypeError):
            return jsonify({"ok": False, "error": "Invalid minimum size"}), 400
        return jsonify({"ok": True, "candidates": agent.scan_offload_candidates(min_size_mb=min_mb)})

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

    return app


def start_server(port: int, bundle_root: Path, meta: dict):
    create_app(bundle_root, meta).run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
