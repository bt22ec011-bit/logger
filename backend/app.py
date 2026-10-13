"""Backend logging API (Flask) for the Universal Application Logger.

Endpoints:
  GET    /api/health      - service health + configuration
  GET    /api/logs        - paginated, filterable log records
  GET    /api/logs/stats  - severity totals and grand total
  GET    /api/logs/<id>   - one record
  POST   /api/logs        - ingest a structured application event
                             (application-level instrumentation)

Run directly (standalone on port 4000):
    python3 backend/app.py --port 4000 --logs-root logs

Or mount into an existing Flask app:
    from backend.app import create_app
    # reuse create_app's blueprint logic or run standalone.
"""

from __future__ import annotations

import argparse
import os
import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from flask_cors import CORS

try:  # when run as `python3 backend/app.py` from the repo root
    from logging_agent import AgentConfig, validate_event, utc_now_iso
    from log_storage import get_storage
except ImportError:  # executed with the repo root not on sys.path
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from logging_agent import AgentConfig, validate_event, utc_now_iso
    from log_storage import get_storage


def _int_arg(name, default, lo=0, hi=10_000):
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, value))


def create_app(config: AgentConfig | None = None, logs_root=None,
               frontend_port=5173, backend_port=4000):
    """Create the Flask app exposing the logger backend API."""
    if config is None:
        config = AgentConfig(frontend_port=frontend_port,
                             backend_port=backend_port,
                             logs_root=logs_root or os.environ.get(
                                 "LOGGER_LOGS_ROOT", "logs"))
    storage = get_storage(config.logs_root)
    started_at = datetime.now(timezone.utc).isoformat()

    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # ------------------------------------------------------------------ #
    @app.get("/api/health")
    def health():
        return jsonify({
            "status": "success",
            "message": "Logger backend is running",
            "data": {
                "service": "logger-backend",
                "started_at": started_at,
                "frontend_port": config.frontend_port,
                "backend_port": config.backend_port,
                "logs_root": str(storage.roots[0]),
                "time": utc_now_iso(),
            },
        })

    # ------------------------------------------------------------------ #
    @app.get("/api/logs")
    def list_logs():
        page = _int_arg("page", 1, 1, 100_000)
        page_size = _int_arg("page_size", 50, 1, 500)
        severity = (request.args.get("severity") or "").upper() or None
        application = request.args.get("application")
        direction = request.args.get("direction")
        method = (request.args.get("method") or "").upper() or None
        search = request.args.get("search") or request.args.get("endpoint")
        start = request.args.get("start_time")
        end = request.args.get("end_time")

        events = storage.read_events()

        def keep(ev):
            if severity and ev.get("severity") != severity:
                return False
            app_name = (ev.get("application") or {}).get("name")
            if application and app_name != application:
                return False
            if direction:
                dirn = (ev.get("network") or {}).get("direction", "")
                if direction.lower() not in dirn.lower():
                    return False
            req = ev.get("request") or {}
            if method and str(req.get("method", "")).upper() != method:
                return False
            if search:
                hay = f"{req.get('route', '')} {ev.get('message', '')}".lower()
                if search.lower() not in hay:
                    return False
            ts = ev.get("timestamp", "")
            if start and ts < start:
                return False
            if end and ts > end:
                return False
            return True

        filtered = [e for e in events if keep(e)]
        total = len(filtered)
        offset = (page - 1) * page_size
        page_items = filtered[offset:offset + page_size]
        return jsonify({
            "status": "success",
            "message": "Logs retrieved successfully",
            "data": {
                "logs": page_items,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                    "pages": (total + page_size - 1) // page_size,
                },
            },
        })

    # ------------------------------------------------------------------ #
    @app.get("/api/logs/stats")
    def log_stats():
        events = storage.read_events()
        counts = {"INFO": 0, "WARNING": 0, "ERROR": 0, "DEBUG": 0}
        for ev in events:
            sev = ev.get("severity", "INFO")
            if sev in counts:
                counts[sev] += 1
        return jsonify({
            "status": "success",
            "message": "Stats retrieved successfully",
            "data": {
                "total": len(events),
                "info": counts["INFO"],
                "warning": counts["WARNING"],
                "error": counts["ERROR"],
                "debug": counts["DEBUG"],
            },
        })

    # ------------------------------------------------------------------ #
    @app.get("/api/logs/<log_id>")
    def one_log(log_id):
        for ev in storage.read_events():
            if ev.get("log_id") == log_id:
                return jsonify({
                    "status": "success",
                    "message": "Log retrieved successfully",
                    "data": ev,
                })
        return jsonify({
            "status": "error",
            "message": f"Log '{log_id}' not found",
        }), 404

    # ------------------------------------------------------------------ #
    @app.post("/api/logs")
    def ingest_log():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"status": "error",
                            "message": "Body must be a JSON object"}), 400
        # Accept both a bare event and the wrapped example schema.
        event = payload.get("data") if isinstance(
            payload.get("data"), dict) else payload
        ok, result = validate_event(event, config)
        if not ok:
            return jsonify({"status": "error",
                            "message": f"Invalid log event: {result}"}), 422
        result.setdefault("log_id", f"log_{uuid.uuid4().hex[:6]}")
        result.setdefault("timestamp", utc_now_iso())
        saved = storage.save_event(result)
        if not saved:
            return jsonify({"status": "error",
                            "message": "Storage failure"}), 500
        return jsonify({
            "status": "success",
            "message": "Log recorded successfully",
            "data": result,
        }), 201

    # ------------------------------------------------------------------ #
    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"status": "error",
                        "message": "Endpoint not found"}), 404

    @app.errorhandler(Exception)
    def on_error(exc):  # never leak internals; API stays up
        app.logger.exception("Unhandled error")
        return jsonify({"status": "error",
                        "message": "Internal server error"}), 500

    app.config["LOGGER_CONFIG"] = config
    return app


def main(argv=None):
    parser = argparse.ArgumentParser(description="Logger backend API")
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("LOGGER_BACKEND_PORT",
                                                   4000)),
                        help="Backend API port (default 4000)")
    parser.add_argument("--frontend-port", type=int, default=5173,
                        help="Configured frontend port for normalization")
    parser.add_argument("--logs-root", default="logs")
    parser.add_argument("--app-name", default="application")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args(argv)

    config = AgentConfig(frontend_port=args.frontend_port,
                         backend_port=args.port,
                         logs_root=args.logs_root,
                         app_name=args.app_name)
    app = create_app(config)
    print(f"Logger backend listening on http://{args.host}:{args.port}")
    print(f"Reading/writing logs under '{args.logs_root}'")
    app.run(host=args.host, port=args.port, debug=args.debug,
            threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
