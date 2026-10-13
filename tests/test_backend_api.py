"""End-to-end tests: backend API integration + logging agent proxy mode.

Covers:
- POST /api/logs ingest (validation, redaction, normalization)
- GET /api/logs with filters + pagination
- GET /api/logs/stats
- GET /api/logs/:id
- GET /api/health
- The proxy mode of logging_agent end-to-end: browser(ephemeral port)
  -> agent -> backend, exactly one log event per request, and the stored
  record only ever shows the configured logical ports.
"""
import json
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import log_storage
from logging_agent import AgentConfig, make_server
from backend.app import create_app


@pytest.fixture()
def app(tmp_path, monkeypatch):
    """Flask test client with an isolated logs root."""
    monkeypatch.setattr(log_storage, "_default_storage", None)
    config = AgentConfig(frontend_port=5173, backend_port=4000,
                         logs_root=str(tmp_path / "logs"),
                         app_name="SkillAlign")
    flask_app = create_app(config)
    flask_app.config.update(TESTING=True)
    return flask_app.test_client()


VALID_EVENT = {
    "severity": "ERROR",
    "event": "API request failed",
    "message": "The matching request failed because of a division-by-zero "
               "error.",
    "application": {"name": "SkillAlign", "environment": "development",
                    "version": "1.2.0"},
    "network": {"source": "Frontend", "source_port": 5173,
                "destination": "Backend", "destination_port": 4000,
                "direction": "Frontend -> Backend"},
    "request": {"request_id": "req_8a21", "method": "POST",
                "route": "/api/matches", "status_code": 500,
                "outcome": "Failed"},
    "performance": {"duration_ms": 250.42, "slow_request": False},
    "user": {"user_id": "user_123", "role": "Recruiter"},
    "error": {"type": "ZeroDivisionError",
              "description": "A calculation attempted to divide by zero.",
              "location": "matching_service.py:85"},
    "context": {"job_id": "job_456", "candidate_id": "candidate_789"},
}


class TestIngestAndQuery:
    def test_health(self, app):
        res = app.get("/api/health")
        assert res.status_code == 200
        body = res.get_json()
        assert body["status"] == "success"
        assert body["data"]["frontend_port"] == 5173
        assert body["data"]["backend_port"] == 4000

    def test_post_and_get_log(self, app):
        res = app.post("/api/logs", json={"data": VALID_EVENT})
        assert res.status_code == 201
        body = res.get_json()
        assert body["status"] == "success"
        log_id = body["data"]["log_id"]

        res = app.get(f"/api/logs/{log_id}")
        assert res.status_code == 200
        record = res.get_json()["data"]
        assert record["request"]["route"] == "/api/matches"
        assert record["error"]["type"] == "ZeroDivisionError"
        # Logical ports preserved.
        assert record["network"]["source_port"] == 5173
        assert record["network"]["destination_port"] == 4000

    def test_post_rejects_invalid(self, app):
        assert app.post("/api/logs", json={"message": "missing event"}
                        ).status_code == 422
        assert app.post("/api/logs", data="not json",
                        content_type="text/plain").status_code == 400

    def test_post_redacts_secrets(self, app):
        ev = dict(VALID_EVENT)
        ev["request"] = {**ev["request"],
                        "headers": {"Authorization": "Bearer abc123"}}
        ev["password"] = "hunter2"
        res = app.post("/api/logs", json=ev)
        blob = json.dumps(res.get_json())
        assert "abc123" not in blob
        assert "hunter2" not in blob

    def test_stats_and_filters(self, app):
        app.post("/api/logs", json=VALID_EVENT)
        ok_event = {**VALID_EVENT, "severity": "INFO",
                    "request": {"method": "GET", "route": "/api/todos",
                                "status_code": 200, "outcome": "Success"}}
        app.post("/api/logs", json=ok_event)

        stats = app.get("/api/logs/stats").get_json()["data"]
        assert stats["total"] == 2
        assert stats["error"] == 1
        assert stats["info"] == 1

        filtered = app.get("/api/logs?severity=ERROR").get_json()["data"]
        assert filtered["pagination"]["total"] == 1
        assert filtered["logs"][0]["severity"] == "ERROR"

        by_method = app.get("/api/logs?method=GET").get_json()["data"]
        assert by_method["pagination"]["total"] == 1

        by_search = app.get("/api/logs?search=matches").get_json()["data"]
        assert by_search["pagination"]["total"] == 1

        by_dir = app.get("/api/logs?direction=Backend -> Frontend"
                         ).get_json()["data"]
        assert by_dir["pagination"]["total"] == 0

    def test_pagination(self, app):
        for i in range(5):
            app.post("/api/logs", json={**VALID_EVENT,
                                         "message": f"event {i}"})
        page1 = app.get("/api/logs?page=1&page_size=2").get_json()["data"]
        assert len(page1["logs"]) == 2
        assert page1["pagination"]["total"] == 5
        assert page1["pagination"]["pages"] == 3

    def test_missing_log_404(self, app):
        assert app.get("/api/logs/log_nope").status_code == 404


# --------------------------------------------------------------------- #
# Proxy-mode end-to-end
# --------------------------------------------------------------------- #

class FakeBackend(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/api/matches":
            body = b'{"detail":"boom"}'
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_GET(self):
        if self.path.startswith("/@vite"):  # dev asset passthrough
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(200)
            body = b'{"todos":[]}'
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a):
        pass


class TestProxyEndToEnd:
    @pytest.fixture()
    def stack(self, tmp_path, monkeypatch):
        monkeypatch.setattr(log_storage, "_default_storage", None)
        backend = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackend)
        backend_port = backend.server_address[1]
        threading.Thread(target=backend.serve_forever, daemon=True).start()

        config = AgentConfig(frontend_port=5173, backend_port=backend_port,
                             logs_root=str(tmp_path / "logs"),
                             app_name="SkillAlign", proxy_port=0)
        # Bind proxy on an ephemeral port for the test but keep the
        # *displayed* frontend/backend ports fixed at 5173/backend_port.
        server = make_server(config)
        server.server_close()
        from http.server import ThreadingHTTPServer as T
        proxy = T(("127.0.0.1", 0), type("H", (server.RequestHandlerClass,),
                                        {"config": config}))
        proxy_port = proxy.server_address[1]
        threading.Thread(target=proxy.serve_forever, daemon=True).start()

        yield proxy_port, backend_port, config, tmp_path

        proxy.shutdown(); proxy.server_close()
        backend.shutdown(); backend.server_close()
        monkeypatch.setattr(log_storage, "_default_storage", None)

    def _post(self, port, path, payload):
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as err:  # 4xx/5xx are passed through
            return err.code, err.read()

    def test_api_call_logged_once_with_logical_ports(self, stack):
        proxy_port, backend_port, config, tmp_path = stack
        status, _ = self._post(proxy_port, "/api/matches", {"job": "x"})
        assert status == 500  # response passed through unchanged

        events = log_storage.LogStorage(
            root=tmp_path / "logs").read_events()
        api_events = [e for e in events
                      if e["request"].get("route") == "/api/matches"]
        assert len(api_events) == 1  # no duplicates
        ev = api_events[0]
        assert ev["severity"] == "ERROR"
        assert ev["network"]["source_port"] == 5173
        assert ev["network"]["destination_port"] == backend_port
        assert ev["network"]["direction"] == "Frontend -> Backend"
        assert ev["performance"]["duration_ms"] >= 0
        # The actual ephemeral client port used by urllib is NOT recorded.
        blob = json.dumps(ev)
        assert "_diagnostics" not in blob

    def test_dev_assets_not_logged(self, stack):
        proxy_port, _, _, tmp_path = stack
        req = urllib.request.Request(f"http://127.0.0.1:{proxy_port}/@vite/client")
        # Non-API paths are forwarded to the *frontend* port in real use;
        # here the fake backend serves them so we can assert filtering.
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass
        storage = log_storage.LogStorage(root=tmp_path / "logs")
        events = storage.read_events()
        assert all("@vite" not in json.dumps(e) for e in events)
