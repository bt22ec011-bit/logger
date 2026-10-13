"""Tests for structured JSON formatting and storage behaviour."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from logging_agent import AgentConfig, build_http_event, validate_event
from log_storage import LogStorage, sanitize_file_part


@pytest.fixture
def config():
    return AgentConfig(frontend_port=5173, backend_port=4000,
                       app_name="SkillAlign", version="1.2.0")


@pytest.fixture
def event(config):
    net = {"source": "Frontend", "source_port": 5173,
           "destination": "Backend", "destination_port": 4000,
           "direction": "Frontend -> Backend"}
    ok, ev = build_http_event(config, method="POST", route="/api/matches",
                              status_code=500, duration_ms=250.42, net=net)
    assert ok
    return ev


class TestJsonFormatting:
    def test_readable_indented_output(self, event):
        text = json.dumps(event, indent=2, ensure_ascii=False)
        assert "\n" in text
        assert '"severity": "ERROR"' in text
        assert '"route": "/api/matches"' in text

    def test_severity_mapping(self, config):
        net = {"source_port": 5173, "destination_port": 4000}
        for code, sev in ((200, "INFO"), (404, "WARNING"), (500, "ERROR")):
            ok, ev = build_http_event(config, method="GET", route="/api/x",
                                      status_code=code, duration_ms=1, net=net)
            assert ev["severity"] == sev
            assert ev["request"]["outcome"] == (
                "Failed" if code >= 400 else "Success")

    def test_no_ephemeral_ports_in_serialized_record(self, event):
        blob = json.dumps(event)
        for banned in ("52841", "60122", "49382"):
            assert banned not in blob
        assert event["network"]["source_port"] == 5173
        assert event["network"]["destination_port"] == 4000

    def test_missing_fields_omitted_not_fabricated(self, event):
        # No application instrumentation supplied user/error/context:
        assert "user" not in event
        assert "error" not in event
        assert "context" not in event

    def test_redaction_of_sensitive_keys(self, config):
        raw = {
            "event": "login attempt",
            "message": "POST /api/auth returned 401",
            "severity": "WARNING",
            "request": {"method": "POST", "route": "/api/auth",
                        "headers": {"Authorization": "Bearer secret",
                                    "Cookie": "session=abc",
                                    "Content-Type": "application/json"},
                        "password": "hunter2"},
            "user": {"token": "jwt...", "name": "Recruiter"},
        }
        ok, ev = validate_event(raw, config)
        assert ok
        blob = json.dumps(ev)
        assert "Bearer secret" not in blob
        assert "hunter2" not in blob
        assert "jwt..." not in blob
        assert "session=abc" not in blob
        assert "Content-Type" in blob  # benign header kept


class TestStorage:
    def test_directory_structure_and_files(self, tmp_path, event):
        storage = LogStorage(root=tmp_path / "logs")
        written = storage.save_event(event)
        year = f"{event['timestamp'][:4]}"
        month = event["timestamp"][5:7]
        day = event["timestamp"][8:10]
        day_dir = tmp_path / "logs" / year / month / day
        assert (day_dir / "combined.log").exists()
        assert (day_dir / "ERROR.log").exists()
        assert (day_dir / "HTTP_RESPONSE.log").exists()
        assert all(str(day_dir) in p for p in written)

    def test_all_months_created(self, tmp_path, event):
        storage = LogStorage(root=tmp_path / "logs")
        storage.save_event(event)
        year_dir = tmp_path / "logs" / event["timestamp"][:4]
        months = sorted(p.name for p in year_dir.iterdir() if p.is_dir())
        assert months == [f"{m:02d}" for m in range(1, 13)]

    def test_json_lines_format(self, tmp_path, event):
        storage = LogStorage(root=tmp_path / "logs")
        first = {**event, "log_id": "log_first"}
        second = {**first, "log_id": "log_second", "severity": "INFO"}
        storage.save_event(first)
        storage.save_event(second)
        combined = next((tmp_path / "logs").glob("*/*/*/combined.log"))
        lines = combined.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2  # one complete JSON object per line
        parsed = [json.loads(line) for line in lines]
        assert {p["log_id"] for p in parsed} == {"log_first", "log_second"}

    def test_malformed_events_rejected_safely(self, tmp_path, event):
        storage = LogStorage(root=tmp_path / "logs")
        class Bad:  # not JSON serializable
            pass
        assert storage.save_event({"bad": Bad()}) == []
        assert storage.save_event("not a dict") == []
        # valid event still works afterwards (no crash state)
        assert storage.save_event(event)

    def test_corrupt_lines_skipped_on_read(self, tmp_path, event):
        storage = LogStorage(root=tmp_path / "logs")
        storage.save_event(event)
        combined = next((tmp_path / "logs").glob("*/*/*/combined.log"))
        combined.write_text('{"broken json\n' + combined.read_text(),
                            encoding="utf-8")
        events = storage.read_events()
        assert len(events) == 1  # corrupt line skipped safely

    def test_multiple_destinations(self, tmp_path, event):
        storage = LogStorage(root=tmp_path / "a",
                             destinations=[tmp_path / "b"])
        storage.save_event(event)
        assert list((tmp_path / "a").glob("*/*/*/combined.log"))
        assert list((tmp_path / "b").glob("*/*/*/combined.log"))

    def test_retention(self, tmp_path, event):
        storage = LogStorage(root=tmp_path / "logs", retention_days=1)
        old = {**event, "timestamp": "2020-01-01T10:00:00.000Z"}
        storage.save_event(old)
        storage.save_event(event)
        removed = storage.apply_retention()
        assert removed
        assert not list((tmp_path / "logs").glob("2020/*/*"))
        assert list((tmp_path / "logs").glob("*/*/*/combined.log"))

    def test_sanitize_file_part(self):
        assert sanitize_file_part("HTTP_REQUEST") == "HTTP_REQUEST"
        assert sanitize_file_part("../../evil") == "evil"
        assert sanitize_file_part("", default="UNKNOWN") == "UNKNOWN"
