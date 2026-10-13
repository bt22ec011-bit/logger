"""Tests for port normalization, direction labels and ephemeral-port safety."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

from logging_agent import (AgentConfig, normalize_network, parse_ports,
                           validate_event)


@pytest.fixture
def config():
    return AgentConfig(frontend_port=5173, backend_port=4000)


class TestParsePorts:
    def test_valid_pair(self):
        assert parse_ports("5173,4000") == [5173, 4000]

    def test_whitespace(self):
        assert parse_ports(" 5173 , 4000 ") == [5173, 4000]

    @pytest.mark.parametrize("bad", ["5173", "5173,4000,8080", "abc,def",
                                     "0,4000", "70000,4000", "5173,5173"])
    def test_invalid(self, bad):
        import argparse
        with pytest.raises(argparse.ArgumentTypeError):
            parse_ports(bad)


class TestNormalizeNetwork:
    def test_frontend_to_backend_exact(self, config):
        net = normalize_network(5173, 4000, config)
        assert net["direction"] == "Frontend -> Backend"
        assert net["source"] == "Frontend"
        assert net["source_port"] == 5173
        assert net["destination"] == "Backend"
        assert net["destination_port"] == 4000

    def test_backend_to_frontend_exact(self, config):
        net = normalize_network(4000, 5173, config)
        assert net["direction"] == "Backend -> Frontend"
        assert net["source_port"] == 4000
        assert net["destination_port"] == 5173

    def test_ephemeral_client_to_backend_is_normalized(self, config):
        """A browser's temporary source port (e.g. 52841) must never be
        exposed; the logical frontend/backend ports are shown instead."""
        net = normalize_network(52841, 4000, config)
        assert net["source_port"] == 5173
        assert net["destination_port"] == 4000
        assert net["direction"] == "Frontend -> Backend"
        assert 52841 not in (net["source_port"], net["destination_port"])

    def test_backend_to_ephemeral_client(self, config):
        net = normalize_network(4000, 60122, config)
        assert net["source_port"] == 4000
        assert net["destination_port"] == 5173
        assert net["direction"] == "Backend -> Frontend"

    def test_unrelated_traffic_dropped(self, config):
        assert normalize_network(8080, 9000, config) is None

    def test_diagnostics_hidden_by_default(self, config):
        net = normalize_network(52841, 4000, config)
        assert "_diagnostics" not in net

    def test_diagnostics_opt_in(self):
        cfg = AgentConfig(frontend_port=5173, backend_port=4000,
                          diagnostics=True)
        net = normalize_network(52841, 4000, cfg)
        assert net["_diagnostics"]["real_src_port"] == 52841
        # Public fields still show logical ports only.
        assert net["source_port"] == 5173


class TestValidateEventNormalization:
    def test_injected_ephemeral_port_is_stripped(self, config):
        event = {
            "event": "API request completed",
            "message": "GET /api/todos returned 200",
            "severity": "INFO",
            "network": {"source": "Frontend", "source_port": 49382,
                        "destination": "Backend", "destination_port": 4000,
                        "direction": "Frontend -> Backend"},
        }
        ok, ev = validate_event(event, config)
        assert ok
        # 49382 is not a configured port -> rebuilt from configuration.
        assert ev["network"]["source_port"] == 5173
        assert ev["network"]["destination_port"] == 4000

    def test_missing_network_gets_logical_defaults(self, config):
        event = {"event": "Something happened", "message": "detail"}
        ok, ev = validate_event(event, config)
        assert ok
        assert ev["network"]["source_port"] == 5173
        assert ev["network"]["destination_port"] == 4000

    def test_severity_validation(self, config):
        ok, ev = validate_event({"event": "x", "message": "y",
                                 "severity": "BOGUS"}, config)
        assert ok and ev["severity"] == "INFO"
        ok, ev = validate_event({"event": "x", "message": "y",
                                 "severity": "error"}, config)
        assert ev["severity"] == "ERROR"

    def test_required_fields(self, config):
        ok, msg = validate_event({"message": "no event field"}, config)
        assert not ok
        ok, msg = validate_event({"event": "no message"}, config)
        assert not ok
        ok, msg = validate_event("not-a-dict", config)
        assert not ok
