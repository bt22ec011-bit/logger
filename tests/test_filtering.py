"""Tests for API-route filtering rules."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from logging_agent import AgentConfig, should_log_path


@pytest.fixture
def config():
    return AgentConfig(frontend_port=5173, backend_port=4000)


@pytest.mark.parametrize("path", [
    "/api/auth/login",
    "/api/todos",
    "/api/users/42",
    "/api/matches",
    "/graphql",
    "/api",
])
def test_api_routes_are_logged(config, path):
    assert should_log_path(path, config) is True


@pytest.mark.parametrize("path", [
    "/@vite/client",
    "/@react-refresh",
    "/src/main.jsx",
    "/node_modules/vite/dist/client/env.mjs",
    "/assets/index-a1b2c3.js",
    "/styles/app.css",
    "/images/logo.png",
    "/fonts/roboto.woff2",
    "/favicon.ico",
    "/index.html",
    "/vendor.js.map",
    "/random/page",           # non-API traffic
    "http://example.com/x",   # unrelated absolute target
])
def test_dev_assets_and_non_api_are_ignored(config, path):
    assert should_log_path(path, config) is False


def test_query_strings_stripped(config):
    assert should_log_path("/api/todos?done=false", config) is True
    assert should_log_path("/main.jsx?t=123", config) is False


def test_custom_prefix_allowlist():
    cfg = AgentConfig(frontend_port=5173, backend_port=4000,
                      api_prefixes=("/rest", "/query"))
    assert should_log_path("/rest/items", cfg) is True
    assert should_log_path("/query/ping", cfg) is True
    assert should_log_path("/api/todos", cfg) is False  # no longer allowed


def test_log_all_traffic_override():
    cfg = AgentConfig(frontend_port=5173, backend_port=4000,
                      log_all_traffic=True)
    assert should_log_path("/some/page", cfg) is True
    # Explicit ignore rules still win over log-all.
    assert should_log_path("/@vite/client", cfg) is False
