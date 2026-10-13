"""Universal Application Logger Agent.

Captures or receives application API events and generates structured,
readable JSON log records stored via `log_storage`.

Two capture modes:

1. **proxy** (default, no special privileges required)
   Runs a local HTTP proxy in front of the backend so every frontend API
   call is observed exactly once, with full request/response metadata.

       python3 logging_agent.py --mode proxy --port 5173,4000 \
           --proxy-port 4100 --api-prefix /api

   Point the Vite dev-server proxy target at the agent (see README), e.g.
   '/api' -> 'http://localhost:4100'. The agent forwards to the real
   backend on port 4000 and logs one normalized event per request.

2. **capture** (optional, requires root/libpcap; best-effort)
   Passive packet capture with Scapy. Only plain-HTTP traffic can be
   parsed — HTTPS payloads are NOT visible without decryption or
   application-level instrumentation.

Application-level instrumentation is always preferred: POST complete
structured events to the backend `POST /api/logs` endpoint (or run this
agent's own ingest endpoint) so fields such as user identity, error
location and durations come from verified sources instead of guesses.

Port display contract:
- Configured ports: first = frontend (e.g. 5173), second = backend
  (e.g. 4000).
- Every displayed direction uses ONLY those logical ports:
    Frontend (5173) -> Backend (4000)
    Backend (4000)  -> Frontend (5173)
- Temporary/ephemeral browser source ports are NEVER written into
  user-facing records. Real socket endpoints are kept only under
  `_diagnostics` when explicitly enabled and are never shown in the
  dashboard.
"""

from __future__ import annotations

import argparse
import json
import re
import signal
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from log_storage import get_storage

# --------------------------------------------------------------------- #
# Configuration helpers
# --------------------------------------------------------------------- #

def parse_ports(value: str) -> list[int]:
    """Parse 'FRONTEND,BACKEND' into two validated ints."""
    try:
        ports = [int(p.strip()) for p in value.split(",")]
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Use comma-separated ports, e.g. 5173,4000")
    if len(ports) != 2:
        raise argparse.ArgumentTypeError(
            "Provide exactly two ports: frontend,backend (e.g. 5173,4000)")
    if any(p < 1 or p > 65535 for p in ports):
        raise argparse.ArgumentTypeError("Ports must be between 1 and 65535")
    if ports[0] == ports[1]:
        raise argparse.ArgumentTypeError(
            "Frontend and backend ports must be different")
    return ports


DEFAULT_IGNORE_PREFIXES = (
    "/@vite/", "/@react-refresh", "/src/", "/node_modules/",
    "/.vite/", "/assets/", "/public/", "/favicon.ico",
)

IGNORE_EXTENSIONS = (
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".css", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".html",
)

SEVERITIES = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class AgentConfig:
    def __init__(self, frontend_port, backend_port, interface=None,
                 logs_root="logs", app_name="application",
                 environment="development", version=None,
                 api_prefixes=("/api", "/graphql"),
                 ignore_prefixes=DEFAULT_IGNORE_PREFIXES,
                 log_all_traffic=False, enable_capture=False,
                 proxy_port=None, diagnostics=False):
        self.frontend_port = int(frontend_port)
        self.backend_port = int(backend_port)
        self.interface = interface
        self.logs_root = logs_root
        self.app_name = app_name
        self.environment = environment
        self.version = version
        self.api_prefixes = tuple(api_prefixes)
        self.ignore_prefixes = tuple(ignore_prefixes)
        self.log_all_traffic = log_all_traffic
        self.enable_capture = enable_capture
        self.proxy_port = proxy_port
        self.diagnostics = diagnostics

    @property
    def frontend_label(self):
        return f"Frontend ({self.frontend_port})"

    @property
    def backend_label(self):
        return f"Backend ({self.backend_port})"


# --------------------------------------------------------------------- #
# Filtering
# --------------------------------------------------------------------- #

def should_log_path(path: str, config: AgentConfig) -> bool:
    """True when the request path represents meaningful API traffic."""
    clean = path.split("?", 1)[0]

    for prefix in config.ignore_prefixes:
        if clean.startswith(prefix):
            return False
    base = clean.rsplit("/", 1)[-1]
    if "." in base:
        ext = "." + base.rsplit(".", 1)[-1].lower()
        if ext in IGNORE_EXTENSIONS:
            return False

    if config.log_all_traffic:
        return True

    return any(clean == p or clean.startswith(p.rstrip("/") + "/") or
               clean.startswith(p) for p in config.api_prefixes)


# --------------------------------------------------------------------- #
# Port normalization (core requirement)
# --------------------------------------------------------------------- #

def normalize_network(src_port, dst_port, config: AgentConfig):
    """Map real socket ports onto the configured logical application ports.

    Returns None when neither endpoint belongs to the configured
    frontend/backend pair (unrelated traffic). Never returns ephemeral
    browser ports in the public fields — they stay in `_diagnostics` only
    when diagnostics are explicitly enabled.
    """
    src_port = int(src_port)
    dst_port = int(dst_port)
    fe, be = config.frontend_port, config.backend_port

    if src_port == fe and dst_port == be:
        direction, source, dest = "Frontend -> Backend", "Frontend", "Backend"
    elif src_port == be and dst_port == fe:
        direction, source, dest = "Backend -> Frontend", "Backend", "Frontend"
    elif dst_port == be:                     # client socket -> backend
        direction, source, dest = "Frontend -> Backend", "Frontend", "Backend"
    elif src_port == be:                     # backend -> client socket
        direction, source, dest = "Backend -> Frontend", "Backend", "Frontend"
    elif dst_port == fe:
        direction, source, dest = "Client -> Frontend", "Client", "Frontend"
    elif src_port == fe:
        direction, source, dest = "Frontend -> Client", "Frontend", "Client"
    else:
        return None

    net = {
        "source": source,
        "destination": dest,
        "direction": direction,
    }
    # Logical ports only.
    if source in ("Frontend", "Client"):
        net["source_port"] = fe if source == "Frontend" else None
    else:
        net["source_port"] = be
    if dest in ("Frontend", "Client"):
        net["destination_port"] = fe if dest == "Frontend" else None
    else:
        net["destination_port"] = be
    net = {k: v for k, v in net.items() if v is not None}

    if config.diagnostics:
        # Internal-only record of the real socket pair. Dashboard never
        # reads `_diagnostics`; it exists solely for local troubleshooting.
        net["_diagnostics"] = {"real_src_port": src_port,
                               "real_dst_port": dst_port}
    return net


def severity_for_status(status_code: int) -> str:
    if status_code >= 500:
        return "ERROR"
    if status_code >= 400:
        return "WARNING"
    return "INFO"


def outcome_for_status(status_code: int) -> str:
    if status_code >= 400:
        return "Failed"
    return "Success"


def message_for_status(status_code: int, method: str, route: str) -> str:
    if status_code >= 500:
        return f"API request failed: {method} {route} returned {status_code}"
    if status_code >= 400:
        return f"API request rejected: {method} {route} returned {status_code}"
    return f"API request completed: {method} {route} returned {status_code}"


# --------------------------------------------------------------------- #
# Sensitive data redaction
# --------------------------------------------------------------------- #

SENSITIVE_KEYS = {"authorization", "cookie", "set-cookie", "password",
                  "passwd", "token", "access_token", "refresh_token",
                  "secret", "api_key", "apikey", "x-api-key", "session"}


def _is_sensitive(key: str) -> bool:
    k = key.lower()
    return k in SENSITIVE_KEYS or any(s in k for s in
                                      ("password", "token", "secret", "cookie"))


REDACTED = "[redacted]"


def redact_mapping(mapping):
    """Return a copy of `mapping` with sensitive keys removed."""
    if not isinstance(mapping, dict):
        return {}
    return {k: v for k, v in mapping.items() if not _is_sensitive(k)}


def deep_redact(obj):
    """Recursively drop sensitive keys/values from arbitrary JSON data."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if _is_sensitive(str(k)):
                continue
            out[k] = deep_redact(v)
        return out
    if isinstance(obj, list):
        return [deep_redact(item) for item in obj]
    return obj


# --------------------------------------------------------------------- #
# Event building / validation
# --------------------------------------------------------------------- #

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_http_event(config: AgentConfig, *, method, route, status_code,
                     duration_ms, net, request_id=None, extra=None):
    """Build a normalized structured event from verified HTTP facts."""
    severity = severity_for_status(status_code) if status_code is not None \
        else "INFO"
    event = {
        "log_id": f"log_{uuid.uuid4().hex[:6]}",
        "timestamp": utc_now_iso(),
        "severity": severity,
        "event_type": "HTTP_RESPONSE" if status_code is not None
                      else "HTTP_REQUEST",
        "event": ("API request completed" if status_code and status_code < 400
                  else "API request failed" if status_code
                  else "API request received"),
        "message": (message_for_status(status_code, method, route)
                    if status_code is not None
                    else f"{method} {route} received"),
        "application": {
            "name": config.app_name,
            "environment": config.environment,
        },
        "network": dict(net or {}),
        "request": {
            "request_id": request_id or f"req_{uuid.uuid4().hex[:8]}",
            "method": method,
            "route": route,
        },
        "performance": {
            "duration_ms": round(float(duration_ms), 2),
            "slow_request": bool(duration_ms >= 1000),
        },
    }
    if config.version:
        event["application"]["version"] = config.version
    if status_code is not None:
        event["request"]["status_code"] = int(status_code)
        event["request"]["outcome"] = outcome_for_status(status_code)
    if extra:
        event.update(deep_redact(extra))
    return validate_event(event, config)


def validate_event(event: dict, config: AgentConfig):
    """Validate/sanitize an incoming structured event.

    Drops unknown-shaped data, removes sensitive fields, ensures required
    fields exist and normalizes network ports. Missing optional metadata
    is omitted — never invented. Returns (ok, event_or_error_message).
    """
    if not isinstance(event, dict):
        return False, "event must be a JSON object"

    ev = dict(event)

    ts = ev.get("timestamp")
    try:
        datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        ev["timestamp"] = utc_now_iso()

    sev = str(ev.get("severity", "INFO")).upper()
    if sev not in SEVERITIES:
        sev = "INFO"
    if sev == "CRITICAL":
        sev = "ERROR"
    ev["severity"] = sev

    if not str(ev.get("event", "")).strip():
        return False, "'event' description is required"
    if not str(ev.get("message", "")).strip():
        return False, "'message' is required"

    ev.setdefault("log_id", f"log_{uuid.uuid4().hex[:6]}")

    app = ev.get("application")
    if isinstance(app, dict):
        ev["application"] = {k: v for k, v in app.items()
                             if k in ("name", "environment", "version")
                             and v not in (None, "")}

    # --- Network normalization: strip anything that could leak an
    # ephemeral port and rebuild from configured logical ports. ---
    raw_net = ev.get("network") or {}
    sp = raw_net.get("source_port")
    dp = raw_net.get("destination_port")
    known = {config.frontend_port, config.backend_port}
    if sp not in known or dp not in known:
        # Ports missing or not matching configuration: infer direction
        # from labels, defaulting to Frontend -> Backend.
        direction = str(raw_net.get("direction", "")).lower()
        if "backend -> frontend" in direction or direction.startswith("response"):
            sp, dp = config.backend_port, config.frontend_port
            src, dst = "Backend", "Frontend"
        else:
            sp, dp = config.frontend_port, config.backend_port
            src, dst = "Frontend", "Backend"
        ev["network"] = {
            "source": raw_net.get("source", src),
            "source_port": sp,
            "destination": raw_net.get("destination", dst),
            "destination_port": dp,
            "direction": f"{src} -> {dst}",
        }
    else:
        net = normalize_network(sp, dp, config) or {}
        net.pop("_diagnostics", None)  # ingest input never carries diag
        ev["network"] = net

    req = ev.get("request")
    if isinstance(req, dict):
        clean = {}
        for k in ("request_id", "method", "route", "status_code", "outcome"):
            if req.get(k) not in (None, ""):
                clean[k] = req[k]
        if "headers" in req:
            clean["headers"] = redact_mapping(req["headers"])
        ev["request"] = clean

    ev = deep_redact(ev)

    # Size guard: never store huge bodies.
    body = json.dumps(ev, ensure_ascii=False)
    if len(body) > 64 * 1024:
        return False, "event too large (>64KB); omit payload bodies"

    return True, ev


# --------------------------------------------------------------------- #
# Console printing (never shows ephemeral ports)
# --------------------------------------------------------------------- #

def print_event(event: dict, config: AgentConfig):
    net = event.get("network", {})
    sp, dp = net.get("source_port"), net.get("destination_port")
    parts = []
    if sp == config.frontend_port:
        parts.append(f"Frontend ({config.frontend_port})")
    elif sp == config.backend_port:
        parts.append(f"Backend ({config.backend_port})")
    if dp == config.backend_port:
        parts.append(f"Backend ({config.backend_port})")
    elif dp == config.frontend_port:
        parts.append(f"Frontend ({config.frontend_port})")
    arrow = " → ".join(parts) if parts else "external traffic"

    req = event.get("request", {})
    line = (f"[{event['timestamp']}] [{event['severity']}] "
            f"{arrow} | {req.get('method', '-')} {req.get('route', '-')}"
            f" | {req.get('status_code', '-')}")
    print(line)
    print(json.dumps(event, indent=2, ensure_ascii=False))
    print("-" * 70)


# --------------------------------------------------------------------- #
# Proxy mode: observes each frontend->backend API call exactly once
# --------------------------------------------------------------------- #

class ProxyHandler(BaseHTTPRequestHandler):
    config: AgentConfig = None  # injected by make_server
    protocol_version = "HTTP/1.1"

    def _handle(self):
        cfg = self.config
        path = self.path
        if not should_log_path(path, cfg):
            self._forward_without_logging()
            return

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""

        conn = HTTPConnection("127.0.0.1", cfg.backend_port, timeout=10)
        start = time.monotonic()
        request_id = self.headers.get("X-Request-Id") or \
            f"req_{uuid.uuid4().hex[:8]}"
        try:
            headers = dict(self.headers)
            headers.pop("Host", None)
            headers["Host"] = f"localhost:{cfg.backend_port}"
            headers["X-Request-Id"] = request_id
            conn.request(self.command, path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            status = resp.status
        except OSError as exc:
            duration = (time.monotonic() - start) * 1000
            self._record(cfg, status=502, duration=duration,
                         request_id=request_id,
                         error={"type": type(exc).__name__,
                                "description": "Backend request failed "
                                               "(backend may be down)."})
            self.send_error(502, "Bad gateway (logger proxy)")
            return
        finally:
            duration = (time.monotonic() - start) * 1000
            conn.close()

        # Forward response to the browser unchanged.
        self.send_response(status)
        for key, value in resp.getheaders():
            if key.lower() in ("transfer-encoding", "connection"):
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

        self._record(cfg, status=status, duration=duration,
                     request_id=request_id)

    def _record(self, cfg, status, duration, request_id, error=None):
        # Displayed ports are ALWAYS the configured logical ports.
        # The real TCP client port (ephemeral) is deliberately discarded.
        net = normalize_network(self.client_address[1], cfg.backend_port, cfg)
        extra = {}
        if error:
            extra["error"] = error
        ok, result = build_http_event(
            cfg, method=self.command, route=self.path.split("?")[0],
            status_code=status, duration_ms=duration, net=net,
            request_id=request_id, extra=extra)
        if ok:
            get_storage(cfg.logs_root).save_event(result)
            print_event(result, cfg)
        else:
            print(f"[logging_agent] dropped invalid event: {result}",
                  file=sys.stderr)

    def _forward_without_logging(self):
        """Pass-through for non-API traffic (Vite assets etc.)."""
        cfg = self.config
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            conn = HTTPConnection("127.0.0.1", cfg.frontend_port, timeout=10)
            headers = dict(self.headers)
            headers["Host"] = f"localhost:{cfg.frontend_port}"
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            self.send_response(resp.status)
            for key, value in resp.getheaders():
                if key.lower() in ("transfer-encoding", "connection"):
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            conn.close()
        except OSError:
            self.send_error(502, "Bad gateway (logger proxy)")

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _handle

    def log_message(self, fmt, *args):  # silence default stderr noise
        pass


# --------------------------------------------------------------------- #
# Capture mode (optional, scapy-based, best effort)
# --------------------------------------------------------------------- #

HTTP_METHOD_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/")


def _capture_worker(cfg: AgentConfig, stop: threading.Event):
    try:
        from scapy.all import sniff, TCP, Raw  # lazy import
    except ImportError:
        print("[logging_agent] scapy not installed; capture mode disabled. "
              "pip install scapy (and run with root privileges).",
              file=sys.stderr)
        return
    bpf = (f"tcp port {cfg.frontend_port} or tcp port {cfg.backend_port}")
    kwargs = {"filter": bpf, "prn": lambda p: _process_packet(p, cfg),
              "store": False}
    if cfg.interface:
        kwargs["iface"] = cfg.interface
    while not stop.is_set():
        try:
            sniff(stop_filter=lambda _: stop.wait(0.5), count=0, **kwargs)
            break
        except PermissionError:
            print("[logging_agent] capture needs root privileges.",
                  file=sys.stderr)
            return
        except Exception as exc:  # keep logger alive
            print(f"[logging_agent] capture error (retrying): {exc}",
                  file=sys.stderr)
            stop.wait(3)


def _process_packet(packet, cfg: AgentConfig):
    try:
        from scapy.all import TCP, Raw
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return
        payload = bytes(packet[Raw].load)
        if not payload:
            return
        tcp = packet[TCP]
        net = normalize_network(tcp.sport, tcp.dport, cfg)
        if not net:
            return
        text = payload.decode("utf-8", errors="replace")
        m = HTTP_METHOD_RE.match(text)
        if m:
            route = m.group(2).split("?")[0]
            if not should_log_path(route, cfg):
                return
            event = build_http_event(cfg, method=m.group(1), route=route,
                                     status_code=None, duration_ms=0.0,
                                     net=net)
        elif text.startswith("HTTP/"):
            parts = text.split(" ", 2)
            status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() \
                else 0
            event = build_http_event(cfg, method="-",
                                     route="(response)",
                                     status_code=status, duration_ms=0.0,
                                     net=net)
            event["event"] = "API response observed (passive capture)"
            event["message"] += " (captured passively; pairing approximate)"
        else:
            return  # fragments/binary: never store raw payloads
        ok, result = validate_event(event, cfg)
        if ok:
            get_storage(cfg.logs_root).save_event(result)
            print_event(result, cfg)
    except Exception as exc:  # never crash the logger
        print(f"[logging_agent] packet handler error: {exc}",
              file=sys.stderr)


# --------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------- #

def make_server(cfg: AgentConfig) -> ThreadingHTTPServer:
    handler = type("BoundProxyHandler", (ProxyHandler,), {"config": cfg})
    return ThreadingHTTPServer(("127.0.0.1", cfg.proxy_port), handler)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Universal Application Logger Agent")
    parser.add_argument("--interface", "-i", default=None,
                        help="Capture interface (capture mode), e.g. lo0")
    parser.add_argument("--port", "-p", type=parse_ports, required=True,
                        metavar="FRONTEND,BACKEND",
                        help="Configured ports: frontend,backend "
                             "(e.g. 5173,4000)")
    parser.add_argument("--mode", choices=("proxy", "capture"),
                        default="proxy",
                        help="proxy (default): local logging proxy; "
                             "capture: passive scapy capture (needs root)")
    parser.add_argument("--proxy-port", type=int, default=None,
                        help="Port for the logging proxy (default: backend "
                             "port + 100)")
    parser.add_argument("--logs-root", default="logs")
    parser.add_argument("--app-name", default="application")
    parser.add_argument("--environment", default="development")
    parser.add_argument("--version", default=None,
                        help="Application version (only if known)")
    parser.add_argument("--api-prefix", action="append", default=None,
                        metavar="PREFIX",
                        help="API route prefix to log (repeatable). "
                             "Default: /api /graphql")
    parser.add_argument("--log-all-traffic", action="store_true",
                        help="Log all HTTP traffic (not just API prefixes)")
    parser.add_argument("--retention-days", type=int, default=None)
    parser.add_argument("--diagnostics", action="store_true",
                        help="Store real socket ports under _diagnostics "
                             "(internal only, never shown in dashboard)")
    args = parser.parse_args(argv)

    frontend_port, backend_port = args.port
    cfg = AgentConfig(
        frontend_port=frontend_port,
        backend_port=backend_port,
        interface=args.interface,
        logs_root=args.logs_root,
        app_name=args.app_name,
        environment=args.environment,
        version=args.version,
        api_prefixes=tuple(args.api_prefix or ("/api", "/graphql")),
        log_all_traffic=args.log_all_traffic,
        enable_capture=args.mode == "capture",
        proxy_port=args.proxy_port or (backend_port + 100),
        diagnostics=args.diagnostics,
    )
    if cfg.proxy_port in (frontend_port, backend_port):
        parser.error("--proxy-port must differ from the configured ports")

    storage = get_storage(cfg.logs_root, retention_days=args.retention_days)

    print("=" * 62)
    print("Universal Application Logger Agent")
    print(f"  Frontend port : {frontend_port}  ({cfg.frontend_label})")
    print(f"  Backend  port : {backend_port}  ({cfg.backend_label})")
    print(f"  Mode          : {args.mode}")
    print(f"  Logs root     : {cfg.logs_root}")
    print(f"  API prefixes  : {', '.join(cfg.api_prefixes)}")
    if args.mode == "proxy":
        print(f"  Proxy listens : 127.0.0.1:{cfg.proxy_port}")
        print(f"  Set your Vite proxy target to "
              f"http://localhost:{cfg.proxy_port}")
    else:
        print(f"  Interface     : {cfg.interface or '(default)'}")
        print("  NOTE: passive capture cannot see inside HTTPS traffic.")
    print("  Ephemeral browser ports are never displayed; directions use")
    print("  only the configured logical ports.")
    print("  Press Ctrl+C to stop gracefully.")
    print("=" * 62)

    stop = threading.Event()
    threads = []

    if args.mode == "proxy":
        server = make_server(cfg)
        srv_thread = threading.Thread(target=server.serve_forever,
                                      name="proxy", daemon=True)
        srv_thread.start()
        threads.append(srv_thread)
    if args.mode == "capture":
        t = threading.Thread(target=_capture_worker, args=(cfg, stop),
                             name="capture", daemon=True)
        t.start()
        threads.append(t)

    def shutdown(signum, frame):
        print("\nStopping Logger Agent gracefully...")
        stop.set()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while not stop.wait(0.5):
            pass
    except KeyboardInterrupt:
        stop.set()

    if args.mode == "proxy":
        server.shutdown()
        server.server_close()
    for t in threads:
        t.join(timeout=3)
    if args.retention_days:
        removed = storage.apply_retention()
        if removed:
            print(f"Retention removed {len(removed)} old day folder(s).")
    print("Logger stopped.")


if __name__ == "__main__":
    main()
