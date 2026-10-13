import argparse
import base64
import json
import signal
import sys
from datetime import datetime
from scapy.all import sniff, TCP, Raw, IP, IPv6, get_if_list
from log_storage import save_log

def parse_ports(value):
    try:
        ports = [int(p.strip()) for p in value.split(",")]
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Use comma-separated ports, e.g. 5173,4000"
        )

    if len(ports) != 2:
        raise argparse.ArgumentTypeError(
            "Provide frontend,backend ports, e.g. 5173,4000"
        )

    if any(p < 1 or p > 65535 for p in ports):
        raise argparse.ArgumentTypeError(
            "Ports must be between 1 and 65535"
        )

    if ports[0] == ports[1]:
        raise argparse.ArgumentTypeError(
            "Frontend and backend ports must be different"
        )

    return ports

def get_ips(packet):
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst

    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst

    return "unknown", "unknown"

def get_direction(src_port, dst_port, frontend, backend):
    if src_port == frontend and dst_port == backend:
        return f"Frontend ({frontend}) -> Backend ({backend})"

    if src_port == backend and dst_port == frontend:
        return f"Backend ({backend}) -> Frontend ({frontend})"

    if dst_port == frontend:
        return f"Client -> Frontend ({frontend})"

    if src_port == frontend:
        return f"Frontend ({frontend}) -> Client"

    if dst_port == backend:
        return f"Client -> Backend ({backend})"

    if src_port == backend:
        return f"Backend ({backend}) -> Client"

    return "Other traffic"

HTTP_METHODS = {
    "GET", "POST", "PUT", "PATCH", "DELETE",
    "HEAD", "OPTIONS", "CONNECT", "TRACE"
}

def summarize_body(body):
    """Format a JSON body so it is readable in console and logs."""
    body = body.strip()

    if not body:
        return "No readable body in this packet."

    try:
        parsed = json.loads(body)
        return json.dumps(
            parsed,
            indent=2,
            ensure_ascii=False
        )
    except (json.JSONDecodeError, ValueError):
        # Do not display arbitrary binary content as readable text.
        if not body.isprintable() and "\n" not in body and "\r" not in body:
            return "[Non-text or binary payload]"

        preview = body
        if len(preview) > 2000:
            preview = preview[:2000] + "\n... [truncated]"
        return preview

def analyze_payload(payload):
    """Identify HTTP request/response lines and format available body."""
    text = payload.decode("utf-8", errors="replace")
    header_text, separator, body = text.partition("\r\n\r\n")
    lines = header_text.split("\r\n")
    first_line = lines[0].strip() if lines else ""

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    result = {
        "type": "TCP_DATA",
        "summary": "TCP payload",
        "details": [],
        "readable_payload": summarize_body(text),
    }

    parts = first_line.split()

    if len(parts) >= 3 and parts[0] in HTTP_METHODS:
        method, path = parts[0], parts[1]
        result["type"] = "HTTP_REQUEST"
        result["summary"] = f"{method} {path}"
        result["details"] = [
            f"Method: {method}",
            f"Endpoint: {path}",
        ]

        if "host" in headers:
            result["details"].append(f"Host: {headers['host']}")

        if "content-type" in headers:
            result["details"].append(
                f"Content-Type: {headers['content-type']}"
            )

        if separator and body.strip():
            result["readable_payload"] = summarize_body(body)
        else:
            result["readable_payload"] = (
                "No request body in this packet."
            )

    elif first_line.startswith("HTTP/"):
        result["type"] = "HTTP_RESPONSE"
        result["summary"] = f"HTTP response: {first_line}"

        if "content-type" in headers:
            result["details"].append(
                f"Content-Type: {headers['content-type']}"
            )

        if separator and body.strip():
            result["readable_payload"] = summarize_body(body)
        else:
            result["readable_payload"] = (
                "No response body in this packet."
            )

    else:
        # Some packets may contain only a fragment of a message.
        result["details"].append(
            "This packet may contain part of an HTTP message."
        )

    return result

def process_packet(
    packet,
    frontend_port,
    backend_port,
    label,
    logs_root,
):
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return

    tcp = packet[TCP]
    src_port = int(tcp.sport)
    dst_port = int(tcp.dport)

    if (
        src_port not in (frontend_port, backend_port)
        and dst_port not in (frontend_port, backend_port)
    ):
        return

    payload = bytes(packet[Raw].load)
    if not payload:
        return

    src_ip, dst_ip = get_ips(packet)
    readable = analyze_payload(payload)

    timestamp = datetime.now().astimezone().isoformat(
        timespec="milliseconds"
    )

    direction = get_direction(
        src_port,
        dst_port,
        frontend_port,
        backend_port,
    )

    event = {
        "timestamp": timestamp,
        "label": label,
        "type": readable["type"],
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "direction": direction,
        "summary": readable["summary"],
        "details": readable["details"],
        "data": readable["readable_payload"],
        "size": len(payload),
    }

    print(f"\n[{timestamp}] [LABEL: {label}]")
    print(f"Type: {event['type']}")
    print(f"Event: {event['summary']}")
    print(f"Direction: {direction}")
    print(f"Source: {src_ip}:{src_port}")
    print(f"Destination: {dst_ip}:{dst_port}")
    print(f"Payload size: {len(payload)} bytes")

    for detail in readable["details"]:
        print(detail)

    print("\nReadable payload:")
    print(readable["readable_payload"])
    print("=" * 70)

    try:
        save_log(event, logs_root)
    except OSError as exc:
        print(f"Error saving log: {exc}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(
        description="Readable frontend/backend traffic logger"
    )

    parser.add_argument(
        "--interface",
        "-i",
        help="Capture interface, e.g. lo0 on macOS",
    )

    parser.add_argument(
        "--port",
        "-p",
        type=parse_ports,
        metavar="FRONTEND,BACKEND",
        help="Frontend and backend ports, e.g. 5173,4000",
    )

    parser.add_argument(
        "--logs-root",
        default="logs",
        help="Root log directory (default: logs)",
    )

    parser.add_argument(
        "--label",
        nargs="?",
        const="capture",
        default="capture",
        help="Optional label (default: capture)",
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available capture interfaces and exit",
    )

    args = parser.parse_args()

    if args.list_interfaces:
        for interface in get_if_list():
            print(interface)
        return

    if not args.interface:
        parser.error("--interface is required")

    if not args.port:
        parser.error("--port is required")

    frontend_port, backend_port = args.port

    capture_filter = (
        f"tcp port {frontend_port} or tcp port {backend_port}"
    )

    print("Logger Agent started")
    print(f"Interface: {args.interface}")
    print(f"Frontend port: {frontend_port}")
    print(f"Backend port: {backend_port}")
    print(f"Logs directory: {args.logs_root}")
    print("Readable JSON output enabled.")
    print("Press Ctrl+C to stop.")

    def stop_logger(signum, frame):
        print("\nStopping Logger Agent...")
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, stop_logger)
    signal.signal(signal.SIGTERM, stop_logger)

    try:
        sniff(
            iface=args.interface,
            filter=capture_filter,
            prn=lambda packet: process_packet(
                packet,
                frontend_port,
                backend_port,
                args.label,
                args.logs_root,
            ),
            store=False,
        )
    except KeyboardInterrupt:
        print("\nLogger stopped.")
    except Exception as exc:
        print(f"Capture failed: {exc}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()