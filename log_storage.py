from pathlib import Path
from datetime import datetime

def save_log(event, logs_root="logs"):
    """Save readable events in combined and event-specific log files."""

    timestamp = datetime.fromisoformat(event["timestamp"])

    date_dir = (
        Path(logs_root)
        / timestamp.strftime("%Y")
        / timestamp.strftime("%m")
        / timestamp.strftime("%d")
    )

    date_dir.mkdir(parents=True, exist_ok=True)

    event_type = "".join(
        char
        for char in event["type"]
        if char.isalnum() or char in ("_", "-")
    ) or "UNKNOWN"

    lines = [
        f"Timestamp: {event['timestamp']}",
        f"Label: {event['label']}",
        f"Type: {event['type']}",
        f"Event: {event['summary']}",
        f"Direction: {event['direction']}",
        f"Source: {event['src_ip']}:{event['src_port']}",
        f"Destination: {event['dst_ip']}:{event['dst_port']}",
        f"Payload size: {event['size']} bytes",
    ]

    for detail in event.get("details", []):
        lines.append(detail)

    lines.extend([
        "",
        "Readable payload:",
        event.get("data", ""),
        "=" * 70,
        "",
    ])

    entry = "\n".join(lines) + "\n"

    # Combined log: all event types.
    with (date_dir / "combined.log").open(
        "a", encoding="utf-8"
    ) as file:
        file.write(entry)

    # Individual log file for this event type.
    with (date_dir / f"{event_type}.log").open(
        "a", encoding="utf-8"
    ) as file:
        file.write(entry)