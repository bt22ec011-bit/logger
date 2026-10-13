"""Log storage module for the Universal Application Logger.

Stores structured log events in a date-based folder tree using JSON Lines
(one complete JSON object per line):

    logs/
    └── 2026/
        ├── 01 ... 12              <- all month folders created per year
        └── 10/
            └── 13/
                ├── combined.log   <- every event
                ├── INFO.log       <- severity split
                ├── WARNING.log
                ├── ERROR.log
                ├── DEBUG.log
                ├── HTTP_REQUEST.log    <- event-type split
                └── HTTP_RESPONSE.log

Design goals:
- Safe file handling: malformed records are rejected, never crash storage.
- Configurable retention and multiple storage destinations.
- Thread-safe appends; directories created automatically.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_FILES = ("DEBUG", "INFO", "WARNING", "ERROR")
EVENT_TYPE_FILES = ("HTTP_REQUEST", "HTTP_RESPONSE")
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_-]")


def sanitize_file_part(name: str, default: str = "UNKNOWN") -> str:
    """Return a filesystem-safe file name derived from an event type."""
    cleaned = _SAFE_NAME_RE.sub("", str(name or ""))
    return cleaned or default


def parse_event_timestamp(value) -> datetime:
    """Parse an ISO-8601 timestamp string; fall back to 'now' (UTC)."""
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class LogStorage:
    """Writes structured events to one or more storage roots."""

    def __init__(self, root="logs", destinations=None, retention_days=None):
        # `root` is the primary destination; extra paths can be added via
        # `destinations` (multiple storage destinations requirement).
        roots = [Path(root)]
        for extra in destinations or []:
            p = Path(extra)
            if p not in roots:
                roots.append(p)
        self.roots = roots
        self.retention_days = retention_days
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Directory management
    # ------------------------------------------------------------------ #
    def date_dir(self, root: Path, dt: datetime) -> Path:
        """Return (creating if needed) logs/<year>/<month>/<day>/ ."""
        day_dir = root / f"{dt:%Y}" / f"{dt:%m}" / f"{dt:%d}"
        # Requirement: create all 12 month folders for each year.
        year_dir = root / f"{dt:%Y}"
        year_dir.mkdir(parents=True, exist_ok=True)
        for month in range(1, 13):
            try:
                (year_dir / f"{month:02d}").mkdir(exist_ok=True)
            except OSError as exc:  # pragma: no cover - fs edge case
                print(f"[log_storage] month dir warning: {exc}",
                      file=sys.stderr)
        day_dir.mkdir(parents=True, exist_ok=True)
        return day_dir

    # ------------------------------------------------------------------ #
    # Writing
    # ------------------------------------------------------------------ #
    def save_event(self, event: dict) -> list[str]:
        """Persist one structured event as a JSON Lines record.

        Returns the list of files written. Never raises for malformed
        input — invalid events are reported on stderr and skipped.
        """
        if not isinstance(event, dict):
            print("[log_storage] rejected non-dict event", file=sys.stderr)
            return []
        try:
            line = json.dumps(event, ensure_ascii=False,
                              separators=(",", ":"))
            json.loads(line)  # sanity check round-trip
        except (TypeError, ValueError) as exc:
            print(f"[log_storage] rejected malformed event: {exc}",
                  file=sys.stderr)
            return []

        dt = parse_event_timestamp(event.get("timestamp"))
        severity = sanitize_file_part(
            str(event.get("severity", "")).upper(), default="INFO")
        event_type = event.get("event_type") or event.get("type")
        written: list[str] = []

        with self._lock:
            for root in self.roots:
                try:
                    day_dir = self.date_dir(root, dt)
                except OSError as exc:
                    print(f"[log_storage] cannot create dirs in {root}: {exc}",
                          file=sys.stderr)
                    continue

                targets = ["combined.log"]
                if severity in SEVERITY_FILES:
                    targets.append(f"{severity}.log")
                if event_type in EVENT_TYPE_FILES:
                    targets.append(f"{sanitize_file_part(event_type)}.log")

                for name in targets:
                    if self._append_line(day_dir / name, line):
                        written.append(str(day_dir / name))
        return written

    @staticmethod
    def _append_line(path: Path, line: str) -> bool:
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            return True
        except OSError as exc:
            print(f"[log_storage] write failed for {path}: {exc}",
                  file=sys.stderr)
            return False

    # ------------------------------------------------------------------ #
    # Reading (used by the backend API)
    # ------------------------------------------------------------------ #
    def read_events(self, date: str | None = None,
                    limit: int | None = None) -> list[dict]:
        """Read JSON Lines events from the day-folder tree (newest first).

        `date` (YYYY-MM-DD) restricts reading to one day folder. Corrupt
        lines are skipped safely rather than raising.
        """
        events: list[dict] = []
        root = self.roots[0]
        if not root.exists():
            return []

        for ydir in sorted(root.iterdir(), reverse=True):
            if not (ydir.is_dir() and ydir.name.isdigit()):
                continue
            for mdir in sorted(ydir.iterdir(), reverse=True):
                if not (mdir.is_dir() and mdir.name.isdigit()):
                    continue
                for ddir in sorted(mdir.iterdir(), reverse=True):
                    if not (ddir.is_dir() and ddir.name.isdigit()):
                        continue
                    folder_date = f"{ydir.name}-{mdir.name}-{ddir.name}"
                    if date and folder_date != date:
                        continue
                    combined = ddir / "combined.log"
                    if not combined.exists():
                        continue
                    try:
                        raw_lines = combined.read_text(
                            encoding="utf-8").splitlines()
                    except OSError as exc:
                        print(f"[log_storage] read failed: {exc}",
                              file=sys.stderr)
                        continue
                    for raw in reversed(raw_lines):
                        raw = raw.strip()
                        if not raw:
                            continue
                        try:
                            ev = json.loads(raw)
                        except ValueError:
                            continue  # skip corrupt lines safely
                        if isinstance(ev, dict):
                            events.append(ev)

        events.sort(key=lambda e: str(e.get("timestamp", "")), reverse=True)
        if limit:
            events = events[:limit]
        return events

    # ------------------------------------------------------------------ #
    # Retention
    # ------------------------------------------------------------------ #
    def apply_retention(self) -> list[str]:
        """Delete day folders older than `retention_days`."""
        if not self.retention_days or self.retention_days <= 0:
            return []
        cutoff = datetime.now(timezone.utc).timestamp() - (
            self.retention_days * 86400)
        removed: list[str] = []
        for root in self.roots:
            if not root.exists():
                continue
            for ydir in root.glob("[0-9][0-9][0-9][0-9]"):
                for mdir in ydir.glob("[0-9][0-9]"):
                    for ddir in mdir.glob("[0-9][0-9]"):
                        try:
                            folder = datetime.strptime(
                                f"{ydir.name}-{mdir.name}-{ddir.name}",
                                "%Y-%m-%d").replace(tzinfo=timezone.utc)
                        except ValueError:
                            continue
                        if folder.timestamp() < cutoff:
                            try:
                                shutil.rmtree(ddir)
                                removed.append(str(ddir))
                            except OSError as exc:
                                print(
                                    f"[log_storage] retention error: {exc}",
                                    file=sys.stderr)
        return removed


# ---------------------------------------------------------------------- #
# Module-level convenience API
# ---------------------------------------------------------------------- #
_default_storage: LogStorage | None = None
_default_lock = threading.Lock()


def get_storage(root="logs", **kwargs) -> LogStorage:
    """Return a shared LogStorage instance for `root`."""
    global _default_storage
    with _default_lock:
        if _default_storage is None or str(_default_storage.roots[0]) != str(
                Path(root)):
            _default_storage = LogStorage(root=root, **kwargs)
        return _default_storage


def save_log(event: dict, logs_root="logs") -> list[str]:
    """Save one structured event (JSON Lines) under `logs_root`."""
    return get_storage(logs_root).save_event(event)
