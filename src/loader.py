from __future__ import annotations

import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .models import Event


def discover_input_files(dataset_root: Path) -> dict[str, list[Path]]:
    return {
        "network": sorted(dataset_root.rglob("*Flow_labeled.csv")),
        "host_auth": sorted(dataset_root.rglob("*-auth_labeled*")),
        "host_audit": sorted(dataset_root.rglob("*-audit_labeled*")),
        "host_filebeat": sorted(dataset_root.rglob("host/filebeat/*_labeled*")),
        "host_syslog": sorted(dataset_root.rglob("*-syslog_labeled*")),
        "host_windows": sorted(dataset_root.rglob("*windows*_labeled.csv")),
    }


def _to_iso_from_epoch_seconds(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


def _parse_text_datetime(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None

    for fmt in [
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %I:%M %p",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ]:
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return None


def _is_number_like(value: str) -> bool:
    return bool(re.fullmatch(r"[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?", value.strip()))


def _to_timestamp(record: dict[str, Any], raw_message: str) -> str | None:
    timestamp_keys = [
        "bidirectional_first_seen_ms",
        "src2dst_first_seen_ms",
        "dst2src_first_seen_ms",
        "timestamp",
        "time",
        "Date",
        "Date and Time",
    ]
    for key in timestamp_keys:
        if key not in record:
            continue
        raw = str(record[key]).strip()
        if raw in {"", "nan", "None"}:
            continue

        if _is_number_like(raw):
            value = float(raw)
            if key.endswith("_ms") or value >= 1e11:
                return _to_iso_from_epoch_seconds(value / 1000.0)
            return _to_iso_from_epoch_seconds(value)

        parsed = _parse_text_datetime(raw)
        if parsed:
            return parsed

    audit_match = re.search(r"audit\((\d+(?:\.\d+)?):\d+\)", raw_message)
    if audit_match:
        return _to_iso_from_epoch_seconds(float(audit_match.group(1)))

    syslog_match = re.match(
        r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
        raw_message,
    )
    if syslog_match:
        try:
            dt = datetime.strptime(f"2021 {syslog_match.group(1)}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            return None

    return None


def _extract_host_from_filename(file_path: Path) -> str | None:
    match = re.search(r"(\d+_\d+_\d+_\d+)", file_path.name)
    if not match:
        return None
    return match.group(1).replace("_", ".")


def _make_event(
    event_id: str,
    source_type: str,
    source_file: Path,
    record: dict[str, Any],
    raw_message: str,
) -> Event:
    src_ip = str(record.get("src_ip", "")).strip() or None
    dst_ip = str(record.get("dst_ip", "")).strip() or None
    host = _extract_host_from_filename(source_file) or src_ip
    activity = str(record.get("Activity", "")).strip() or None
    stage = str(record.get("Stage", "")).strip() or None
    defender_response = str(record.get("DefenderResponse", "")).strip() or None
    signature = str(record.get("Signature", "")).strip() or None

    if signature and signature.lower() == "none":
        signature = None

    source_type = sys.intern(source_type)
    source_file_str = sys.intern(str(source_file))
    host = sys.intern(host) if host else None
    src_ip = sys.intern(src_ip) if src_ip else None
    dst_ip = sys.intern(dst_ip) if dst_ip else None
    activity = sys.intern(activity) if activity else None
    stage = sys.intern(stage) if stage else None
    defender_response = sys.intern(defender_response) if defender_response else None
    signature = sys.intern(signature) if signature else None

    return Event(
        event_id=event_id,
        source_type=source_type,
        source_file=source_file_str,
        raw_message=raw_message,
        timestamp=_to_timestamp(record, raw_message),
        host=host,
        src_ip=src_ip,
        dst_ip=dst_ip,
        activity=activity,
        stage=stage,
        defender_response=defender_response,
        signature=signature,
    )


def _raw_message_from_record(record: dict[str, Any]) -> str:
    for key in ["LogEvent", "Keywords", "Message", "EventData", "Source"]:
        value = str(record.get(key, "")).strip()
        if value:
            return value
    return ""


def _is_labeled_log_header(header: str) -> bool:
    normalized = header.strip().lower().replace(" ", "")
    return normalized == "logevent,activity,stage,defenderresponse,signature"


def _parse_labeled_log_line(line: str) -> dict[str, str] | None:
    parts = line.rstrip("\n\r").rsplit(",", 4)
    if len(parts) != 5:
        return None

    log_event, activity, stage, defender_response, signature = parts
    return {
        "LogEvent": log_event.strip(),
        "Activity": activity.strip(),
        "Stage": stage.strip(),
        "DefenderResponse": defender_response.strip(),
        "Signature": signature.strip(),
    }


def _is_windows_labeled_header(header: str) -> bool:
    normalized = header.strip().lower().replace(" ", "")
    return (
        normalized
        == "level,dateandtime,source,eventid,taskcategory,activity,stage,defenderresponse,signature"
    )


def _clean_csv_text(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1].replace('""', '"')
    return value


def _parse_windows_labeled_line(line: str) -> dict[str, str] | None:
    left = line.rstrip("\n\r").split(",", 5)
    if len(left) != 6:
        return None

    level, date_time, source, event_id, task_category, remainder = left
    right = remainder.rsplit(",", 4)
    if len(right) != 5:
        return None

    log_event, activity, stage, defender_response, signature = right
    return {
        "Level": level.strip(),
        "Date and Time": date_time.strip(),
        "Source": source.strip(),
        "Event ID": event_id.strip(),
        "Task Category": task_category.strip(),
        "LogEvent": _clean_csv_text(log_event),
        "Activity": activity.strip(),
        "Stage": stage.strip(),
        "DefenderResponse": defender_response.strip(),
        "Signature": signature.strip(),
    }


def _event_id(file_path: Path, line_number: int, event_id_root: Path | None) -> str:
    if event_id_root is None:
        return f"{file_path.name}:{line_number}"
    try:
        source_name = file_path.relative_to(event_id_root).as_posix()
    except ValueError:
        source_name = file_path.as_posix()
    return f"{source_name}:{line_number}"


def _iter_csv_events(
    file_path: Path,
    source_type: str,
    event_id_root: Path | None,
) -> Iterator[Event]:
    with file_path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for i, row in enumerate(reader):
            raw_message = _raw_message_from_record(row)
            yield _make_event(
                _event_id(file_path, i + 1, event_id_root),
                source_type,
                file_path,
                row,
                raw_message,
            )


def _iter_labeled_log_events(
    file_path: Path,
    source_type: str,
    event_id_root: Path | None,
) -> Iterator[Event]:
    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        header = fh.readline()
        if not _is_labeled_log_header(header):
            yield from _iter_text_events(file_path, source_type, event_id_root)
            return

        for i, line in enumerate(fh):
            if not line.strip():
                continue
            record = _parse_labeled_log_line(line)
            if record is None:
                record = {"LogEvent": line.strip()}
            raw_message = record["LogEvent"]
            yield _make_event(
                _event_id(file_path, i + 1, event_id_root),
                source_type,
                file_path,
                record,
                raw_message,
            )


def _iter_windows_labeled_events(
    file_path: Path,
    source_type: str,
    event_id_root: Path | None,
) -> Iterator[Event]:
    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        header = fh.readline()
        if not _is_windows_labeled_header(header):
            yield from _iter_csv_events(file_path, source_type, event_id_root)
            return

        for i, line in enumerate(fh):
            if not line.strip():
                continue
            record = _parse_windows_labeled_line(line)
            if record is None:
                record = {"LogEvent": line.strip()}
            raw_message = record["LogEvent"]
            yield _make_event(
                _event_id(file_path, i + 1, event_id_root),
                source_type,
                file_path,
                record,
                raw_message,
            )


def _iter_json_events(
    file_path: Path,
    source_type: str,
    event_id_root: Path | None,
) -> Iterator[Event]:
    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        payload = json.load(fh)

    rows = payload if isinstance(payload, list) else payload.get("events", [])
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            row = {"LogEvent": str(row)}
        raw_message = str(row.get("LogEvent") or row)
        yield _make_event(
            _event_id(file_path, i + 1, event_id_root),
            source_type,
            file_path,
            row,
            raw_message,
        )


def _iter_text_events(
    file_path: Path,
    source_type: str,
    event_id_root: Path | None,
) -> Iterator[Event]:
    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            if line.startswith("LogEvent,Activity,Stage,DefenderResponse,Signature"):
                continue
            record = {"LogEvent": line}
            yield _make_event(
                _event_id(file_path, i + 1, event_id_root),
                source_type,
                file_path,
                record,
                line,
            )


def _has_csv_header(file_path: Path) -> bool:
    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        first_line = fh.readline().strip()

    if not first_line:
        return False

    lower = first_line.lower()
    if _is_labeled_log_header(first_line):
        return True
    if "," not in first_line:
        return False
    csv_tokens = [
        "signature",
        "activity",
        "stage",
        "defenderresponse",
        "src_ip",
        "dst_ip",
        "date and time",
    ]
    return any(token in lower for token in csv_tokens)


def _is_labeled_log_file(file_path: Path) -> bool:
    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        return _is_labeled_log_header(fh.readline())


def _is_windows_labeled_file(file_path: Path) -> bool:
    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        return _is_windows_labeled_header(fh.readline())


def load_events_from_file(file_path: Path, source_type: str) -> list[Event]:
    return list(iter_events_from_file(file_path, source_type))


def iter_events_from_file(
    file_path: Path,
    source_type: str,
    event_id_root: Path | None = None,
) -> Iterator[Event]:
    suffix = file_path.suffix.lower()
    if _is_windows_labeled_file(file_path):
        yield from _iter_windows_labeled_events(file_path, source_type, event_id_root)
    elif _is_labeled_log_file(file_path):
        yield from _iter_labeled_log_events(file_path, source_type, event_id_root)
    elif suffix == ".csv" or _has_csv_header(file_path):
        yield from _iter_csv_events(file_path, source_type, event_id_root)
    elif suffix == ".json":
        yield from _iter_json_events(file_path, source_type, event_id_root)
    else:
        yield from _iter_text_events(file_path, source_type, event_id_root)


def iter_all_events(dataset_root: Path) -> Iterator[Event]:
    buckets = discover_input_files(dataset_root)

    for path in buckets["network"]:
        yield from iter_events_from_file(path, "network", dataset_root)
    for path in buckets["host_auth"]:
        yield from iter_events_from_file(path, "host-auth", dataset_root)
    for path in buckets["host_audit"]:
        yield from iter_events_from_file(path, "host-audit", dataset_root)
    for path in buckets["host_filebeat"]:
        yield from iter_events_from_file(path, "host-filebeat", dataset_root)
    for path in buckets["host_syslog"]:
        yield from iter_events_from_file(path, "host-syslog", dataset_root)
    for path in buckets["host_windows"]:
        yield from iter_events_from_file(path, "host-windows", dataset_root)


def iter_event_chunks(dataset_root: Path, chunk_size: int = 50_000) -> Iterator[list[Event]]:
    chunk: list[Event] = []
    for event in iter_all_events(dataset_root):
        chunk.append(event)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


__all__ = [
    "discover_input_files",
    "iter_events_from_file",
    "iter_all_events",
    "iter_event_chunks",
    "load_events_from_file",
]
