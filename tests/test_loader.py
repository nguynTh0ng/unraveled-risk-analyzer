from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.loader import (
    discover_input_files,
    iter_event_chunks,
    load_events_from_file,
)


def test_load_events_from_csv(tmp_path: Path) -> None:
    csv_file = tmp_path / "network.csv"
    csv_file.write_text(
        "src_ip,dst_ip,bidirectional_first_seen_ms,Activity,Stage,DefenderResponse,Signature\n"
        "10.0.0.1,10.0.0.2,1622052177753,Remote System Discovery,Reconnaissance,Detected,APT\n",
        encoding="utf-8",
    )

    events = load_events_from_file(csv_file, "network")

    assert len(events) == 1
    assert events[0].src_ip == "10.0.0.1"
    assert events[0].signature == "APT"
    assert events[0].timestamp is not None
    assert events[0].timestamp.endswith("+00:00")


def test_load_events_from_txt(tmp_path: Path) -> None:
    txt_file = tmp_path / "auth_labeled"
    txt_file.write_text(
        "LogEvent,Activity,Stage,DefenderResponse,Signature\n"
        "Jun 13 00:17:01 ubuntu sshd[100]: Failed password for root from 10.0.0.9 port 22\n"
        "Jun 13 00:17:10 ubuntu sshd[100]: Accepted password for ubuntu from 10.0.0.9 port 22\n",
        encoding="utf-8",
    )

    events = load_events_from_file(txt_file, "host-auth")

    assert len(events) == 2
    assert "Failed password" in events[0].raw_message
    assert events[0].timestamp is not None
    assert events[0].timestamp.startswith("2021-06-13T00:17:01")


def test_load_events_scientific_epoch_and_windows_short_time(tmp_path: Path) -> None:
    network_file = tmp_path / "net.csv"
    network_file.write_text(
        "src_ip,dst_ip,bidirectional_first_seen_ms,Activity,Stage,DefenderResponse,Signature\n"
        "10.0.0.1,10.0.0.2,1.62443E+12,Normal,Benign,Benign,None\n",
        encoding="utf-8",
    )
    net_events = load_events_from_file(network_file, "network")
    assert net_events[0].timestamp is not None
    assert net_events[0].timestamp.endswith("+00:00")

    win_file = tmp_path / "win.csv"
    win_file.write_text(
        "Date and Time,Activity,Stage,DefenderResponse,Signature\n"
        "7/17/2021 22:49,Normal,Benign,Benign,None\n",
        encoding="utf-8",
    )
    win_events = load_events_from_file(win_file, "host-windows")
    assert win_events[0].timestamp is not None
    assert win_events[0].timestamp.startswith("2021-07-17T22:49:00")


def test_load_events_from_json(tmp_path: Path) -> None:
    json_file = tmp_path / "events.json"
    json_file.write_text(
        """
[
  {"LogEvent": "event-1", "Signature": "None"},
  {"LogEvent": "event-2", "Signature": "None"},
  {"LogEvent": "event-3", "Signature": "AA", "Activity": "Reconnaissance"}
]
""".strip(),
        encoding="utf-8",
    )

    events = load_events_from_file(json_file, "host-auth")

    assert len(events) == 3
    assert any(event.signature == "AA" for event in events)


def test_iter_event_chunks_bounds_chunk_size(tmp_path: Path) -> None:
    data_root = tmp_path / "dataset"
    flow_dir = data_root / "network-flows" / "day"
    flow_dir.mkdir(parents=True)
    (flow_dir / "net_Flow_labeled.csv").write_text(
        "src_ip,dst_ip,bidirectional_first_seen_ms,Activity,Stage,DefenderResponse,Signature\n"
        "10.0.0.1,10.0.0.2,1622052177753,Normal,Benign,Benign,None\n"
        "10.0.0.3,10.0.0.4,1622052177754,Normal,Benign,Benign,None\n"
        "10.0.0.5,10.0.0.6,1622052177755,Recon,Reconnaissance,Detected,APT\n",
        encoding="utf-8",
    )

    chunks = list(iter_event_chunks(data_root, chunk_size=2))

    assert [len(chunk) for chunk in chunks] == [2, 1]
    assert chunks[0][0].event_id == "network-flows/day/net_Flow_labeled.csv:1"


def test_labeled_host_log_with_commas_keeps_signature(tmp_path: Path) -> None:
    host_file = tmp_path / "10_0_0_1-auth_labeled"
    host_file.write_text(
        "LogEvent,Activity,Stage,DefenderResponse,Signature\n"
        "Jun 15 app[1]: message, with, commas,Phishing,Initial Access,Detected,SH\n",
        encoding="utf-8",
    )

    events = load_events_from_file(host_file, "host-auth")

    assert len(events) == 1
    assert events[0].raw_message == "Jun 15 app[1]: message, with, commas"
    assert events[0].activity == "Phishing"
    assert events[0].stage == "Initial Access"
    assert events[0].defender_response == "Detected"
    assert events[0].signature == "SH"


def test_discover_input_files_includes_filebeat(tmp_path: Path) -> None:
    filebeat_dir = tmp_path / "host" / "filebeat"
    filebeat_dir.mkdir(parents=True)
    filebeat_file = filebeat_dir / "10_0_0_1-ubuntu_labeled"
    filebeat_file.write_text(
        "LogEvent,Activity,Stage,DefenderResponse,Signature\n",
        encoding="utf-8",
    )

    buckets = discover_input_files(tmp_path)

    assert buckets["host_filebeat"] == [filebeat_file]


def test_windows_labeled_csv_keeps_message_and_signature(tmp_path: Path) -> None:
    win_file = tmp_path / "host-windows.csv"
    win_file.write_text(
        "Level,Date and Time,Source,Event ID,Task Category,Activity,"
        "Stage,DefenderResponse,Signature\n"
        'Information,7/1/2021 10:33:48 PM,Wow64 Emulation Layer,1109,None,'
        '"The program, feature ""Part_2.exe"" cannot start.",Phishing,'
        "Establish Foothold,Mitigated,SH\n",
        encoding="utf-8",
    )

    events = load_events_from_file(win_file, "host-windows")

    assert len(events) == 1
    assert events[0].raw_message == 'The program, feature "Part_2.exe" cannot start.'
    assert events[0].activity == "Phishing"
    assert events[0].stage == "Establish Foothold"
    assert events[0].defender_response == "Mitigated"
    assert events[0].signature == "SH"
