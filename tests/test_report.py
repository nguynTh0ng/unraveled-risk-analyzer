from __future__ import annotations

import sys
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.models import Event
from src.report import TimelineJsonlWriter, TimelineSummaryState, write_reports
from src.scoring import FACTOR_MEANINGS


def test_timeline_jsonl_writer_keeps_only_risk_signatures(tmp_path: Path) -> None:
    with TimelineJsonlWriter(tmp_path) as writer:
        writer.update(
            Event(
                event_id="unknown-1",
                source_type="network",
                source_file="x",
                raw_message="",
                signature=None,
            )
        )
        writer.update(
            Event(
                event_id="apt-1",
                source_type="network",
                source_file="x",
                raw_message="",
                signature="APT",
                stage="Reconnaissance",
            )
        )
        writer.update(
            Event(
                event_id="aa-1",
                source_type="host-auth",
                source_file="x",
                raw_message="",
                signature="AA",
                activity="Valid Accounts",
            )
        )

    lines = (tmp_path / "timeline_full.jsonl").read_text(encoding="utf-8").splitlines()

    assert len(lines) == 2
    assert '"event_id": "apt-1"' in lines[0]
    assert "unknown-1" not in "\n".join(lines)
    assert "description" not in json.loads(lines[0])

    apt_lines = (tmp_path / "timeline_APT.jsonl").read_text(encoding="utf-8").splitlines()
    aa_lines = (tmp_path / "timeline_AA.jsonl").read_text(encoding="utf-8").splitlines()
    sh_lines = (tmp_path / "timeline_SH.jsonl").read_text(encoding="utf-8").splitlines()

    assert len(apt_lines) == 1
    assert '"event_id": "apt-1"' in apt_lines[0]
    assert len(aa_lines) == 1
    assert '"event_id": "aa-1"' in aa_lines[0]
    assert sh_lines == []


def test_timeline_summary_state_groups_by_signature_and_stage() -> None:
    state = TimelineSummaryState()
    state.update(
        Event(
            event_id="aa-1",
            source_type="network",
            source_file="x",
            raw_message="",
            timestamp="2021-01-01T00:00:00+00:00",
            stage="Reconnaissance",
            signature="AA",
        )
    )
    state.update(
        Event(
            event_id="aa-2",
            source_type="network",
            source_file="x",
            raw_message="",
            timestamp="2021-01-01T02:00:00+00:00",
            stage="Initial Access",
            signature="AA",
        )
    )

    rows = state.finalize()
    aa_row = [row for row in rows if row["signature"] == "AA"][0]

    assert aa_row["event_count"] == 2
    assert aa_row["first_seen"] == "2021-01-01T00:00:00+00:00"
    assert aa_row["last_seen"] == "2021-01-01T02:00:00+00:00"
    assert aa_row["stages"]["Reconnaissance"]["event_count"] == 1
    assert aa_row["stages"]["Initial Access"]["event_count"] == 1
    assert "stages" not in aa_row["stages"]["Reconnaissance"]


def test_write_reports_includes_timeline_summary_and_scoring_model(tmp_path: Path) -> None:
    write_reports(
        output_dir=tmp_path,
        total_events=2,
        scenarios=[],
        risk_scores=[],
        factor_meanings=FACTOR_MEANINGS,
        timeline_summary=[
            {
                "signature": "AA",
                "event_count": 2,
                "first_seen": "2021-01-01T00:00:00+00:00",
                "last_seen": "2021-01-01T02:00:00+00:00",
                "stages": {},
            }
        ],
    )

    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))

    assert summary["timeline_summary"][0]["signature"] == "AA"
    assert summary["factor_meanings"]["A1"] == "Specialist expertise"
    assert summary["scoring_model"]["formula"] == "risk_score = likelihood_score * impact_score * 4"
    assert "Offensive Pressure" in summary["scoring_model"]["likelihood_inputs"]
