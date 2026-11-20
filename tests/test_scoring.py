from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.models import Event
from src.scoring import LabelLogScoringState


def test_label_log_scoring_state_returns_matrix() -> None:
    events = [
        Event(
            event_id="e1",
            source_type="network",
            source_file="x",
            raw_message="",
            timestamp="2021-01-01T00:00:00+00:00",
            activity="Remote System Discovery",
            stage="Reconnaissance",
            defender_response="Detected",
            signature="AA",
        ),
        Event(
            event_id="e2",
            source_type="host-auth",
            source_file="x",
            raw_message="",
            timestamp="2021-01-01T02:00:00+00:00",
            activity="Maintain Access",
            stage="Lateral Movement",
            defender_response="Benign",
            signature="APT",
        ),
    ]

    state = LabelLogScoringState()
    for event in events:
        state.update(event)

    matrix = state.finalize()
    assert len(matrix) == 6

    aa_net = [row for row in matrix if row["signature"] == "AA" and row["log_type"] == "network"][0]
    assert aa_net["event_count"] == 1
    assert "stage_count" not in aa_net
    assert "activity_count" not in aa_net
    assert "criteria" not in aa_net
    assert aa_net["likelihood_score"] > 0
    assert aa_net["impact_score"] > 0
    assert aa_net["risk_score"] > 0
    assert aa_net["factor_scores"]["A1"] == 3.0
    assert aa_net["factor_scores"]["T1"] == 2.0
    assert "factor_meanings" not in aa_net
    assert "Evidence Volume" in aa_net["risk_factors"]

    apt_host = [row for row in matrix if row["signature"] == "APT" and row["log_type"] == "host"][0]
    assert apt_host["event_count"] == 1
    assert apt_host["factor_scores"]["A1"] == 8.0
    assert apt_host["factor_scores"]["T1"] == 8.0

    sh_host = [row for row in matrix if row["signature"] == "SH" and row["log_type"] == "host"][0]
    assert sh_host["event_count"] == 0
    assert sh_host["severity"] == "No Evidence"
