from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.matcher import MatcherState, load_scenarios
from src.models import Event


def test_matcher_creates_scenario_instance(tmp_path: Path) -> None:
    scenario_file = tmp_path / "scenarios.json"
    scenario_file.write_text(
        json.dumps(
            {
                "scenarios": [
                    {
                        "scenario_id": "APT-NET-001",
                        "scenario_type": "APT-Network",
                        "signature": "APT",
                        "log_type": "network",
                        "required_any": ["reconnaissance"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    definitions = load_scenarios(scenario_file)
    events = [
        Event(
            event_id="1",
            source_type="network",
            source_file="f.csv",
            raw_message="",
            activity="Remote System Discovery",
            stage="Reconnaissance",
            defender_response="Detected",
            signature="APT",
        )
    ]

    state = MatcherState(definitions)
    for event in events:
        state.update(event)
    instances = state.finalize()

    assert len(instances) == 1
    assert instances[0].scenario_type == "APT-Network"
    assert instances[0].metadata["matched_events"] == 1
    assert instances[0].metadata["stages"] == {"Reconnaissance": 1}
    assert instances[0].metadata["activities"] == {"Remote System Discovery": 1}
    assert instances[0].metadata["defender_responses"] == {"Detected": 1}


def test_matcher_builds_attack_chain_and_affected_assets(tmp_path: Path) -> None:
    scenario_file = tmp_path / "scenarios.json"
    scenario_file.write_text(
        json.dumps(
            {
                "scenarios": [
                    {
                        "scenario_id": "APT-NET-001",
                        "scenario_type": "APT-Network",
                        "signature": "APT",
                        "log_type": "network",
                        "required_any": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    definitions = load_scenarios(scenario_file)
    events = [
        Event(
            event_id="e2",
            source_type="network",
            source_file="f.csv",
            raw_message="",
            timestamp="2021-01-01T00:05:00+00:00",
            activity="Internal Pivot",
            stage="Lateral Movement",
            defender_response="Benign",
            signature="APT",
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
        ),
        Event(
            event_id="e1",
            source_type="network",
            source_file="f.csv",
            raw_message="",
            timestamp="2021-01-01T00:01:00+00:00",
            activity="Remote System Discovery",
            stage="Reconnaissance",
            defender_response="Detected",
            signature="APT",
            src_ip="10.0.0.10",
            dst_ip="10.0.0.11",
        ),
        Event(
            event_id="e3",
            source_type="network",
            source_file="f.csv",
            raw_message="",
            timestamp="2021-01-01T00:10:00+00:00",
            activity="Staged Exfiltration",
            stage="Exfiltration",
            defender_response="Mitigated",
            signature="APT",
            src_ip="10.0.0.20",
            dst_ip="10.0.0.99",
        ),
    ]

    state = MatcherState(definitions)
    for event in events:
        state.update(event)
    instances = state.finalize()
    metadata = instances[0].metadata

    assert metadata["affected_assets"] == ["10.0.0.20", "10.0.0.11", "10.0.0.99"]
    assert metadata["source_ips"] == ["10.0.0.10", "10.0.0.20"]
    assert metadata["destination_ips"] == ["10.0.0.20", "10.0.0.11", "10.0.0.99"]
    assert [step["stage"] for step in metadata["attack_chain"]] == [
        "Reconnaissance",
        "Lateral Movement",
        "Exfiltration",
    ]
    assert metadata["attack_chain"][0]["affected_assets"] == ["10.0.0.11"]
    assert metadata["attack_chain"][0]["defender_responses"] == {"Detected": 1}
    assert "description" not in metadata["attack_chain"][0]


def test_matcher_caps_matched_event_ids_at_20(tmp_path: Path) -> None:
    scenario_file = tmp_path / "scenarios.json"
    scenario_file.write_text(
        json.dumps(
            {
                "scenarios": [
                    {
                        "scenario_id": "AA-NET-001",
                        "scenario_type": "AA-Network",
                        "signature": "AA",
                        "log_type": "network",
                        "required_any": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    definitions = load_scenarios(scenario_file)
    state = MatcherState(definitions)
    for index in range(25):
        state.update(
            Event(
                event_id=f"e{index}",
                source_type="network",
                source_file="f.csv",
                raw_message="",
                stage="Reconnaissance",
                signature="AA",
            )
        )

    instances = state.finalize()

    assert instances[0].metadata["matched_events"] == 25
    assert len(instances[0].matched_event_ids) == 20
