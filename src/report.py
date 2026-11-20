from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import Event, ScenarioInstance

RISK_SIGNATURES = {"AA", "SH", "APT"}


def _normalize_signature(value: str | None) -> str:
    return (value or "").strip().upper()


def _event_action(event: Event) -> str:
    if event.stage and event.stage.strip():
        return event.stage.strip()
    if event.activity and event.activity.strip():
        return event.activity.strip()
    return "Unknown"


def _event_endpoint(value: str | None) -> str:
    return (value or "").strip() or "unknown"


def _event_timeline_row(event: Event) -> dict:
    signature = _normalize_signature(event.signature) or "Unknown"
    action = _event_action(event)
    src = _event_endpoint(event.src_ip)
    dst = _event_endpoint(event.dst_ip)

    return {
        "event_id": event.event_id,
        "signature": signature,
        "from_time": event.timestamp,
        "to_time": event.timestamp,
        "action": action,
        "from_ip": src,
        "to_ip": dst,
        "source_type": event.source_type,
    }


class TimelineJsonlWriter:
    def __init__(self, output_dir: Path) -> None:
        self.path = output_dir / "timeline_full.jsonl"
        self._fh = None
        self._label_paths = {
            signature: output_dir / f"timeline_{signature}.jsonl"
            for signature in sorted(RISK_SIGNATURES)
        }
        self._label_fhs = {}

    def __enter__(self) -> "TimelineJsonlWriter":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("w", encoding="utf-8")
        self._label_fhs = {
            signature: path.open("w", encoding="utf-8")
            for signature, path in self._label_paths.items()
        }
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._fh is not None:
            self._fh.close()
        for fh in self._label_fhs.values():
            fh.close()

    def update(self, event: Event) -> None:
        if self._fh is None:
            return
        signature = _normalize_signature(event.signature)
        if signature not in RISK_SIGNATURES:
            return
        line = json.dumps(_event_timeline_row(event), ensure_ascii=False)
        self._fh.write(line)
        self._fh.write("\n")

        label_fh = self._label_fhs.get(signature)
        if label_fh is not None:
            label_fh.write(line)
            label_fh.write("\n")


def _update_time_window(row: dict[str, Any], timestamp: str | None) -> None:
    if not timestamp:
        return
    if row["first_seen"] is None or timestamp < row["first_seen"]:
        row["first_seen"] = timestamp
    if row["last_seen"] is None or timestamp > row["last_seen"]:
        row["last_seen"] = timestamp


def _new_timeline_bucket() -> dict[str, Any]:
    return {
        "event_count": 0,
        "first_seen": None,
        "last_seen": None,
        "stages": defaultdict(_new_stage_bucket),
    }


def _new_stage_bucket() -> dict[str, Any]:
    return {
        "event_count": 0,
        "first_seen": None,
        "last_seen": None,
    }


def _stage_name(event: Event) -> str:
    return (event.stage or "").strip() or "Unknown"


def _timeline_bucket_to_dict(bucket: dict[str, Any]) -> dict[str, Any]:
    stages = bucket.get("stages", {})
    return {
        "event_count": bucket["event_count"],
        "first_seen": bucket["first_seen"],
        "last_seen": bucket["last_seen"],
        "stages": {
            stage: {
                "event_count": stage_bucket["event_count"],
                "first_seen": stage_bucket["first_seen"],
                "last_seen": stage_bucket["last_seen"],
            }
            for stage, stage_bucket in sorted(stages.items())
        },
    }


class TimelineSummaryState:
    def __init__(self) -> None:
        self.buckets: dict[str, dict[str, Any]] = defaultdict(_new_timeline_bucket)

    def update(self, event: Event) -> None:
        signature = _normalize_signature(event.signature)
        if signature not in RISK_SIGNATURES:
            return

        bucket = self.buckets[signature]
        bucket["event_count"] += 1
        _update_time_window(bucket, event.timestamp)

        stage_bucket = bucket["stages"][_stage_name(event)]
        stage_bucket["event_count"] += 1
        _update_time_window(stage_bucket, event.timestamp)

    def finalize(self) -> list[dict[str, Any]]:
        rows = []
        for signature in ["AA", "SH", "APT"]:
            bucket = self.buckets.get(signature, _new_timeline_bucket())
            row = _timeline_bucket_to_dict(bucket)
            row["signature"] = signature
            rows.append(row)
        return rows


SCORING_MODEL = {
    "formula": "risk_score = likelihood_score * impact_score * 4",
    "score_scale": "0-100",
    "likelihood_scale": "0-5",
    "impact_scale": "0-5",
    "likelihood_inputs": [
        "Offensive Pressure",
        "Defense Gap",
        "Threat Actor Pressure",
        "Evidence Volume",
        "Stage Coverage",
        "Activity Diversity",
    ],
    "impact_inputs": [
        "Signature Impact",
        "Affected Scope",
        "Attack Stage Impact",
        "Log Type Impact",
    ],
}


def _summary_payload(
    total_events: int,
    scenarios: list[ScenarioInstance],
    risk_scores: list[dict],
    timeline_summary: list[dict[str, Any]] | None = None,
    factor_meanings: dict[str, str] | None = None,
) -> dict:
    scenario_rows = []
    for scenario in scenarios:
        scenario_rows.append(asdict(scenario))

    return {
        "counts": {
            "events": total_events,
            "scenarios": len(scenarios),
        },
        "scenarios": scenario_rows,
        "risk_scores": risk_scores,
        "factor_meanings": factor_meanings or {},
        "timeline_summary": timeline_summary or [],
        "scoring_model": SCORING_MODEL,
    }


def write_reports(
    output_dir: Path,
    total_events: int,
    scenarios: list[ScenarioInstance],
    risk_scores: list[dict],
    timeline_summary: list[dict[str, Any]] | None = None,
    factor_meanings: dict[str, str] | None = None,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "summary.json"
    summary = _summary_payload(
        total_events=total_events,
        scenarios=scenarios,
        risk_scores=risk_scores,
        timeline_summary=timeline_summary,
        factor_meanings=factor_meanings,
    )
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary_path
