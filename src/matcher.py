from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .models import Event, ScenarioDefinition, ScenarioInstance


def load_scenarios(path: Path) -> list[ScenarioDefinition]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("scenarios", payload)
    result: list[ScenarioDefinition] = []

    for row in rows:
        result.append(
            ScenarioDefinition(
                scenario_id=row["scenario_id"],
                scenario_type=row["scenario_type"],
                signature=row["signature"],
                log_type=row["log_type"],
                required_any=row.get("required_any", []),
            )
        )
    return result


def _label_text(event: Event) -> str:
    return " ".join(
        [
            event.activity or "",
            event.stage or "",
            event.defender_response or "",
            event.signature or "",
        ]
    ).lower()


def _full_event_text(event: Event) -> str:
    return f"{_label_text(event)} {event.raw_message}".lower()


def _matches_rule(event: Event, rule_tokens: list[str]) -> bool:
    tokens = [token.lower() for token in rule_tokens if token.strip()]
    if not tokens:
        return True

    label_text = _label_text(event)
    if any(token in label_text for token in tokens):
        return True

    return any(token in _full_event_text(event) for token in tokens)


def _counter_to_dict(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items()))


def _counter_values(counter: Counter[str], limit: int = 20) -> list[str]:
    return [value for value, _ in counter.most_common(limit)]


def _event_value(value: str | None) -> str | None:
    value = (value or "").strip()
    return value or None


STAGE_ORDER = {
    "reconnaissance": 10,
    "initial access": 20,
    "establish foothold": 30,
    "execution": 40,
    "persistence": 50,
    "privilege escalation": 60,
    "defense evasion": 70,
    "credential access": 80,
    "discovery": 90,
    "lateral movement": 100,
    "collection": 110,
    "command and control": 120,
    "exfiltration": 130,
    "impact": 140,
    "maintain access": 150,
}


def _new_accumulator() -> dict[str, Any]:
    return {
        "matched_events": 0,
        "stages": Counter(),
        "activities": Counter(),
        "defender_responses": Counter(),
        "hosts": Counter(),
        "src_ips": Counter(),
        "dst_ips": Counter(),
        "attack_steps": {},
    }


def _step_key(event: Event) -> tuple[str, str]:
    return (_event_value(event.stage) or "Unknown", _event_value(event.activity) or "Unknown")


def _new_step(stage: str, activity: str, sequence: int) -> dict[str, Any]:
    return {
        "stage": stage,
        "activity": activity,
        "sequence": sequence,
        "event_count": 0,
        "defender_responses": Counter(),
        "hosts": Counter(),
        "src_ips": Counter(),
        "dst_ips": Counter(),
        "from_time": None,
        "to_time": None,
    }


def _update_time_window(step: dict[str, Any], timestamp: str | None) -> None:
    if not timestamp:
        return

    if step["from_time"] is None or timestamp < step["from_time"]:
        step["from_time"] = timestamp
    if step["to_time"] is None or timestamp > step["to_time"]:
        step["to_time"] = timestamp


def _update_step(step: dict[str, Any], event: Event) -> None:
    step["event_count"] += 1
    _update_time_window(step, event.timestamp)

    for key, value in [
        ("defender_responses", event.defender_response),
        ("hosts", event.host),
        ("src_ips", event.src_ip),
        ("dst_ips", event.dst_ip),
    ]:
        normalized = _event_value(value)
        if normalized is not None:
            step[key][normalized] += 1


def _update_accumulator(accumulator: dict[str, Any], event: Event) -> None:
    accumulator["matched_events"] += 1
    for key, value in [
        ("stages", event.stage),
        ("activities", event.activity),
        ("defender_responses", event.defender_response),
        ("hosts", event.host),
        ("src_ips", event.src_ip),
        ("dst_ips", event.dst_ip),
    ]:
        normalized = _event_value(value)
        if normalized is not None:
            accumulator[key][normalized] += 1

    key = _step_key(event)
    steps = accumulator["attack_steps"]
    if key not in steps:
        steps[key] = _new_step(stage=key[0], activity=key[1], sequence=len(steps))
    _update_step(steps[key], event)


def _stage_sort_key(stage: str) -> int:
    return STAGE_ORDER.get(stage.strip().lower(), 10_000)


def _step_to_dict(step: dict[str, Any], index: int) -> dict[str, Any]:
    affected_assets = Counter()
    affected_assets.update(step["hosts"])
    affected_assets.update(step["dst_ips"])

    return {
        "step": index,
        "stage": step["stage"],
        "activity": step["activity"],
        "event_count": step["event_count"],
        "from_time": step["from_time"],
        "to_time": step["to_time"],
        "defender_responses": _counter_to_dict(step["defender_responses"]),
        "affected_assets": _counter_values(affected_assets),
        "source_ips": _counter_values(step["src_ips"]),
        "destination_ips": _counter_values(step["dst_ips"]),
    }


def _build_attack_chain(accumulator: dict[str, Any]) -> list[dict[str, Any]]:
    steps = list(accumulator["attack_steps"].values())
    steps.sort(
        key=lambda step: (
            _stage_sort_key(step["stage"]),
            step["from_time"] or "",
            step["sequence"],
        )
    )
    return [_step_to_dict(step, index + 1) for index, step in enumerate(steps)]


def _build_metadata(accumulator: dict[str, Any]) -> dict[str, Any]:
    affected_assets = accumulator["hosts"] + accumulator["dst_ips"]
    return {
        "matched_events": accumulator["matched_events"],
        "stages": _counter_to_dict(accumulator["stages"]),
        "activities": _counter_to_dict(accumulator["activities"]),
        "defender_responses": _counter_to_dict(accumulator["defender_responses"]),
        "host_count": len(accumulator["hosts"]),
        "src_ip_count": len(accumulator["src_ips"]),
        "dst_ip_count": len(accumulator["dst_ips"]),
        "affected_assets": _counter_values(affected_assets),
        "source_ips": _counter_values(accumulator["src_ips"]),
        "destination_ips": _counter_values(accumulator["dst_ips"]),
        "attack_chain": _build_attack_chain(accumulator),
    }


class MatcherState:
    def __init__(
        self,
        scenario_definitions: list[ScenarioDefinition],
        max_event_ids: int = 20,
    ) -> None:
        self.scenario_definitions = scenario_definitions
        self.max_event_ids = max_event_ids
        self.matched_counts: dict[str, int] = defaultdict(int)
        self.matched_event_ids: dict[str, list[str]] = defaultdict(list)
        self.accumulators: dict[str, dict[str, Any]] = defaultdict(_new_accumulator)

    def update(self, event: Event) -> None:
        signature = (event.signature or "").upper()
        if signature not in {"AA", "SH", "APT"}:
            return

        log_type = "network" if event.source_type == "network" else "host"
        for definition in self.scenario_definitions:
            if definition.signature.upper() != signature or definition.log_type != log_type:
                continue
            if not _matches_rule(event, definition.required_any or [definition.signature]):
                continue

            self.matched_counts[definition.scenario_id] += 1
            _update_accumulator(self.accumulators[definition.scenario_id], event)
            ids = self.matched_event_ids[definition.scenario_id]
            if len(ids) < self.max_event_ids:
                ids.append(event.event_id)

    def finalize(self) -> list[ScenarioInstance]:
        instances: list[ScenarioInstance] = []

        for definition in self.scenario_definitions:
            count = self.matched_counts.get(definition.scenario_id, 0)
            if count == 0:
                continue

            instances.append(
                ScenarioInstance(
                    scenario_id=definition.scenario_id,
                    scenario_type=definition.scenario_type,
                    signature=definition.signature,
                    log_type=definition.log_type,
                    matched_event_ids=self.matched_event_ids[definition.scenario_id],
                    metadata=_build_metadata(self.accumulators[definition.scenario_id]),
                )
            )

        return instances
