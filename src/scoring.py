from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from .models import Event

RISK_SIGNATURES = {"AA", "SH", "APT"}

FACTOR_MEANINGS = {
    "A1": "Specialist expertise",
    "A2": "Knowledge of the system",
    "A3": "Equipment and tools",
    "A4": "Elapsed time",
    "A5": "Window of opportunity",
    "D1": "Security monitoring",
    "D2": "Vulnerability management",
    "D3": "Log management",
    "D4": "Security awareness training",
    "D5": "Incident response plan",
    "T1": "Threat actor",
}

LIKELIHOOD_WEIGHTS = {
    "Offensive Pressure": 0.25,
    "Defense Gap": 0.20,
    "Threat Actor Pressure": 0.15,
    "Evidence Volume": 0.20,
    "Stage Coverage": 0.10,
    "Activity Diversity": 0.10,
}

IMPACT_WEIGHTS = {
    "Signature Impact": 0.35,
    "Affected Scope": 0.25,
    "Attack Stage Impact": 0.30,
    "Log Type Impact": 0.10,
}

SIGNATURE_BASE = {
    "AA": {"A1": 3.0, "A3": 3.0, "T1": 2.0, "impact": 6.0},
    "SH": {"A1": 5.0, "A3": 5.0, "T1": 4.0, "impact": 8.0},
    "APT": {"A1": 8.0, "A3": 8.0, "T1": 8.0, "impact": 10.0},
}

STAGE_IMPACT = {
    "reconnaissance": 2.0,
    "initial access": 5.0,
    "establish foothold": 6.0,
    "execution": 6.0,
    "persistence": 7.0,
    "privilege escalation": 8.0,
    "defense evasion": 7.0,
    "credential access": 7.0,
    "discovery": 4.0,
    "lateral movement": 8.0,
    "collection": 8.0,
    "command and control": 8.0,
    "exfiltration": 10.0,
    "impact": 10.0,
    "maintain access": 7.0,
}

def _normalize_signature(value: str | None) -> str:
    return (value or "").strip().upper()


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _clamp(value: float, low: float = 0.0, high: float = 10.0) -> float:
    return min(max(value, low), high)


def _score_10_to_5(value: float) -> float:
    return round(_clamp(value) / 2.0, 2)


def _weighted_average(values: dict[str, float], weights: dict[str, float]) -> float:
    return sum(_clamp(values.get(key, 0.0)) * weight for key, weight in weights.items())


def _severity(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _evidence_level(count: int) -> float:
    if count >= 500:
        return 10.0
    if count >= 200:
        return 8.0
    if count >= 80:
        return 6.0
    if count >= 20:
        return 4.0
    if count > 0:
        return 2.0
    return 0.0


def _coverage_level(count: int) -> float:
    if count >= 5:
        return 10.0
    if count >= 4:
        return 8.0
    if count >= 3:
        return 6.0
    if count >= 2:
        return 4.0
    if count == 1:
        return 2.0
    return 0.0


def _scope_level(*counts: int) -> float:
    scope = max(counts or (0,))
    if scope >= 20:
        return 10.0
    if scope >= 10:
        return 8.0
    if scope >= 5:
        return 6.0
    if scope >= 2:
        return 4.0
    if scope >= 1:
        return 2.0
    return 0.0


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _elapsed_level(first_seen: str | None, last_seen: str | None, event_count: int) -> float:
    first = _parse_timestamp(first_seen)
    last = _parse_timestamp(last_seen)
    if first is not None and last is not None:
        hours = max((last - first).total_seconds() / 3600.0, 0.0)
        if hours >= 72:
            return 10.0
        if hours >= 24:
            return 8.0
        if hours >= 6:
            return 6.0
        if hours >= 1:
            return 4.0
        if hours > 0:
            return 2.0
    return _evidence_level(event_count)


def _defender_response_levels(responses: Counter[str]) -> dict[str, float]:
    detected = responses.get("detected", 0)
    mitigated = responses.get("mitigated", 0)
    benign = responses.get("benign", 0)
    total = detected + mitigated + benign
    if total == 0:
        return {
            "D1": 5.0,
            "D5": 5.0,
        }

    detection_ratio = (detected + mitigated) / total
    mitigation_ratio = mitigated / total
    benign_ratio = benign / total
    return {
        "D1": _clamp((detection_ratio * 10.0) - (benign_ratio * 2.0)),
        "D5": _clamp((mitigation_ratio * 10.0) + (detection_ratio * 4.0)),
    }


def _max_stage_impact(stages: Counter[str]) -> float:
    return max(
        [STAGE_IMPACT.get(stage.strip().lower(), 3.0) for stage in stages]
        or [0.0]
    )


def _signature_impact(signature: str) -> float:
    return SIGNATURE_BASE[_normalize_signature(signature)]["impact"]


def _log_type_impact(log_type: str) -> float:
    return 6.0 if log_type == "network" else 5.0


def _dynamic_factor_scores(
    signature: str,
    event_count: int,
    stages: Counter[str],
    activities: Counter[str],
    responses: Counter[str],
    affected_scope: float,
    first_seen: str | None,
    last_seen: str | None,
) -> dict[str, float]:
    base = SIGNATURE_BASE[signature]
    evidence = _evidence_level(event_count)
    stage_coverage = _coverage_level(len(stages))
    activity_diversity = _coverage_level(len(activities))
    defender = _defender_response_levels(responses)

    return {
        "A1": base["A1"],
        "A2": round(_mean([stage_coverage, activity_diversity, affected_scope]), 2),
        "A3": round(max(base["A3"], activity_diversity), 2),
        "A4": _elapsed_level(first_seen, last_seen, event_count),
        "A5": round(max(evidence, affected_scope), 2),
        "D1": round(defender["D1"], 2),
        "D2": 5.0,
        "D3": round(max(evidence, stage_coverage, activity_diversity), 2),
        "D4": 5.0,
        "D5": round(defender["D5"], 2),
        "T1": base["T1"],
    }


def _base_factor_scores(factor_scores: dict[str, float]) -> dict[str, float]:
    offensive = _mean([factor_scores[f"A{i}"] for i in range(1, 6)])
    defensive = _mean([factor_scores[f"D{i}"] for i in range(1, 6)])
    threat = factor_scores["T1"]
    return {
        "Offensive Pressure": offensive,
        "Defensive Strength": defensive,
        "Defense Gap": 10.0 - defensive,
        "Threat Actor Pressure": threat,
    }


def _risk_row(
    signature: str,
    log_type: str,
    event_count: int,
    stages: Counter[str],
    activities: Counter[str],
    responses: Counter[str],
    host_count: int,
    src_ip_count: int,
    dst_ip_count: int,
    first_seen: str | None,
    last_seen: str | None,
) -> dict[str, Any]:
    affected_scope = (
        _scope_level(host_count)
        if log_type == "host"
        else _scope_level(src_ip_count, dst_ip_count)
    )
    factor_scores = _dynamic_factor_scores(
        signature=signature,
        event_count=event_count,
        stages=stages,
        activities=activities,
        responses=responses,
        affected_scope=affected_scope,
        first_seen=first_seen,
        last_seen=last_seen,
    )
    base_factors = _base_factor_scores(factor_scores)

    evidence_volume = _evidence_level(event_count)
    stage_coverage = _coverage_level(len(stages))
    activity_diversity = _coverage_level(len(activities))
    attack_stage_impact = _max_stage_impact(stages)
    signature_impact = _signature_impact(signature)
    log_type_impact = _log_type_impact(log_type)

    likelihood_inputs = {
        "Offensive Pressure": base_factors["Offensive Pressure"],
        "Defense Gap": base_factors["Defense Gap"],
        "Threat Actor Pressure": base_factors["Threat Actor Pressure"],
        "Evidence Volume": evidence_volume,
        "Stage Coverage": stage_coverage,
        "Activity Diversity": activity_diversity,
    }
    impact_inputs = {
        "Signature Impact": signature_impact,
        "Affected Scope": affected_scope,
        "Attack Stage Impact": attack_stage_impact,
        "Log Type Impact": log_type_impact,
    }

    likelihood_10 = _weighted_average(likelihood_inputs, LIKELIHOOD_WEIGHTS)
    impact_10 = _weighted_average(impact_inputs, IMPACT_WEIGHTS)
    likelihood_score = _score_10_to_5(likelihood_10)
    impact_score = _score_10_to_5(impact_10)
    risk_score = round(likelihood_score * impact_score * 4.0, 2) if event_count else 0.0

    risk_factors = {
        **{key: _score_10_to_5(value) for key, value in base_factors.items()},
        "Evidence Volume": _score_10_to_5(evidence_volume),
        "Stage Coverage": _score_10_to_5(stage_coverage),
        "Activity Diversity": _score_10_to_5(activity_diversity),
        "Signature Impact": _score_10_to_5(signature_impact),
        "Affected Scope": _score_10_to_5(affected_scope),
        "Attack Stage Impact": _score_10_to_5(attack_stage_impact),
        "Log Type Impact": _score_10_to_5(log_type_impact),
    }

    return {
        "signature": signature,
        "log_type": log_type,
        "event_count": event_count,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "likelihood_score": likelihood_score if event_count else 0.0,
        "impact_score": impact_score if event_count else 0.0,
        "risk_score": risk_score,
        "severity": _severity(risk_score) if event_count else "No Evidence",
        "factor_scores": {k: round(v, 2) for k, v in factor_scores.items()},
        "risk_factors": risk_factors,
        "defender_responses": dict(sorted(responses.items())),
    }


class LabelLogScoringState:
    def __init__(self) -> None:
        self.counts: Counter[tuple[str, str]] = Counter()
        self.responses: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        self.stages: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        self.activities: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        self.hosts: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        self.src_ips: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        self.dst_ips: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        self.first_seen: dict[tuple[str, str], str] = {}
        self.last_seen: dict[tuple[str, str], str] = {}

    def _update_time_window(self, key: tuple[str, str], timestamp: str | None) -> None:
        if not timestamp:
            return
        if key not in self.first_seen or timestamp < self.first_seen[key]:
            self.first_seen[key] = timestamp
        if key not in self.last_seen or timestamp > self.last_seen[key]:
            self.last_seen[key] = timestamp

    def update(self, event: Event) -> None:
        signature = _normalize_signature(event.signature)
        if signature not in RISK_SIGNATURES:
            return

        source_type = (event.source_type or "").strip().lower()
        log_type = "network" if source_type == "network" else "host"
        key = (signature, log_type)
        self.counts[key] += 1
        self.responses[key][(event.defender_response or "").lower()] += 1
        self._update_time_window(key, event.timestamp)
        if event.stage:
            self.stages[key][event.stage] += 1
        if event.activity:
            self.activities[key][event.activity] += 1
        if event.host:
            self.hosts[key][event.host] += 1
        if event.src_ip:
            self.src_ips[key][event.src_ip] += 1
        if event.dst_ip:
            self.dst_ips[key][event.dst_ip] += 1

    def finalize(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for signature in ["AA", "SH", "APT"]:
            for log_type in ["host", "network"]:
                key = (signature, log_type)
                results.append(
                    _risk_row(
                        signature=signature,
                        log_type=log_type,
                        event_count=self.counts[key],
                        stages=self.stages[key],
                        activities=self.activities[key],
                        responses=self.responses[key],
                        host_count=len(self.hosts[key]),
                        src_ip_count=len(self.src_ips[key]),
                        dst_ip_count=len(self.dst_ips[key]),
                        first_seen=self.first_seen.get(key),
                        last_seen=self.last_seen.get(key),
                    )
                )

        return results
