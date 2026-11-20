from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Event:
    event_id: str
    source_type: str
    source_file: str
    raw_message: str
    timestamp: str | None = None
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    activity: str | None = None
    stage: str | None = None
    defender_response: str | None = None
    signature: str | None = None


@dataclass(slots=True)
class ScenarioDefinition:
    scenario_id: str
    scenario_type: str
    signature: str
    log_type: str
    required_any: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScenarioInstance:
    scenario_id: str
    scenario_type: str
    signature: str
    log_type: str
    matched_event_ids: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)
