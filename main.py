from __future__ import annotations

import argparse
import time
from pathlib import Path

from src.loader import iter_event_chunks
from src.matcher import MatcherState, load_scenarios
from src.report import TimelineJsonlWriter, TimelineSummaryState, write_reports
from src.scoring import FACTOR_MEANINGS, LabelLogScoringState

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATASET_ROOT = BASE_DIR / "data"
DEFAULT_SCENARIOS = BASE_DIR / "data" / "scenarios.json"
DEFAULT_OUTPUT_DIR = BASE_DIR / "reports"
CHUNK_SIZE = 50_000


def _validate_run_inputs(dataset_root: Path, scenarios_path: Path) -> bool:
    ok = True
    if not dataset_root.exists():
        print(f"[ERROR] Dataset not found: {dataset_root}")
        ok = False
    if not scenarios_path.exists():
        print(f"[ERROR] Scenario file not found: {scenarios_path}")
        ok = False
    return ok


def _print_run_start(dataset_root: Path, output_dir: Path) -> None:
    print()
    print("=== Starting Unraveled Risk Analyzer ===")
    print(f"Dataset : {dataset_root}")
    print(f"Output  : {output_dir}")
    print()


def _resolve_user_path(value: str) -> Path:
    path = Path(value.strip().strip('"'))
    if path.is_absolute():
        return path
    return BASE_DIR / path


def run_pipeline(dataset_root: Path, output_dir: Path) -> None:
    if not _validate_run_inputs(dataset_root, DEFAULT_SCENARIOS):
        return

    started_at = time.perf_counter()
    _print_run_start(dataset_root, output_dir)

    scenario_definitions = load_scenarios(DEFAULT_SCENARIOS)
    matcher_state = MatcherState(scenario_definitions)
    scoring_state = LabelLogScoringState()
    timeline_summary_state = TimelineSummaryState()

    total_events = 0
    with TimelineJsonlWriter(output_dir) as timeline_writer:
        for chunk in iter_event_chunks(
            dataset_root=dataset_root,
            chunk_size=CHUNK_SIZE,
        ):
            total_events += len(chunk)

            for event in chunk:
                matcher_state.update(event)
                scoring_state.update(event)
                timeline_summary_state.update(event)
                timeline_writer.update(event)

    scenarios = matcher_state.finalize()
    risk_scores = scoring_state.finalize()
    timeline_summary = timeline_summary_state.finalize()
    write_reports(
        output_dir=output_dir,
        total_events=total_events,
        scenarios=scenarios,
        risk_scores=risk_scores,
        timeline_summary=timeline_summary,
        factor_meanings=FACTOR_MEANINGS,
    )

    elapsed_seconds = time.perf_counter() - started_at
    print(f"Completed in {elapsed_seconds:.2f}s")
    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reconstruct and score labeled risk scenarios from UNRAVELED logs.",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default=str(DEFAULT_DATASET_ROOT),
        help="Dataset root path. Defaults to data.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(DEFAULT_OUTPUT_DIR),
        help="Report output directory. Defaults to reports.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_pipeline(
        dataset_root=_resolve_user_path(args.dataset),
        output_dir=_resolve_user_path(args.output),
    )


if __name__ == "__main__":
    main()
