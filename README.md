# Unraveled Risk Analyzer

A basic risk scenario reconstruction tool for labeled network security logs from the UNRAVELED dataset.

The project focuses on **label-driven risk scenario reconstruction**. It does not detect new attacks from raw logs. Instead, it uses existing labels such as `Signature`, `Activity`, `Stage`, and `DefenderResponse` to group related events, rebuild attack chains, list affected assets, and calculate risk scores.

## Scope

This project focuses on:

- Reading labeled dataset files.
- Grouping events by `Signature` and log type.
- Reconstructing risk scenarios for `AA`, `SH`, and `APT`.
- Building attack chains from `Stage` and `Activity`.
- Listing affected hosts and IP addresses.
- Summarizing labeled defender responses.
- Calculating `risk_scores` with weighted risk scoring.

This project does not focus on:

- Detecting new attack behavior.
- Anomaly detection.
- Machine learning model training.
- Rule-based behavioral detection in the main pipeline.

## Project Structure

```text
unraveled-risk-analyzer/
|-- main.py
|-- data/
|   |-- scenarios.json
|   |-- host/
|   `-- network/
|-- src/
|   |-- models.py
|   |-- loader.py
|   |-- matcher.py
|   |-- scoring.py
|   `-- report.py
|-- tests/
`-- README.md
```

## Pipeline

```text
Labeled dataset
  -> Stream input files by chunks
  -> Normalize raw records to Event
  -> Match labeled events to scenario definitions
  -> Reconstruct attack chain and affected assets
  -> Score risk by Signature + log type
  -> Write summary JSON and full risk timeline JSONL
```

## Running the Program

The program always runs in streaming mode. It reads events by chunk, processes them immediately, and does not keep the full dataset in memory.

Install dependencies:

```powershell
pip install -r requirements.txt
```

Run the default dataset and write reports to `reports`:

```powershell
python main.py
```

Run a custom dataset and output directory:

```powershell
python main.py --dataset data --output reports
```

Useful options:

- `--dataset`: dataset root path.
- `--output`: report output directory.
- `--help`: show command-line help.

## Output

The program writes these files to the report directory:

- `summary.json`: scenario summary and `risk_scores` matrix.
- `timeline_full.jsonl`: full timeline of risk events with signatures `AA`, `SH`, and `APT`; each line is one JSON object.
- `timeline_AA.jsonl`, `timeline_SH.jsonl`, `timeline_APT.jsonl`: per-label risk timelines with the same row format as `timeline_full.jsonl`.

`timeline_full.jsonl` only includes events whose `Signature` is `AA`, `SH`, or `APT`. Events with `None`, `Unknown`, or other signatures are not included in the risk timeline.

Important fields in each scenario inside `summary.json`:

- `scenario_id`, `scenario_type`, `signature`, `log_type`.
- `matched_event_ids`: sampled matched event IDs with relative source file paths, capped at 20 per scenario.
- `metadata.attack_chain`: attack chain built from `Stage` and `Activity`.
- `metadata.affected_assets`: affected hosts and IP addresses.
- `metadata.source_ips`, `metadata.destination_ips`: related source and destination IP addresses.
- `metadata.defender_responses`: response counts such as `Detected`, `Mitigated`, and `Benign`.

Additional top-level fields in `summary.json`:

- `timeline_summary`: per-signature timeline summary with event counts, first/last seen timestamps, and per-stage timing.
- `scoring_model`: formula, score scales, and likelihood/impact inputs used to explain the risk scoring output.
- `factor_meanings`: descriptions for A1-A5, D1-D5, and T1.

## Risk Scoring

The project uses structured risk scoring. It does not use machine learning.

Risk scores are calculated by:

```text
Risk = Likelihood x Impact
```

The `risk_scores` output contains up to six rows:

- `AA-host`
- `AA-network`
- `SH-host`
- `SH-network`
- `APT-host`
- `APT-network`

`likelihood_score` and `impact_score` use a 1-5 scale. `risk_score` is scaled to 0-100:

```text
risk_score = likelihood_score * impact_score * 4
```

Likelihood combines Appendix A risk-factor definitions with observed log evidence:

- `A1-A5`: offensive factors such as attacker expertise, system knowledge, tools, elapsed time, and window of opportunity.
- `D1-D5`: defensive factors such as monitoring, vulnerability management, log management, security awareness, and incident response.
- `T1`: threat actor factor.
- Evidence observed in logs: event volume, stage coverage, and activity diversity.

The factor names come from Appendix A1. Factor values are calculated dynamically for every `Signature + log_type` group, so `AA`, `SH`, and `APT` are all scored with the same rubric.

Some defensive factors cannot be directly observed from the available logs. For those fields, the scorer uses a neutral value and only adjusts factors that can be inferred from log evidence, such as monitoring/detection and incident response signals from `DefenderResponse`.

Impact is calculated from observed risk context:

- Signature type: `AA`, `SH`, or `APT`.
- Log type: `host` or `network`.
- Affected asset and IP scope.
- Attack stage severity, for example lateral movement, exfiltration, or impact stages.

Appendix A factor names are included once in `summary.json` through the top-level `factor_meanings` field.

Each scoring row includes:

- `likelihood_score`, `impact_score`, `risk_score`, and `severity`.
- `factor_scores`: raw A/D/T factor scores on a 0-10 scale.
- `risk_factors`: normalized scoring inputs used to calculate likelihood and impact.

## Tests

Run all tests:

```powershell
pytest -q
```

The test suite covers:

- Loader behavior for CSV, text logs, JSON, and Windows logs.
- Matcher behavior and attack chain reconstruction.
- Affected asset extraction.
- Risk scoring.
- JSONL timeline filtering for risk signatures.
