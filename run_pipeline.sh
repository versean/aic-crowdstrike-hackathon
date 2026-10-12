#!/usr/bin/env bash
# End-to-end: raw AIT-ADS JSON -> ranked, explained incidents -> dashboard.
set -euo pipefail
cd "$(dirname "$0")"
PY=.venv/bin/python

$PY -m blueteam.ingest              # 2.66M alerts -> data/alerts.parquet            (~20s)
$PY -m blueteam.features            # labels, meta-alerts, feature calcers            (~90s)
[ -f data/best_params.json ] || $PY -m blueteam.train --tune   # LOSO random search → best_params.json (~7 min)
$PY -m blueteam.train               # leave-one-network-out 5-seed LightGBM ensemble + baselines (~6 min)
$PY -m blueteam.train --ablation    # feature-group ablation                          (~10 min)
$PY -m blueteam.explain             # SHAP reasons, kill-chain stage, incidents       (~25s)
$PY -m blueteam.baseline            # learning period, baselines, per-alert score breakdown (~6 min)
$PY -m blueteam.llm                 # local LLM incident reports via Ollama           (~2 min / incident)
$PY -m blueteam.export              # outputs/ranked_alerts.csv + outputs/incident_reports.md
$PY -m blueteam.figures             # figures/*.png for the pitch
.venv/bin/streamlit run app.py
