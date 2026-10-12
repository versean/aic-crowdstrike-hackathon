"""Frontend adapter for the current AlertLens backend outputs and local analyst."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from blueteam import llm  # noqa: E402

DATA_DIR = Path(os.getenv("ALERTLENS_DATA_DIR", str(ROOT / "data"))).expanduser()
REQUIRED_ARTIFACTS = (
    "meta_explained.parquet",
    "incidents.json",
    "metrics_summary.csv",
    "metrics_by_scenario.csv",
    "feature_importance.csv",
    "stats.json",
)


def backend_status(data_dir: Path | None = None) -> dict:
    data_dir = Path(data_dir or DATA_DIR).expanduser().resolve()
    missing = [name for name in REQUIRED_ARTIFACTS if not (data_dir / name).is_file()]
    ollama_base = llm.OLLAMA_URL.rsplit("/api/", 1)[0]
    model_ready = False
    try:
        response = requests.get(f"{ollama_base}/api/tags", timeout=0.8)
        ollama_online = response.ok
        if response.ok:
            names = [item.get("name", "") for item in response.json().get("models", [])]
            model_ready = llm.MODEL in names or f"{llm.MODEL}:latest" in names
    except (requests.RequestException, ValueError):
        ollama_online = False
    return {
        "ready": not missing,
        "missing": missing,
        "data_dir": data_dir,
        "ollama_online": ollama_online,
        "model_ready": model_ready,
        "model": llm.MODEL,
    }


def load_results(data_dir: Path | None = None) -> dict:
    data_dir = Path(data_dir or DATA_DIR).expanduser().resolve()
    meta = pd.read_parquet(data_dir / "meta_explained.parquet")
    meta["start_dt"] = pd.to_datetime(meta["start"], unit="s", utc=True)
    meta["end_dt"] = pd.to_datetime(meta["end"], unit="s", utc=True)

    incidents = pd.DataFrame(json.loads((data_dir / "incidents.json").read_text()))
    incidents["start_dt"] = pd.to_datetime(incidents["start"], unit="s", utc=True)
    incidents["end_dt"] = pd.to_datetime(incidents["end"], unit="s", utc=True)

    labels_path = data_dir.parent / "labels.csv"
    labels = pd.read_csv(labels_path) if labels_path.exists() else pd.DataFrame()
    if not labels.empty:
        labels["start_dt"] = pd.to_datetime(labels["start"], unit="s", utc=True)
        labels["end_dt"] = pd.to_datetime(labels["end"], unit="s", utc=True)

    optional = data_dir / "narratives.json"
    narratives = json.loads(optional.read_text()) if optional.exists() else {}
    return {
        "meta": meta,
        "incidents": incidents,
        "summary": pd.read_csv(data_dir / "metrics_summary.csv", index_col=0),
        "by_network": pd.read_csv(data_dir / "metrics_by_scenario.csv"),
        "importance": pd.read_csv(data_dir / "feature_importance.csv", index_col=0),
        "stats": json.loads((data_dir / "stats.json").read_text()),
        "labels": labels,
        "narratives": narratives,
    }


def incident_context(meta: pd.DataFrame, incident: dict) -> str:
    return llm.incident_context(meta, incident)


def generate_report(context: str):
    return llm.narrate(context, stream=True)


def ask_analyst(context: str, question: str, history=()):
    return llm.ask(context, question, history=history, stream=True)


def workspace_context(meta: pd.DataFrame, incidents: pd.DataFrame, network: str, page: str) -> str:
    """Bounded evidence from the active network, refreshed on every page/filter change."""
    flagged = meta[meta["score_model"] >= 0.5]
    lines = [
        "PRECOMPUTED AIT-ADS EVALUATION SNAPSHOT. This is not live telemetry.",
        f"Selected network: {network}. Open page: {page}.",
        f"Raw alerts: {int(meta['n_alerts'].sum())}; grouped alerts: {len(meta)}; "
        f"groups scoring >=0.5: {len(flagged)}; incidents: {len(incidents)}.",
        f"Evidence period (UTC): {meta['start_dt'].min()} to {meta['end_dt'].max()}.",
        "Top ranked evidence (subset; not a full inventory):",
    ]
    columns = ["scenario", "incident_id", "start_dt", "host", "src_ip", "source", "rule_desc", "score_model", "pred_stage"]
    lines.append(meta.sort_values("score_model", ascending=False).head(10)[columns].to_json(orient="records", date_format="iso"))
    if not incidents.empty:
        lines.append("Top incidents:\n" + incidents.sort_values("risk", ascending=False).head(3)[
            ["scenario", "incident_id", "risk", "hosts", "stages"]
        ].to_json(orient="records"))
    return "\n".join(lines)
