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
from blueteam.ingest import DATA_DIR as DEFAULT_DATA_DIR  # noqa: E402

DATA_DIR = Path(os.getenv("ALERTLENS_DATA_DIR", str(DEFAULT_DATA_DIR))).expanduser()
REQUIRED_ARTIFACTS = (
    "meta_explained.parquet",
    "incidents.json",
    "metrics_summary.csv",
    "metrics_by_scenario.csv",
    "feature_importance.csv",
    "stats.json",
)


def backend_status() -> dict:
    missing = [name for name in REQUIRED_ARTIFACTS if not (DATA_DIR / name).is_file()]
    ollama_base = llm.OLLAMA_URL.rsplit("/api/", 1)[0]
    try:
        response = requests.get(f"{ollama_base}/api/tags", timeout=0.8)
        ollama_online = response.ok
    except requests.RequestException:
        ollama_online = False
    return {
        "ready": not missing,
        "missing": missing,
        "data_dir": DATA_DIR,
        "ollama_online": ollama_online,
        "model": llm.MODEL,
    }


def load_results() -> dict:
    meta = pd.read_parquet(DATA_DIR / "meta_explained.parquet")
    meta["start_dt"] = pd.to_datetime(meta["start"], unit="s", utc=True)
    meta["end_dt"] = pd.to_datetime(meta["end"], unit="s", utc=True)

    incidents = pd.DataFrame(json.loads((DATA_DIR / "incidents.json").read_text()))
    incidents["start_dt"] = pd.to_datetime(incidents["start"], unit="s", utc=True)
    incidents["end_dt"] = pd.to_datetime(incidents["end"], unit="s", utc=True)

    labels_path = DATA_DIR.parent / "labels.csv"
    labels = pd.read_csv(labels_path) if labels_path.exists() else pd.DataFrame()
    if not labels.empty:
        labels["start_dt"] = pd.to_datetime(labels["start"], unit="s", utc=True)
        labels["end_dt"] = pd.to_datetime(labels["end"], unit="s", utc=True)

    optional = DATA_DIR / "narratives.json"
    narratives = json.loads(optional.read_text()) if optional.exists() else {}
    return {
        "meta": meta,
        "incidents": incidents,
        "summary": pd.read_csv(DATA_DIR / "metrics_summary.csv", index_col=0),
        "by_network": pd.read_csv(DATA_DIR / "metrics_by_scenario.csv"),
        "importance": pd.read_csv(DATA_DIR / "feature_importance.csv", index_col=0),
        "stats": json.loads((DATA_DIR / "stats.json").read_text()),
        "labels": labels,
        "narratives": narratives,
    }


def incident_context(meta: pd.DataFrame, incident: dict) -> str:
    return llm.incident_context(meta, incident)


def generate_report(context: str):
    return llm.narrate(context, stream=True)


def ask_analyst(context: str, question: str, history=()):
    return llm.ask(context, question, history=history, stream=True)
