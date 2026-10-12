# AlertLens frontend integration

The current `alertlens` branch does not expose an HTTP API. The Streamlit frontend reads the backend's exported result bundle from `data/` and imports `blueteam.llm` for report generation and evidence-grounded chat through local Ollama.

The adapter expects these files under `ALERTLENS_DATA_DIR` (defaults to the repository's `data/` directory):

- `meta_explained.parquet`
- `incidents.json`
- `metrics_summary.csv`
- `metrics_by_scenario.csv`
- `feature_importance.csv`
- `stats.json`
- `labels.csv` beside the data directory (optional)
- `narratives.json` (optional)

Run from the repository root:

```sh
pip install -r frontend/requirements.txt
streamlit run frontend/app.py
```

The analyst uses the backend's configured `blueteam.llm.OLLAMA_URL` and model. Ollama is optional for browsing saved data, but required to generate new reports and chat.
