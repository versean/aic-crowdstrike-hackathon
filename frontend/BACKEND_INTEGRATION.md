# AlertLens frontend integration

The Streamlit frontend reads the backend's exported results directly and calls `blueteam.llm` for local Ollama reports and chat. It visualizes the Track 2 flow (sample alerts → grouped and ranked evidence → incidents → analyst review), but does not trigger raw-data ingestion or model scoring. The `alertlens` backend is a local pipeline rather than an HTTP API. Set `ALERTLENS_DATA_DIR` before starting the frontend or enter the backend checkout's `data/` folder under **Backend results folder** in the sidebar, then choose **Connect / refresh results** after a pipeline run.

`ALERTLENS_DATA_DIR` defaults to the repository's `data/` directory. Required files:

- `meta_explained.parquet`
- `incidents.json`
- `metrics_summary.csv`
- `metrics_by_scenario.csv`
- `feature_importance.csv`
- `stats.json`

Optional files are `labels.csv` beside the data directory and `narratives.json` inside it. Alert and incident timestamps are interpreted as UTC Unix seconds. Alert rows carry scenario, incident ID, source, host, rule description, model score, predicted stage and explanation fields.

`frontend/backend_client.py` handles loading, readiness checks and bounded workspace chat context. `blueteam/llm.py` handles streamed Ollama calls with `OLLAMA_URL` and `OLLAMA_MODEL`; defaults are `http://127.0.0.1:11434/api/chat` and `qwen3:0.6b`. Readiness distinguishes an available service from an installed model. API failures remain visible and can be retried without restarting the app.

Saved-data exploration works without Ollama. Global chat follows the active network and includes the selected incident on the investigation page. Existing incident-specific chat is retained. Neither chat changes backend results or executes remediation.

For setup and testing, see [README.md](README.md).
