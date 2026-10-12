# aic-crowdstrike-hackathon

## Track 2 dashboard

Run the AlertLens Streamlit dashboard from the repository root:

```sh
pip install -r frontend/requirements.txt
streamlit run frontend/app.py
```

The dashboard reads the precomputed model results in `data/` and `labels.csv`. Incident report generation and analyst chat use a local Ollama server at `http://localhost:11434` with the `qwen3:14b` model.
