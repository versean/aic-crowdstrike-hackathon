# AlertLens · AI security operations workspace

AlertLens ranks and explains AIT-ADS security alerts, groups them into incidents, and presents an analyst workspace with local AI chat and reports.

From the repository root:

```sh
./frontend/scripts/start-local.sh
```

This sets up the frontend and the small local Qwen3 test model through Ollama, verifies inference, and opens a Streamlit service at **http://127.0.0.1:8501**. Install [Ollama](https://ollama.com/download) first if it is not available on your machine.

See the [frontend README](frontend/README.md) for setup without AI, configuration, the cyberpunk-inspired interface, automatic light and dark appearance, the persistent security assistant, and verification commands. The dashboard uses the saved exports in `data/`; it is an evaluation workspace rather than a live security feed.
