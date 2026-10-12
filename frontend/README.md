# AlertLens frontend

A Streamlit analyst workspace for AlertLens backend results on the AIT-ADS benchmark. Six views explain the pipeline and its data, summarize ranked alerts, investigate incidents, triage and export filtered queues, compare model quality, and review detections against labeled attack windows. Lens is a local AI assistant available in a floating panel on every page, with incident-specific chat during investigations.

## Quick start with the local test model

From the repository root, install [Ollama](https://ollama.com/download), then run:

```sh
./frontend/scripts/start-local.sh
```

The launcher creates `.venv` if needed, installs frontend dependencies, starts Ollama if it is not already running, pulls `qwen3:0.6b`, runs an actual streamed inference check, and starts the dashboard at **http://127.0.0.1:8501**. Ctrl+C stops the dashboard and an Ollama server owned by the launcher. An existing Ollama server is left running.

This checkout also has an official macOS Ollama runtime and test-model weights in the ignored `.local/` directory. The launcher detects that runtime automatically. Those large files are not committed; on another machine, install Ollama first.

Qwen3 0.6B is a [523 MB test model](https://ollama.com/library/qwen3:0.6b). It is useful for verifying chat and report plumbing; its judgments require analyst review. To use a larger model:

```sh
OLLAMA_MODEL=qwen3:4b ./frontend/scripts/start-local.sh
```

## Run the dashboard without AI

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r frontend/requirements.txt
.venv/bin/streamlit run frontend/app.py --server.address 127.0.0.1
```

Ollama is optional for browsing charts, alerts, incidents, model evaluation and saved reports. New reports and chatbot answers require the configured model to be installed and the service reachable. Use **Refresh connection** after starting the service or pulling a model.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `OLLAMA_MODEL` | `qwen3:0.6b` | Local chat and report model |
| `OLLAMA_URL` | `http://127.0.0.1:11434/api/chat` | Ollama chat endpoint, including `/api/chat` |
| `ALERTLENS_DATA_DIR` | repository `data/` | Initial directory containing exported results |
| `ALERTLENS_USERNAME` | `admin` | Shared workspace login username |
| `ALERTLENS_PASSWORD` | `alertlens` | Shared workspace login password |

Set variables before starting Streamlit. No API key is required. `.env` files are not automatically loaded. The launcher checks an alternate Ollama endpoint but does not start a remote server.

The first local sign-in uses **admin / alertlens**. Before sharing the app, set your own `ALERTLENS_USERNAME` and `ALERTLENS_PASSWORD` environment variables. This is a lightweight shared-password gate for the demo, not a multi-user identity system.

## Interface

The interface uses a single redline cyberpunk visual language: graphite panels, red alert accents, cyan and amber status signals, condensed display headings, and compact instrument-style charts. Colors follow the operating system's light or dark preference automatically; there is no theme selector. Motion is limited to subtle panel entrances and respects system reduced-motion preferences. Reusable tokens and styling live in `frontend/alertlens_design.py`.

## Workspace features

- **Overview:** filter by evaluation network, inspect score and sensor distributions, follow the raw-alert-to-incident reduction funnel, read a plain-language explanation of the sample and labels, and export ranked results with explanations.
- **Pipeline & data:** follow the benchmark from source alerts through grouping, ranking and incident creation; see counts for the selected network and understand how `labels.csv` evaluates the results.
- **Incident investigations:** select a ranked incident, inspect its risk and host summary, follow the predicted kill-chain timeline, review evidence and MITRE ATT&CK mappings, generate a local AI report, and chat about that incident.
- **Alert triage:** search hosts, IPs and detections; filter by sensor and risk; adjust queue size; export the filtered queue; and suppress selected rule-and-host pairs for the current browser session. The ground-truth check shows labeled precision and a sample of labeled evidence for the visible queue.
- **Model quality:** compare AlertLens with Isolation Forest, rule rarity and Wazuh severity; review PR-AUC, top-20 precision, review burden at 90% recall, attack-phase recall, stage accuracy, feature importance and per-network results.
- **Ground truth:** overlay saved attack-phase windows on model-risk scores, inspect attack-related points, compare labeled precision at the default risk threshold, and review the highest-risk evidence for a selected network.
- **Lens workspace assistant:** ask cross-workspace questions on any page. Its evidence context follows the selected network and page, and the conversation persists across page changes for that network. Incident investigations also retain an incident-specific chat.

The frontend connects to the result bundle produced by the backend. Enter the backend checkout's `data/` folder in **Backend results folder**, then choose **Connect / refresh results**. The backend pipeline writes the files described in [BACKEND_INTEGRATION.md](BACKEND_INTEGRATION.md). The frontend does not itself run raw JSON ingestion or model scoring because the backend exposes a local pipeline, not an HTTP API. All charts and labels use the connected exports. The ground-truth view needs `labels.csv` beside the configured data directory; without it, the page explains that the optional artifact is missing. This is retrospective benchmark data, not a live telemetry feed. Queue suppressions are temporary browser-session feedback and do not retrain or modify the model.

To start with a separate backend checkout, you can also set its results folder when launching the frontend:

```sh
ALERTLENS_DATA_DIR=/absolute/path/to/alertlens/data .venv/bin/streamlit run frontend/app.py
```

The same folder can be changed in the sidebar while the app is running. After the backend finishes a pipeline run, click **Connect / refresh results** to load its newest bundle.

## Security assistant

Open **Lens / Security assistant** in the bottom-right. Ask “What needs attention?”, “Which hosts are affected?” or “What should I investigate first?” Context includes the selected network's counts, evidence period, ten highest-scored groups and three highest-ranked incidents. Investigations additionally include the selected incident's detailed evidence. Conversations persist across page changes, are separated by network, and can be cleared. Only the last eight messages are sent to the model; the UI retains up to twenty.

Inference runs on the server through Ollama, so the browser needs no Ollama CORS configuration or credentials. With the default local endpoint, evidence stays on this machine. An alternate endpoint receives the supplied evidence. Google Fonts is an external styling request; the UI also has fallback fonts.

The data is **a saved evaluation snapshot, not live telemetry**. Scores rank evidence and do not establish current compromise, safety or remediation. Triage suppressions affect only the browser session. The assistant suggests investigation steps and does not execute security actions.

## Data and verification

See [BACKEND_INTEGRATION.md](BACKEND_INTEGRATION.md) for the artifact contract. Existing exports are included; no model training or raw AIT-ADS download is required.

```sh
.venv/bin/python -m unittest discover -s frontend/tests -v
.venv/bin/python frontend/scripts/check-local.py
```

The first command checks all five pages, chatbot submission and persistence, network scoping, missing-model detection, and streamed API errors. The second requires a real local model and verifies an evidence-grounded streamed answer.

If the assistant is unavailable, check `ollama list`, confirm the configured model was pulled, and inspect `/tmp/alertlens-ollama.log` when using the launcher. Another service occupying port 8501 can be avoided with `streamlit run frontend/app.py --server.port 8502`.
