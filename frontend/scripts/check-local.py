"""Real local-model smoke check: artifact readiness, installed model, and inference."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend_client import backend_status, load_results, workspace_context, ask_analyst
status = backend_status()
if not status['ready'] or not status['model_ready']:
    raise SystemExit(f"Local analyst not ready: {status}")
results = load_results()
context = workspace_context(results['meta'], results['incidents'], 'All networks', 'Overview')
answer = ''.join(ask_analyst(context, 'Briefly summarize the snapshot and one investigation priority.'))
if not answer.strip():
    raise SystemExit('Model returned an empty answer')
print(f"PASS: {status['model']} returned a streamed answer using dashboard evidence.\n{answer}")
