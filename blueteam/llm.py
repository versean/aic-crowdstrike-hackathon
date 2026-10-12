"""Local-LLM analyst (Ollama): incident narratives and Q&A grounded in the ranked, explained evidence."""
import json
import sys
import time

import pandas as pd
import requests

from blueteam.explain import STAGE_MITRE
from blueteam.ingest import DATA_DIR

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen3:14b"

SYSTEM = (
    "You are a senior SOC analyst assistant (like CrowdStrike Charlotte AI). You receive pre-ranked, ML-scored "
    "meta-alerts from Wazuh (HIDS), Suricata (NIDS) and AMiner (log anomaly detection) for one incident. "
    "Only use facts present in the evidence; cite timestamps, hosts, IPs and rules. Be concise and concrete. "
    "If evidence is weak or looks like normal admin/user activity, say so explicitly."
)

NARRATIVE_TASK = """Write an incident report in Markdown with exactly these sections:
### Verdict
One line: TRUE POSITIVE / LIKELY BENIGN / NEEDS REVIEW, with confidence (high/medium/low) and why.
### What happened
3-6 bullet kill-chain timeline (UTC time - stage - what the evidence shows).
### Affected assets & IOCs
Hosts, source IPs, accounts, URLs.
### MITRE ATT&CK
Techniques involved.
### Recommended response
3-5 prioritized actions."""


def _ts(t):
    return pd.to_datetime(t, unit="s").strftime("%m-%d %H:%M:%S")


def incident_context(meta: pd.DataFrame, inc: dict, max_items: int = 25) -> str:
    m = meta[(meta["scenario"] == inc["scenario"]) & (meta["incident_id"] == inc["incident_id"])]
    m = m.sort_values("score_model", ascending=False)
    per_stage = m.groupby("pred_stage", dropna=False).head(max(3, max_items // max(m["pred_stage"].nunique(), 1)))
    m = pd.concat([per_stage, m.drop(per_stage.index)]).head(max_items).sort_values("start")
    lines = [
        f"Incident #{inc['rank_in_scenario']} in network '{inc['scenario']}': {_ts(inc['start'])} -> {_ts(inc['end'])} UTC, "
        f"{inc['n_meta']} meta-alerts ({inc['n_alerts']:,} raw alerts), sensors={inc['sensors']}, "
        f"model-predicted stages={inc['stages']}, hosts={inc['hosts']}, source IPs={inc['src_ips']}",
        "Evidence (time | host | sensor | rule | #alerts | src_ip | risk score | predicted stage | why flagged | sample log):",
    ]
    for r in m.itertuples():
        reasons = "; ".join(x["text"] for x in json.loads(r.reasons or "[]")[:3])
        log = (r.sample_url if isinstance(r.sample_url, str) and r.sample_url else r.sample_log) or ""
        lines.append(
            f"- {_ts(r.start)} | {r.host} | {r.source} | {r.rule_desc} | {r.n_alerts} | {r.src_ip} | "
            f"{r.score_model:.2f} | {r.pred_stage} | {reasons} | {str(log)[:180]}"
        )
    lines.append("Stage -> MITRE hints: " + "; ".join(f"{k}: {v}" for k, v in STAGE_MITRE.items() if k in inc["stages"]))
    return "\n".join(lines)


def chat(messages, model=MODEL, stream=False, timeout=600):
    payload = {"model": model, "messages": messages, "stream": stream, "think": False,
               "options": {"temperature": 0.2, "num_ctx": 8192}}
    r = requests.post(OLLAMA_URL, json=payload, stream=stream, timeout=timeout)
    r.raise_for_status()
    if not stream:
        return r.json()["message"]["content"]
    return (json.loads(line)["message"]["content"] for line in r.iter_lines() if line)


def narrate(context: str, **kw):
    return chat([{"role": "system", "content": SYSTEM},
                 {"role": "user", "content": f"{context}\n\n{NARRATIVE_TASK}"}], **kw)


def ask(context: str, question: str, history=(), **kw):
    msgs = [{"role": "system", "content": SYSTEM + "\n\nIncident evidence:\n" + context}]
    msgs += list(history) + [{"role": "user", "content": question}]
    return chat(msgs, **kw)


def main(limit=None):
    meta = pd.read_parquet(DATA_DIR / "meta_explained.parquet")
    incidents = json.load(open(DATA_DIR / "incidents.json"))
    out_path = DATA_DIR / "narratives.json"
    done = json.load(open(out_path)) if out_path.exists() else {}
    incidents = sorted(incidents, key=lambda i: (i["rank_in_scenario"], -i["risk"]))
    for inc in incidents[:limit]:
        key = f"{inc['scenario']}#{inc['incident_id']}"
        if key in done:
            continue
        t0 = time.time()
        done[key] = narrate(incident_context(meta, inc))
        json.dump(done, open(out_path, "w"), indent=1)
        print(f"{key}: {time.time() - t0:.0f}s", flush=True)


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else None)
