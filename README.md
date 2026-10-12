# AlertLens — AI-powered Blue Team triage (AIC x CrowdStrike, Track 2: Detect)

A mini *Charlotte AI*: ingests **2.66M** heterogeneous IDS alerts (Wazuh HIDS, Suricata NIDS, AMiner log-anomaly)
from the [AIT Alert Data Set](https://zenodo.org/records/8263181), and turns them into a handful of **ranked,
explained incidents** with a kill-chain timeline, MITRE ATT&CK mapping, a local-LLM incident report and an analyst chat.

## Results (leave-one-network-out: every number is on a network the model never saw)

All features are **streaming-safe**: they only use alerts seen *before* the meta-alert (no look-ahead), so this is
what you'd get running live.

| | AlertLens | Isolation Forest | Rule rarity | Wazuh severity (status quo) |
|---|---|---|---|---|
| PR-AUC | **0.961** | 0.366 | 0.143 | 0.006 |
| Precision of top-20 queue | **100%** | 51% | 24% | 1% |
| Items to review to catch 90% of attacks | **64** | 500 | 1,295 | 12,017 |
| Benign meta-alerts suppressed @ 90% recall | **99.9%** | 96.5% | 89.5% | 3.2% |

- **2,655,821 raw alerts → 99,161 meta-alerts → 451 flagged (91% precision) → 13 incidents.**
- The **#1 incident in all 8 networks is the real multi-step attack** (78–100% attack content).
- Each incident gets a label-free confidence tier (high = top score ≥ 0.9 *and* ≥ 2 kill-chain stages). The local LLM
  analyst uses it: all 9 real attack incidents are reported TRUE POSITIVE, the 4 benign ones LIKELY BENIGN / NEEDS
  REVIEW with the most plausible normal explanation (e.g. a user's first-time `sudo`, a package update).
- 88% of attack phases and 91% of attack meta-alerts are surfaced; the kill-chain stage of each alert is predicted
  with 90% accuracy (LOSO).
- Ablation: rule semantics alone → PR-AUC 0.49; behavioral calcers (rarity, novelty, burst, actor history) → 0.96.
  Removing the network-wide time-window context features costs only 0.02, so the model is not just learning "attack time".
- Earlier, untuned version: streaming-safe features 0.933 vs retrospective (whole 5-day window) 0.938 — going live costs ~nothing.

**How we got from 0.933 to 0.961 (all measured leave-one-network-out):**

| Step | PR-AUC | Queue @ 90% recall | Flagged false positives |
|---|---|---|---|
| Behavioral calcers, default LightGBM | 0.933 | 84 | 77 |
| + raw-log attacker/admin indicators, account novelty | 0.944 | 91 | 58 |
| + hyperparameter search (16 configs) + 5-seed ensemble | **0.961** | **64** | **41** |

The search is honest about selection bias: for each held-out network we re-pick the config using only the other
seven networks; that nested estimate is also 0.961 (the same config wins every time). Strong regularization
(`reg_lambda=20`, 30% of features per tree) is what helped.

## Pipeline

```
ait_ads/*.json ─ ingest.py ─▶ one normalized schema (parquet)
               ─ features.py ─▶ label denoising · meta-alerts (same host/rule/src-ip, ≤5 min) · feature calcers
               ─ train.py ─▶ 5-seed LightGBM ensemble, leave-one-network-out, baselines, ablation, --tune
               ─ explain.py ─▶ SHAP → plain-English reasons · kill-chain stage classifier · incident chaining
               ─ llm.py ─▶ Ollama qwen3:14b (local, no telemetry leaves the SOC): report + Q&A grounded in evidence
               ─ app.py ─▶ Streamlit SOC console: overview · incident queue · triage w/ FP feedback · ground truth
```

Feature calcers follow the config-driven registry pattern (`FeatureCalcer` + `register_calcer` + config list):
`burst`, `rule_rarity_causal`, `src_ip_causal`, `context`, `semantics`, `log_content`, `account` — all label-free,
streaming-safe (only past alerts) and computed per network, so they transfer to a new environment without retraining
on its labels.

`log_content` reads the raw log lines of every alert in a meta-alert (hex-encoded audit commands are decoded first) and
flags attacker tradecraft — `www-data` switching user, a pty with no login session, commands run from `/var/www` or
`/tmp`, `/etc/shadow` access, `python-requests`/scanner user agents, `.php` in `uploads/`, long encoded payloads — and
admin tradecraft — SSH public-key logins, commands from `/home/*`. `account` asks whether this user account has been
seen on this host / in this network before. These turn reasons like "rare rule" into "attacker indicators in raw logs:
exec from web/tmp dir, credential file access", and "regular SSH key login by an administrator (likely benign)".

**Baseline, learning period and the why (the "Why suspicious?" tab).** For any alert the dashboard shows:
- *Learning period* — the first 24 h of each network (no attack starts before hour 46 in any network). Alerts in it are
  scored but marked "baseline still learning"; only 3 of 451 flagged items fall there, none of them attacks. After it the
  model keeps learning: every feature uses all alerts before the one being scored, never after.
- *Baseline vs. this alert* — for the signals that drove the score, this alert's value next to what a typical alert in
  this network looked like during the learning period (median and 95th percentile), e.g. "rule active in 0% of past
  hours vs. normal 62%", "12 rarely-seen detections in the same 10 min vs. normal 0 (95% ≤ 3)".
- *Why* — a SHAP waterfall from the typical-alert prior to this alert's score, computed with the same held-out-network
  models that produced the score (it reproduces every displayed score exactly).
- The rule's hourly history and the network-wide rare-detection rate, each with the learning period and baseline drawn in.

`blueteam/baseline.py` builds this (`data/learning_periods.json`, `feature_baseline.parquet`, `rule_hourly.parquet`,
`network_series.parquet`, `score_breakdown.parquet`).

**Labels.** `labels.csv` only gives attack-phase time windows, so ~19K benign background alerts (mail logins, TLS
noise) fall inside them. We denoise: an in-window alert counts as attack-related only if its rule fires ≥10× more often
inside attack windows than in normal operation for that network. Background rules sit at 1–3×, attack rules at 10²–10⁶×.

**About the remaining false positives.** Of the 41 flagged benign meta-alerts, 31 sit *inside* labeled attack windows
(e.g. "first time this IDS alert is generated" on the attacker's scan, AMiner request-frequency alerts on dirb traffic)
— attack traffic that hit a routinely-firing rule and was denoised away; counting them, flagged precision is ~98%.
Only 10 flagged items across all 8 networks are outside any attack: mostly "normal user behavior" decoys planted by
the dataset authors (first-time `sudo`, new login-parameter combos) — exactly what the analyst-feedback suppression handles.

**Known limitation.** DNS exfiltration (`dnsteal`) is barely visible: the AMiner DNS high-entropy detector fires all
day in normal traffic, so it's suppressed with the rest of the noise. Next step: sequence/actor features per domain.

## Run

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/streamlit run app.py            # dashboard works right away from the committed results in data/
```

To reproduce everything from raw alerts, download the AIT Alert Data Set from
[Zenodo](https://zenodo.org/records/8263181) and unpack the 16 `*_wazuh.json` / `*_aminer.json` files into `ait_ads/`:

```bash
ollama pull qwen3:14b                     # optional, for reports / chat
./run_pipeline.sh                         # or run the steps individually
```

## 3-minute demo script

1. **Overview** — "2.66M alerts in 5 days. Sorting by Wazuh severity, an analyst would wade through 12,000 items to
   find 90% of the attack. AlertLens: 64, in a network it never trained on, with no look-ahead."
2. **Incident queue → santos #1** — kill-chain timeline lights up recon → web discovery → webshell → cracking →
   reverse shell → privilege escalation; the AI report names attacker IP, webshell path, compromised accounts.
3. **Ask the analyst** — "Which IP is the attacker and what should I block first?"
4. **Why suspicious? → fox, top alert** — baseline vs. this alert ("rule active in 0% of past hours, normal 62%"),
   the waterfall from the typical-alert prior to 99.8%, the rule's history with the learning period shaded. Then
   **russellmitchell, 01-23 16:24 `sshd: authentication success` on mail** — the rule *is* rare here (+2.2, a rarity-only
   detector would flag it), but nothing else unusual is happening in the network and it is an administrator's SSH key
   login (−0.36), so it stays at ~0.1%.
5. **Alert triage** — mark `First time user executed sudo` as an admin false positive → it disappears from the queue.
6. **Ground truth** — model risk over time vs labeled attack phases.
