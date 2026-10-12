"""AlertLens - AI-powered Blue Team triage over the AIT Alert Data Set (streamlit run app.py)."""
import json

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from blueteam.baseline import LEARNING_HOURS, display_value, feature_info
from blueteam.explain import STAGE_MITRE, STAGE_ORDER
from blueteam.ingest import DATA_DIR
from blueteam import llm

st.set_page_config(page_title="AlertLens - AI Blue Team", layout="wide", page_icon="🛡️")

METHOD_NAMES = {
    "model": "AlertLens (LightGBM, ours)",
    "isoforest": "Isolation Forest (unsupervised)",
    "rarity": "Rule rarity heuristic",
    "wazuh_level": "Wazuh severity level (status quo)",
}


@st.cache_data
def load(version: float):
    meta = pd.read_parquet(DATA_DIR / "meta_explained.parquet")
    meta["start_dt"] = pd.to_datetime(meta["start"], unit="s")
    inc = pd.DataFrame(json.load(open(DATA_DIR / "incidents.json")))
    inc["start_dt"] = pd.to_datetime(inc["start"], unit="s")
    inc["end_dt"] = pd.to_datetime(inc["end"], unit="s")
    summary = pd.read_csv(DATA_DIR / "metrics_summary.csv", index_col=0)
    by_sc = pd.read_csv(DATA_DIR / "metrics_by_scenario.csv")
    imp = pd.read_csv(DATA_DIR / "feature_importance.csv", index_col=0)
    stats = json.load(open(DATA_DIR / "stats.json"))
    labels = pd.read_csv(DATA_DIR.parent / "labels.csv")
    return meta, inc, summary, by_sc, imp, stats, labels


BASELINE_FILES = ("learning_periods.json", "feature_baseline.parquet", "rule_hourly.parquet",
                  "network_series.parquet", "score_breakdown.parquet")


@st.cache_data
def load_baseline(version: float):
    lp = pd.DataFrame(json.load(open(DATA_DIR / "learning_periods.json"))).set_index("scenario")
    fb = pd.read_parquet(DATA_DIR / "feature_baseline.parquet").set_index(["scenario", "feature"])
    rh = pd.read_parquet(DATA_DIR / "rule_hourly.parquet")
    ns = pd.read_parquet(DATA_DIR / "network_series.parquet")
    bd = pd.read_parquet(DATA_DIR / "score_breakdown.parquet").set_index("row")
    return lp, fb, rh, ns, bd


def sigmoid(x):
    return 1 / (1 + np.exp(-x))


def load_narratives():
    p = DATA_DIR / "narratives.json"
    return json.load(open(p)) if p.exists() else {}


meta, incidents, summary, by_sc, imp, stats, labels = load(max(
    (DATA_DIR / f).stat().st_mtime for f in ("meta_explained.parquet", "incidents.json", "stats.json")))
st.session_state.setdefault("suppressed", set())
st.session_state.setdefault("chat", {})

st.title("🛡️ AlertLens — AI-powered Blue Team triage")
st.caption("Wazuh HIDS + Suricata NIDS + AMiner log-anomaly alerts → deduplicated meta-alerts → ML risk ranking "
           "→ explained incidents → local-LLM analyst. All scores are from leave-one-network-out validation with streaming-safe "
           "(no look-ahead) features.")

tab_overview, tab_incidents, tab_why, tab_triage, tab_truth = st.tabs(
    ["📊 Overview", "🚨 Incident queue", "🧭 Why suspicious?", "🔎 Alert triage", "🎯 Ground truth check"])

# ------------------------------------------------------------------ overview
with tab_overview:
    c = st.columns(5)
    c[0].metric("Raw alerts", f"{stats['n_alerts']:,}")
    c[1].metric("Meta-alerts (dedup)", f"{stats['n_meta']:,}", f"-{1 - stats['n_meta'] / stats['n_alerts']:.1%}", delta_color="inverse")
    c[2].metric("Flagged by model", f"{stats['n_flagged_meta']:,}", f"{stats['flagged_precision']:.0%} precision")
    c[3].metric("Incidents", stats["n_incidents"], "#1 = real attack in 8/8 networks")
    c[4].metric("Attack phases detected", f"{stats['phase_recall_flagged']:.0%}",
                f"stage accuracy {stats['stage_accuracy']:.0%}")

    stages = ["Raw alerts", "Meta-alerts", "Flagged meta-alerts", "Incidents"]
    vals = [stats["n_alerts"], stats["n_meta"], stats["n_flagged_meta"], stats["n_incidents"]]
    fig = go.Figure(go.Bar(y=stages[::-1], x=vals[::-1], orientation="h", text=[f"{v:,}" for v in vals[::-1]],
                           textposition="outside", marker_color=["crimson", "darkorange", "goldenrod", "steelblue"]))
    fig.update_xaxes(type="log", range=[0, 7.2])
    fig.update_layout(height=280, margin=dict(l=10, r=10, t=40, b=10),
                      title="Alert fatigue funnel — 8 networks × 5 days (log scale)")
    st.plotly_chart(fig, width="stretch")

    st.subheader("Versus status-quo ranking (mean over 8 held-out networks)")
    s = summary.rename(index=METHOD_NAMES)
    col1, col2, col3 = st.columns(3)
    for col, metric, title in [(col1, "pr_auc", "PR-AUC (attack vs benign)"),
                               (col2, "p@20", "Precision of top-20 queue"),
                               (col3, "queue_size@90recall", "Items to review to catch 90% of attacks")]:
        f = px.bar(s.reset_index(), x=metric, y="method", orientation="h", title=title, text_auto=".3~f")
        f.update_layout(height=280, margin=dict(l=10, r=10, t=40, b=10), yaxis_title=None, xaxis_title=None)
        if metric.startswith("queue"):
            f.update_xaxes(type="log")
        col.plotly_chart(f, width="stretch")
    st.markdown(
        f"**False positives cut:** at 90% attack recall AlertLens suppresses "
        f"**{summary.loc['model', 'fp_suppressed@90recall']:.2%}** of benign meta-alerts — the analyst queue shrinks from "
        f"~{summary.loc['wazuh_level', 'queue_size@90recall']:,.0f} (sorting by Wazuh level) to "
        f"**~{summary.loc['model', 'queue_size@90recall']:.0f}** items per network.")

    with st.expander("Per-network results (held-out)"):
        st.dataframe(by_sc[by_sc.method == "model"].drop(columns="method").round(3), hide_index=True)
    abl_path = DATA_DIR / "ablation.csv"
    if abl_path.exists():
        with st.expander("Ablation: which feature calcers matter? (leave-one-network-out)"):
            abl = pd.read_csv(abl_path)
            st.dataframe(abl[["config", "n_features", "pr_auc", "p@20", "p@50", "phases@50", "queue_size@90recall"]]
                         .round(3), hide_index=True)
            st.caption("Knowing *what* a rule is (semantics only) gives PR-AUC 0.49; *behavioral* context — rarity, "
                       "novelty, burst shape, actor history — lifts it to 0.96. Removing time-window context features "
                       "costs only 0.02, so the model is not just learning 'when the attack happened'.")
    with st.expander("What drives the risk score (mean LightGBM gain)"):
        f = px.bar(imp.head(15).iloc[::-1].reset_index(), x="gain", y=imp.index.name or "index", orientation="h")
        f.update_layout(height=420, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(f, width="stretch")
    with st.expander("How it works"):
        st.markdown("""
1. **Ingest & normalize** 2.66M heterogeneous JSON alerts (Wazuh, Suricata, AMiner) into one schema.
2. **Deduplicate** into meta-alerts: same network, host, rule and source IP within 5 minutes.
3. **Feature calcers** (label-free, streaming-safe — only past alerts are used, per network): rule rarity & novelty, source-IP novelty, burst shape,
   multi-sensor corroboration in a 10-min window, volume spikes, rule semantics / MITRE tactic, attacker vs admin
   indicators in the raw log lines (www-data pivots, /etc/shadow, shells without login vs SSH key logins), account novelty.
4. **LightGBM ranker** (tuned, 5-seed ensemble) trained leave-one-network-out → scores generalize to an unseen environment.
5. **Explain**: SHAP contributions → plain-English reasons; multiclass model → kill-chain stage + ATT&CK.
6. **Incidents**: flagged meta-alerts chained by time (≤60 min gap), ranked by combined risk & stage diversity.
7. **Local LLM analyst** (Ollama, qwen3:14b — no telemetry leaves the SOC) writes the report and answers questions,
   grounded only in the ranked evidence.
""")

# ------------------------------------------------------------------ incidents
with tab_incidents:
    sc = st.selectbox("Network", sorted(incidents["scenario"].unique()), key="inc_sc")
    inc_sc = incidents[incidents["scenario"] == sc].sort_values("rank_in_scenario")
    view = inc_sc.assign(
        window=inc_sc["start_dt"].dt.strftime("%m-%d %H:%M") + " → " + inc_sc["end_dt"].dt.strftime("%H:%M"),
        stages=inc_sc["stages"].apply(" → ".join),
    )[["rank_in_scenario", "risk", "window", "n_meta", "n_alerts", "stages", "sensors"]]
    st.dataframe(view.rename(columns={"rank_in_scenario": "rank"}), hide_index=True, width="stretch",
                 column_config={"risk": st.column_config.ProgressColumn("risk", min_value=0, format="%.2f",
                                                                        max_value=float(incidents["risk"].max()))})
    rank = st.radio("Open incident", inc_sc["rank_in_scenario"].tolist(), horizontal=True,
                    format_func=lambda r: f"#{r}")
    inc = inc_sc[inc_sc["rank_in_scenario"] == rank].iloc[0].to_dict()
    m = meta[(meta["scenario"] == sc) & (meta["incident_id"] == inc["incident_id"])].copy()

    c = st.columns(4)
    c[0].metric("Risk", f"{inc['risk']:.2f}")
    c[1].metric("Raw alerts collapsed", f"{inc['n_alerts']:,}")
    c[2].metric("Kill-chain stages", inc["n_stages"])
    c[3].metric("Hosts involved", len(inc["hosts"]))

    m["stage"] = pd.Categorical(m["pred_stage"], categories=STAGE_ORDER[::-1], ordered=True)
    m["size"] = np.log1p(m["n_alerts"]) + 1
    f = px.scatter(m.sort_values("stage"), x="start_dt", y="stage", size="size", color="score_model",
                   color_continuous_scale="Reds", range_color=(0.5, 1),
                   hover_data={"rule_desc": True, "host": True, "src_ip": True, "n_alerts": True, "size": False},
                   title="Kill-chain timeline (model-predicted stage per meta-alert)")
    f.update_layout(height=360, margin=dict(l=10, r=10, t=40, b=10), yaxis_title=None, xaxis_title="UTC")
    st.plotly_chart(f, width="stretch")

    left, right = st.columns([3, 2])
    key = f"{sc}#{inc['incident_id']}"
    ctx = llm.incident_context(meta, inc)
    with left:
        st.subheader("🤖 AI incident report")
        narratives = load_narratives()
        if key in narratives:
            st.markdown(narratives[key])
        elif st.button("Generate report with local LLM", key=f"gen_{key}"):
            st.write_stream(llm.narrate(ctx, stream=True))
        else:
            st.info("Report not cached yet - click to generate (runs locally, ~1-2 min).")
    with right:
        st.subheader("💬 Ask the analyst")
        hist = st.session_state["chat"].setdefault(key, [])
        for msg in hist:
            st.chat_message(msg["role"]).markdown(msg["content"])
        q = st.chat_input("e.g. Which IP is the attacker? Is this a false positive?", key=f"chat_{key}")
        if q:
            st.chat_message("user").markdown(q)
            with st.chat_message("assistant"):
                ans = st.write_stream(llm.ask(ctx, q, history=hist, stream=True))
            hist += [{"role": "user", "content": q}, {"role": "assistant", "content": ans}]
        st.caption("Stage → MITRE ATT&CK")
        for s in inc["stages"]:
            st.markdown(f"- **{s}**: {STAGE_MITRE.get(s, '')}")

    st.subheader("Evidence (ranked)")
    ev = m.sort_values("score_model", ascending=False)
    ev = ev.assign(why=ev["reasons"].apply(lambda r: " • ".join(x["text"] for x in json.loads(r or "[]")[:3])),
                   time=ev["start_dt"].dt.strftime("%m-%d %H:%M:%S"))
    st.dataframe(ev[["score_model", "time", "pred_stage", "source", "host", "src_ip", "rule_desc", "n_alerts", "why"]],
                 hide_index=True, width="stretch",
                 column_config={"score_model": st.column_config.ProgressColumn("risk", min_value=0, max_value=1, format="%.3f")})

# ------------------------------------------------------------------ why suspicious
def why_view():
    if not all((DATA_DIR / f).exists() for f in BASELINE_FILES):
        st.info("Run `python -m blueteam.baseline` to build the baseline / learning-period view.")
        return
    lp, fb, rh, ns, bd = load_baseline(max((DATA_DIR / f).stat().st_mtime for f in BASELINE_FILES))
    st.markdown("For any alert: **what normal looks like** in this network, **how much history** the model had "
                "seen, and **why** it got its score — how much each signal pushed it up or down.")
    c = st.columns([1, 4])
    sc4 = c[0].selectbox("Network", sorted(meta["scenario"].unique()), key="why_sc")
    cand = meta[(meta["scenario"] == sc4) & meta.index.isin(bd.index)].sort_values("score_model", ascending=False)
    pick = c[1].selectbox(
        "Alert (ranked by risk)", cand.index, key=f"why_pick_{sc4}",
        format_func=lambda i: f"{cand.at[i, 'score_model']:.2f} · {cand.at[i, 'start_dt']:%m-%d %H:%M} · "
                              f"{cand.at[i, 'host']} · {cand.at[i, 'rule_desc'][:80]}")
    row, b, L = meta.loc[pick], bd.loc[pick], lp.loc[sc4]
    t0, learn_end = pd.to_datetime(L["t0"], unit="s"), pd.to_datetime(L["learn_end"], unit="s")
    in_learning = row["start"] < L["learn_end"]

    k = st.columns(4)
    k[0].metric("Risk score", f"{row['score_model']:.1%}",
                help="From models trained on the other 7 networks only (leave-one-network-out).")
    k[1].metric("Predicted stage", row["pred_stage"] if pd.notna(row["pred_stage"]) else "not flagged")
    k[2].metric("History before this alert", f"{(row['start'] - L['t0']) / 3600:.0f} h")
    k[3].metric("Baseline", "still learning" if in_learning else "established")
    st.caption(
        f"**Learning period** for {sc4}: the first {LEARNING_HOURS} h of monitoring ({t0:%m-%d %H:%M} → "
        f"{learn_end:%m-%d %H:%M} UTC) — {L['n_alerts_learning']:,.0f} alerts from {L['n_rules_learning']:.0f} rules. "
        "'Normal' below is what a typical alert in this network looked like during that period. After it, the model "
        "keeps learning: every feature uses all alerts *before* the one being scored, never after.")
    if in_learning:
        st.warning("This alert falls inside the learning period — the baseline is still forming, so treat the score "
                   "with lower confidence.")

    contrib = json.loads(b["contrib"])
    st.subheader("Baseline vs. this alert")
    rows = []
    for feat, v, cval in contrib:
        label, kind = feature_info(feat)
        base = fb.loc[(sc4, feat)] if (sc4, feat) in fb.index else None
        if base is None:
            normal = "–"
        elif kind == "flag":
            normal = f"present in {base['nonzero']:.1%} of alerts"
        else:
            normal = f"{display_value(feat, base['median'])}  (95% of alerts ≤ {display_value(feat, base['p95'])})"
        rows.append({"signal": label, "this alert": display_value(feat, v), "normal in this network": normal,
                     "push on score": cval, "effect": "▲ more suspicious" if cval > 0 else "▼ less suspicious"})
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", column_config={
        "push on score": st.column_config.NumberColumn(format="%+.2f", help="Tree-SHAP contribution in log-odds")})

    names = ["Typical alert (prior)"] + [feature_info(f)[0] for f, _, _ in contrib] + ["All other signals",
                                                                                      "This alert"]
    vals = [b["bias"]] + [cv for _, _, cv in contrib] + [b["rest"], 0]
    f = go.Figure(go.Waterfall(
        orientation="h", y=names, x=vals, measure=["absolute"] + ["relative"] * (len(contrib) + 1) + ["total"],
        increasing=dict(marker_color="crimson"), decreasing=dict(marker_color="steelblue"),
        totals=dict(marker_color="dimgray"), text=[f"{v:+.2f}" for v in vals[:-1]] + [f"{row['score_model']:.1%}"],
        textposition="outside", cliponaxis=False))
    f.update_layout(
        height=480, margin=dict(l=10, r=90, t=50, b=10), yaxis=dict(autorange="reversed"),
        xaxis_title="log-odds of attack (0 = 50/50)",
        title=f"Why: from {sigmoid(b['bias']) * 100:.2g}% for a typical alert to {row['score_model']:.1%} for this one")
    st.plotly_chart(f, width="stretch")

    at = pd.to_datetime(row["start"], unit="s")

    def mark(fig):
        fig.add_vrect(x0=t0, x1=learn_end, fillcolor="lightblue", opacity=0.25, line_width=0, layer="below",
                      annotation_text="learning period", annotation_position="top left")
        fig.add_vrect(x0=at, x1=at + pd.Timedelta(minutes=30), fillcolor="crimson", opacity=0.5, line_width=0,
                      layer="below", annotation_text="this alert", annotation_position="top right")

    left, right = st.columns(2)
    with left:
        hours = pd.RangeIndex(int(L["t0"] // 3600 * 3600), int(L["t_end"]) + 3600, 3600)
        h = rh[(rh["scenario"] == sc4) & (rh["rule_id"] == row["rule_id"])].set_index("hour")["n"]
        h = h.reindex(hours, fill_value=0)
        learn = h[h.index < L["learn_end"]]
        f = go.Figure(go.Bar(x=pd.to_datetime(h.index, unit="s"), y=h.to_numpy(), marker_color="#e0e0e0",
                             marker_line_width=0, name="alerts / hour"))
        mark(f)
        f.add_hline(y=learn.quantile(0.95), line_dash="dot", line_color="deepskyblue",
                    annotation_text="baseline: 95th pct of hourly count")
        f.update_layout(height=340, margin=dict(l=10, r=10, t=50, b=10), showlegend=False, bargap=0,
                        title="This rule over time (alerts per hour)")
        st.plotly_chart(f, width="stretch")
        st.caption(f"**{row['rule_desc']}** — during learning: {learn.mean():.1f} alerts/hour, active in "
                   f"{(learn > 0).mean():.0%} of hours. In the hour of this alert: "
                   f"{int(h.get(int(row['start'] // 3600 * 3600), 0)):,} alerts.")
    with right:
        n = ns[ns["scenario"] == sc4]
        nl = n[n["bucket"] < L["learn_end"]]
        f = go.Figure(go.Scatter(x=pd.to_datetime(n["bucket"], unit="s"), y=n["rare_rules"], mode="lines",
                                 line=dict(color="#e0e0e0", width=1), name="rarely-seen detections / 10 min"))
        mark(f)
        f.add_hline(y=nl["rare_rules"].quantile(0.95), line_dash="dot", line_color="deepskyblue",
                    annotation_text="baseline: 95th pct")
        f.update_layout(height=340, margin=dict(l=10, r=10, t=50, b=10), showlegend=False,
                        title="Whole network: rarely-seen detections per 10 min")
        st.plotly_chart(f, width="stretch")
        st.caption(f"The model's strongest signal. During learning: median {nl['rare_rules'].median():.0f}, "
                   f"95th pct {nl['rare_rules'].quantile(0.95):.0f} per 10 min.")

    st.subheader("Raw evidence")
    reasons = json.loads(row["reasons"] or "[]")
    st.markdown("\n".join(f"- {r['text']}" for r in reasons))
    raw = next((str(v) for v in (row["sample_log"], row["sample_url"]) if pd.notna(v) and str(v)), "")
    st.code(raw[:1500] or "(no raw log line)", language=None, wrap_lines=True)
    with st.expander("Ground truth for this alert (judges' view)"):
        phase = row["phase"] if pd.notna(row["phase"]) else "—"
        st.write(f"label: **{'attack' if row['label'] else 'benign'}** · phase: {phase} · "
                 f"attack share of its raw alerts: {row['attack_share']:.0%}")


with tab_why:
    why_view()

# ------------------------------------------------------------------ triage
with tab_triage:
    st.markdown("Ranked meta-alerts for a network, with **why** each one was scored. Mark false positives — "
                "AlertLens suppresses the same rule on the same host going forward (analyst feedback loop).")
    sc2 = st.selectbox("Network", sorted(meta["scenario"].unique()), key="tri_sc")
    show_k = st.slider("Queue length", 10, 200, 50)
    q = meta[meta["scenario"] == sc2].copy()
    sup = st.session_state["suppressed"]
    q["suppressed"] = [(r, h) in sup for r, h in zip(q["rule_id"], q["host"])]
    q = q[~q["suppressed"]].sort_values("score_model", ascending=False).head(show_k)
    q["why"] = q["reasons"].apply(lambda r: " • ".join(x["text"] for x in json.loads(r or "[]")[:3]))
    q["time"] = q["start_dt"].dt.strftime("%m-%d %H:%M:%S")
    q["mark_fp"] = False
    edited = st.data_editor(
        q[["mark_fp", "score_model", "time", "pred_stage", "source", "host", "src_ip", "rule_desc", "n_alerts", "why"]],
        hide_index=True, width="stretch", disabled=[c for c in q.columns if c != "mark_fp"],
        column_config={"score_model": st.column_config.ProgressColumn("risk", min_value=0, max_value=1, format="%.3f"),
                       "mark_fp": st.column_config.CheckboxColumn("FP?")}, key=f"editor_{sc2}")
    if st.button("Suppress marked false positives"):
        for i in edited.index[edited["mark_fp"]]:
            sup.add((q.at[i, "rule_id"], q.at[i, "host"]))
        st.rerun()
    if sup:
        st.caption(f"{len(sup)} suppression rules active")
        if st.button("Clear suppressions"):
            sup.clear()
            st.rerun()
    with st.expander("Show ground truth for this queue (judges' view)"):
        top = meta[meta["scenario"] == sc2]
        top = top[~np.array([(r, h) in sup for r, h in zip(top["rule_id"], top["host"])], dtype=bool)]
        top = top.sort_values("score_model", ascending=False).head(show_k)
        st.metric(f"Precision of top-{show_k}", f"{top['label'].mean():.0%}")
        st.dataframe(top[["score_model", "rule_desc", "label", "phase"]], hide_index=True)

# ------------------------------------------------------------------ ground truth
with tab_truth:
    sc3 = st.selectbox("Network", sorted(meta["scenario"].unique()), key="gt_sc")
    lab = labels[labels["scenario"] == sc3].assign(
        s=lambda d: pd.to_datetime(d["start"], unit="s"), e=lambda d: pd.to_datetime(d["end"], unit="s"))
    mm = meta[(meta["scenario"] == sc3) & (meta["score_model"] >= 0.05)]
    f = go.Figure()
    for r in lab.itertuples():
        f.add_vrect(x0=r.s, x1=max(r.e, r.s + pd.Timedelta(seconds=60)), fillcolor="orange", opacity=0.25, line_width=0,
                    annotation_text=r.attack, annotation_position="top left", annotation_textangle=-90)
    f.add_trace(go.Scatter(x=mm["start_dt"], y=mm["score_model"], mode="markers",
                           marker=dict(size=np.log1p(mm["n_alerts"]) * 2 + 4, color=mm["label"],
                                       colorscale=[[0, "steelblue"], [1, "crimson"]]),
                           text=mm["rule_desc"], hovertemplate="%{text}<br>risk %{y:.2f}<extra></extra>"))
    f.update_layout(height=450, title="Model risk over time vs labeled attack phases (red = attack-related meta-alert)",
                    yaxis_title="risk", margin=dict(l=10, r=10, t=40, b=10))
    st.plotly_chart(f, width="stretch")
    st.caption("Orange bands = attack phases from labels.csv. Zoom into the attack day to see each phase light up.")
