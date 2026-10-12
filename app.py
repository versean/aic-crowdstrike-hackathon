"""AlertLens - AI-powered Blue Team triage over the AIT Alert Data Set (streamlit run app.py)."""
import json

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

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

tab_overview, tab_incidents, tab_triage, tab_truth = st.tabs(
    ["📊 Overview", "🚨 Incident queue", "🔎 Alert triage", "🎯 Ground truth check"])

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
