"""AlertLens — a friendly SOC workspace for the AIT-ADS evaluation dataset."""
from __future__ import annotations

import html
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

from backend_client import (
    DATA_DIR,
    ask_analyst,
    backend_status,
    generate_report,
    incident_context,
    load_results,
)
from blueteam.stages import STAGE_MITRE, STAGE_ORDER

st.set_page_config(
    page_title="AlertLens | Blue Team Workspace",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

METHOD_NAMES = {
    "model": "AlertLens",
    "isoforest": "Isolation Forest",
    "rarity": "Rule rarity",
    "wazuh_level": "Wazuh severity",
}

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@500;600;700;800&display=swap');
    :root { --ink:#15233b; --muted:#65748b; --line:#e5eaf1; --blue:#3569e8; --navy:#10213c; --red:#e25163; }
    html, body, [class*="css"] { font-family:'DM Sans',sans-serif; }
    [data-testid="stAppViewContainer"] { background:#f5f7fb; }
    [data-testid="stHeader"] { background:rgba(245,247,251,.88); }
    [data-testid="stSidebar"] { background:linear-gradient(180deg,#10213c 0%,#142b4c 100%); border-right:1px solid #213b60; }
    [data-testid="stSidebar"] * { color:#eef4ff; }
    [data-testid="stSidebar"] [data-testid="stRadio"] label { padding:9px 12px; border-radius:10px; }
    [data-testid="stSidebar"] [data-testid="stRadio"] label:hover { background:#203a60; }
    [data-testid="stSidebar"] [data-testid="stSelectbox"] [data-baseweb="select"] > div { background:#1b3355; border-color:#3d5576; }
    .block-container { max-width:1480px; padding-top:1.6rem; padding-bottom:3rem; }
    h1,h2,h3 { color:var(--ink); font-family:'Manrope',sans-serif; letter-spacing:-.035em; }
    h1 { font-weight:800; font-size:2.2rem; }
    h2 { font-weight:750; }
    .brand { font:800 1.32rem 'Manrope',sans-serif; letter-spacing:-.04em; padding:4px 0 0; }
    .brand span { color:#ff6475; }
    .brand-sub { color:#a8bad2; font-size:.69rem; letter-spacing:.17em; text-transform:uppercase; margin:0 0 1.1rem; }
    .eyebrow { color:#6f7f96; font-size:.74rem; font-weight:700; letter-spacing:.15em; text-transform:uppercase; margin-bottom:.35rem; }
    .page-title { font:800 2rem 'Manrope',sans-serif; letter-spacing:-.045em; color:var(--ink); margin:0; }
    .page-subtitle { color:#65748b; margin:.35rem 0 1.2rem; font-size:.98rem; }
    .hero { background:linear-gradient(115deg,#142a4b 0%,#1c4677 56%,#3569e8 100%); padding:25px 28px; border-radius:18px; color:white; margin:.5rem 0 1.35rem; box-shadow:0 12px 30px rgba(20,42,75,.13); }
    .hero-kicker { color:#b9d1fa; font-size:.72rem; font-weight:700; letter-spacing:.15em; text-transform:uppercase; }
    .hero h2 { color:white; font-size:1.48rem; margin:.45rem 0 .3rem; }
    .hero p { color:#d7e5f8; margin:0; max-width:850px; }
    .hero-pill { display:inline-block; border:1px solid rgba(255,255,255,.28); color:#edf5ff; border-radius:999px; padding:6px 11px; margin-top:14px; font-size:.74rem; }
    .section-head { display:flex; align-items:baseline; justify-content:space-between; margin:.25rem 0 .7rem; }
    .section-head h3 { margin:0; font-size:1.1rem; }
    .section-note { color:#77869a; font-size:.8rem; }
    .status-chip { display:inline-flex; align-items:center; gap:7px; border-radius:999px; padding:6px 10px; font-size:.75rem; font-weight:700; }
    .status-ok { color:#b8f0d2; background:rgba(46,174,109,.18); }
    .status-warn { color:#ffe0a4; background:rgba(233,164,52,.18); }
    .tiny-muted { color:#a8bad2; font-size:.75rem; line-height:1.5; }
    [data-testid="stMetric"] { background:white; border:1px solid var(--line); border-radius:15px; padding:16px 17px; box-shadow:0 3px 12px rgba(18,37,65,.035); }
    [data-testid="stMetricLabel"] { color:#718097; font-size:.78rem; font-weight:600; }
    [data-testid="stMetricValue"] { color:var(--ink); font:800 1.65rem 'Manrope',sans-serif; }
    [data-testid="stMetricDelta"] { font-size:.77rem; }
    div[data-testid="stDataFrame"], div[data-testid="stDataEditor"] { background:white; border:1px solid var(--line); border-radius:14px; overflow:hidden; }
    div[data-testid="stPlotlyChart"] { background:white; border:1px solid var(--line); border-radius:14px; padding:7px; }
    div.stButton > button { border-radius:10px; font-weight:700; min-height:2.55rem; }
    div.stButton > button[kind="primary"] { background:#3569e8; border-color:#3569e8; }
    [data-testid="stChatMessage"] { border:1px solid var(--line); border-radius:14px; background:white; }
    hr { border-color:#e5eaf1; }
    @media (max-width: 800px) { .block-container{padding-left:1rem;padding-right:1rem}.page-title{font-size:1.7rem}.hero{padding:20px} }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data(show_spinner="Connecting to AlertLens results…")
def cached_results(version: float):
    return load_results()


@st.cache_data(ttl=10, show_spinner=False)
def cached_backend_status():
    return backend_status()


def reason_text(value) -> str:
    try:
        reasons = json.loads(value or "[]") if isinstance(value, str) else value or []
        return " · ".join(str(reason.get("text", "")) for reason in reasons[:3] if reason.get("text"))
    except (TypeError, ValueError, AttributeError):
        return "Analyst review recommended"


def fmt_time(value, pattern="%b %d · %H:%M UTC") -> str:
    if pd.isna(value):
        return "—"
    return pd.Timestamp(value).strftime(pattern)


def page_heading(kicker: str, title: str, subtitle: str):
    st.markdown(
        f'<div class="eyebrow">{html.escape(kicker)}</div><div class="page-title">{html.escape(title)}</div>'
        f'<div class="page-subtitle">{html.escape(subtitle)}</div>',
        unsafe_allow_html=True,
    )


def nice_network(network: str) -> str:
    return "All networks" if network == "All networks" else network.upper()


status = cached_backend_status()
if not status["ready"]:
    st.error("AlertLens results are not available in this checkout.")
    st.write(f"Looking for result files in `{status['data_dir']}`.")
    st.write("Missing: " + ", ".join(status["missing"]))
    st.stop()

version = max((DATA_DIR / name).stat().st_mtime for name in ("meta_explained.parquet", "incidents.json", "stats.json"))
results = cached_results(version)
meta = results["meta"]
incidents = results["incidents"]
scenarios = sorted(meta["scenario"].dropna().astype(str).unique())

with st.sidebar:
    st.markdown('<div class="brand">ALERT<span>LENS</span></div><div class="brand-sub">Blue team workspace</div>', unsafe_allow_html=True)
    st.markdown('<div class="tiny-muted">Track 02 · AI powered detection & triage</div>', unsafe_allow_html=True)
    st.divider()
    page = st.radio(
        "Workspace",
        ["Overview", "Incident investigations", "Alert triage", "Model quality"],
        label_visibility="collapsed",
        format_func=lambda p: {"Overview": "◫  Overview", "Incident investigations": "◎  Incidents", "Alert triage": "⌕  Triage queue", "Model quality": "⌁  Model quality"}[p],
    )
    network = st.selectbox("Dataset network", ["All networks", *scenarios], format_func=nice_network)
    st.divider()
    st.caption("BACKEND CONNECTION")
    st.markdown('<span class="status-chip status-ok">● Results connected</span>', unsafe_allow_html=True)
    if status["ollama_online"]:
        st.markdown(f'<span class="status-chip status-ok">● Analyst online</span><div class="tiny-muted">Local model · {html.escape(status["model"])}</div>', unsafe_allow_html=True)
    else:
        st.markdown('<span class="status-chip status-warn">● Analyst offline</span><div class="tiny-muted">Reports already in the dataset remain available. Start Ollama to generate new reports or chat.</div>', unsafe_allow_html=True)
    st.divider()
    st.markdown('<div class="tiny-muted">Data source<br><b>AIT-ADS evaluation bundle</b><br>Results are precomputed; this workspace does not ingest live telemetry.</div>', unsafe_allow_html=True)

if network == "All networks":
    current_meta = meta.copy()
    current_incidents = incidents.copy()
else:
    current_meta = meta[meta["scenario"] == network].copy()
    current_incidents = incidents[incidents["scenario"] == network].copy()

raw_alert_count = int(current_meta["n_alerts"].sum())
meta_count = len(current_meta)
flagged = current_meta[current_meta["score_model"] >= 0.5]
precision = float(flagged["label"].mean()) if len(flagged) and "label" in flagged else 0.0
incident_count = len(current_incidents)

# -----------------------------------------------------------------------------
# Overview
if page == "Overview":
    page_heading("SECURITY OPERATIONS / TRACK 02", "Your security overview", "A clear view of what needs attention across your selected evaluation network.")
    st.markdown(
        f'<div class="hero"><div class="hero-kicker">AlertLens · Investigation workspace</div>'
        f'<h2>Start with the signals most likely to matter.</h2>'
        f'<p>Model-ranked alerts are grouped into incidents, with evidence and explanations ready for review. '
        f'This view is using <b>{html.escape(nice_network(network))}</b> from the AIT-ADS dataset.</p>'
        f'<span class="hero-pill">● PRECOMPUTED EVALUATION DATA</span></div>',
        unsafe_allow_html=True,
    )
    cards = st.columns(4)
    cards[0].metric("Raw alerts", f"{raw_alert_count:,}", help="Raw events represented by the selected meta-alerts")
    cards[1].metric("Grouped alerts", f"{meta_count:,}", help="Deduplicated meta-alerts")
    cards[2].metric("High-risk", f"{len(flagged):,}", f"{precision:.0%} labeled precision" if len(flagged) else "No alerts above threshold")
    cards[3].metric("Incidents", f"{incident_count:,}", "Ranked for investigation")

    left, right = st.columns([1.55, 1])
    with left:
        st.markdown('<div class="section-head"><h3>Risk at a glance</h3><span class="section-note">Model score distribution</span></div>', unsafe_allow_html=True)
        hist = px.histogram(current_meta, x="score_model", nbins=30, color_discrete_sequence=["#4778eb"])
        hist.update_layout(height=300, margin=dict(l=12, r=12, t=10, b=10), xaxis_title="Risk score", yaxis_title="Meta-alerts", bargap=.08, showlegend=False)
        hist.update_xaxes(gridcolor="#edf0f5", zeroline=False)
        hist.update_yaxes(gridcolor="#edf0f5", zeroline=False)
        st.plotly_chart(hist, width="stretch", config={"displayModeBar": False})
    with right:
        st.markdown('<div class="section-head"><h3>Signals by source</h3><span class="section-note">Grouped alert count</span></div>', unsafe_allow_html=True)
        source_counts = current_meta.groupby("source", dropna=False)["n_alerts"].sum().sort_values(ascending=True).reset_index()
        source_plot = px.bar(source_counts, x="n_alerts", y="source", orientation="h", text_auto=True,
                             color="source", color_discrete_map={"wazuh": "#3569e8", "suricata": "#e25163", "aminer": "#30a68a"})
        source_plot.update_layout(height=300, margin=dict(l=12, r=16, t=10, b=10), xaxis_title="Raw alerts", yaxis_title=None, showlegend=False)
        source_plot.update_xaxes(gridcolor="#edf0f5", zeroline=False)
        st.plotly_chart(source_plot, width="stretch", config={"displayModeBar": False})

    st.markdown('<div class="section-head"><h3>Priority review</h3><span class="section-note">Highest ranked meta-alerts</span></div>', unsafe_allow_html=True)
    priority = current_meta.sort_values("score_model", ascending=False).head(8).copy()
    priority["time"] = priority["start_dt"].map(lambda x: fmt_time(x, "%b %d · %H:%M"))
    priority["why"] = priority["reasons"].map(reason_text)
    priority["risk"] = priority["score_model"]
    st.dataframe(
        priority[["risk", "time", "pred_stage", "source", "host", "rule_desc", "why"]].rename(columns={"pred_stage": "stage", "rule_desc": "detection", "source": "sensor"}),
        hide_index=True, width="stretch", height=350,
        column_config={"risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=1, format="%.3f"),
                       "why": st.column_config.TextColumn("Why it surfaced", width="large"),
                       "detection": st.column_config.TextColumn("Detection", width="large")},
    )

# -----------------------------------------------------------------------------
# Incident investigations
elif page == "Incident investigations":
    page_heading("INVESTIGATE", "Incident investigations", "Review a ranked incident, follow its timeline, and ask the local analyst about the evidence.")
    if current_incidents.empty:
        st.info("There are no incident records for this selection.")
    else:
        incident_rows = current_incidents.sort_values(["rank_in_scenario", "risk"], ascending=[True, False]).reset_index(drop=True)
        labels_by_id = {
            row["incident_id"]: f"#{int(row['rank_in_scenario'])} · Risk {row['risk']:.2f} · {fmt_time(row['start_dt'], '%b %d %H:%M')} · {row['n_meta']} grouped alerts"
            for _, row in incident_rows.iterrows()
        }
        selected_id = st.selectbox("Choose an incident", incident_rows["incident_id"].tolist(), format_func=lambda i: labels_by_id[i])
        incident = incident_rows[incident_rows["incident_id"] == selected_id].iloc[0].to_dict()
        evidence = current_meta[
            (current_meta["scenario"] == incident["scenario"])
            & (current_meta["incident_id"] == selected_id)
        ].copy()
        stages = incident.get("stages", []) or []
        st.markdown(
            f'<div class="hero"><div class="hero-kicker">{html.escape(nice_network(str(incident["scenario"])))}</div>'
            f'<h2>Incident #{int(incident["rank_in_scenario"])} <span style="font-size:1rem;font-weight:600">· {float(incident["risk"]):.0%} combined risk</span></h2>'
            f'<p>{fmt_time(incident["start_dt"])} — {fmt_time(incident["end_dt"])} · '
            f'{int(incident["n_alerts"]):,} raw alerts across {len(incident.get("hosts", []))} hosts</p></div>',
            unsafe_allow_html=True,
        )
        metrics = st.columns(4)
        metrics[0].metric("Combined risk", f"{float(incident['risk']):.0%}")
        metrics[1].metric("Evidence groups", f"{int(incident['n_meta']):,}")
        metrics[2].metric("Hosts", f"{len(incident.get('hosts', [])):,}")
        metrics[3].metric("Sensors", f"{len(incident.get('sensors', [])):,}")

        if not evidence.empty:
            evidence["stage_order"] = evidence["pred_stage"].map({s: i for i, s in enumerate(STAGE_ORDER)}).fillna(-1)
            evidence["size"] = np.log1p(evidence["n_alerts"].clip(lower=0)) + 1
            timeline = px.scatter(evidence.sort_values("start_dt"), x="start_dt", y="pred_stage", size="size", color="score_model",
                                 color_continuous_scale=[[0, "#8db4ff"], [1, "#dc4057"]], range_color=(0, 1),
                                 hover_data={"rule_desc": True, "host": True, "src_ip": True, "n_alerts": True, "size": False},
                                 title="Evidence timeline · model-predicted stage")
            timeline.update_layout(height=340, margin=dict(l=12, r=12, t=48, b=10), xaxis_title="Time (UTC)", yaxis_title=None,
                                   coloraxis_colorbar_title="Risk")
            timeline.update_xaxes(gridcolor="#edf0f5")
            st.plotly_chart(timeline, width="stretch", config={"displayModeBar": False})

        left, right = st.columns([1.05, .95])
        context = incident_context(current_meta, incident)
        key = f"{incident['scenario']}#{incident['incident_id']}"
        with left:
            st.markdown('<div class="section-head"><h3>AI incident report</h3><span class="section-note">Grounded in ranked evidence</span></div>', unsafe_allow_html=True)
            cached_report = results["narratives"].get(key)
            generated_now = False
            if cached_report:
                st.markdown(cached_report)
            elif status["ollama_online"]:
                if st.button("Generate incident report", type="primary", icon="✨", key=f"report_{key}"):
                    try:
                        with st.spinner(f"Asking {status['model']} to summarize this evidence…"):
                            report = st.write_stream(generate_report(context))
                        st.session_state.setdefault("reports", {})[key] = report
                        generated_now = True
                    except Exception as exc:
                        st.error(f"The local analyst could not generate a report: {exc}")
            else:
                st.info("Start Ollama locally to generate an incident report. Existing saved reports appear here.")
            generated = st.session_state.get("reports", {}).get(key)
            if generated and not cached_report and not generated_now:
                st.markdown(generated)
            st.markdown("**Attack stages**")
            if stages:
                for stage in stages:
                    st.markdown(f"- **{stage}** · {STAGE_MITRE.get(stage, 'No ATT&CK mapping recorded')}")
            else:
                st.caption("No stage was assigned to this incident.")
        with right:
            st.markdown('<div class="section-head"><h3>Ask the analyst</h3><span class="section-note">Local Ollama · evidence grounded</span></div>', unsafe_allow_html=True)
            history = st.session_state.setdefault("incident_chats", {}).setdefault(key, [])
            for message in history:
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])
            if status["ollama_online"]:
                question = st.chat_input("Ask about this incident…", key=f"chat_{key}")
                if question:
                    with st.chat_message("user"):
                        st.markdown(question)
                    history_for_model = list(history)
                    with st.chat_message("assistant"):
                        try:
                            answer = st.write_stream(ask_analyst(context, question, history_for_model))
                            history.extend([{"role": "user", "content": question}, {"role": "assistant", "content": answer}])
                        except Exception as exc:
                            st.error(f"The local analyst could not answer: {exc}")
            else:
                st.caption("Chat becomes available when the local Ollama service is running.")

        st.markdown('<div class="section-head"><h3>Evidence in this incident</h3><span class="section-note">Sorted by model risk</span></div>', unsafe_allow_html=True)
        evidence = evidence.sort_values("score_model", ascending=False).copy()
        evidence["risk"] = evidence["score_model"]
        evidence["time"] = evidence["start_dt"].map(lambda x: fmt_time(x, "%b %d · %H:%M:%S"))
        evidence["why"] = evidence["reasons"].map(reason_text)
        st.dataframe(evidence[["risk", "time", "pred_stage", "source", "host", "src_ip", "rule_desc", "n_alerts", "why"]]
                     .rename(columns={"pred_stage": "stage", "source": "sensor", "rule_desc": "detection", "n_alerts": "events"}),
                     hide_index=True, width="stretch", height=420,
                     column_config={"risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=1, format="%.3f"),
                                    "why": st.column_config.TextColumn("Why it surfaced", width="large"),
                                    "detection": st.column_config.TextColumn("Detection", width="large")})

# -----------------------------------------------------------------------------
# Alert triage
elif page == "Alert triage":
    page_heading("REVIEW QUEUE", "Alert triage", "Narrow the queue, understand each score, and suppress repeated false positives for this session.")
    top_a, top_b, top_c = st.columns([1.1, 1, 1.2])
    with top_a:
        min_score = st.slider("Minimum risk", 0.0, 1.0, 0.5, 0.05, format="%.2f")
    with top_b:
        sources = sorted(current_meta["source"].dropna().unique().tolist())
        selected_sources = st.multiselect("Sensors", sources, default=sources)
    with top_c:
        queue_size = st.select_slider("Queue size", options=[25, 50, 100, 200], value=50)
    search = st.text_input("Search host, IP, or detection", placeholder="e.g. 10.35.32.1 or SSH")

    suppressions = st.session_state.setdefault("suppressed_pairs", set())
    queue = current_meta[current_meta["score_model"] >= min_score].copy()
    queue = queue[queue["source"].isin(selected_sources)]
    if search.strip():
        query = search.strip().lower()
        search_cols = ["host", "src_ip", "rule_desc", "rule_id"]
        mask = pd.Series(False, index=queue.index)
        for column in search_cols:
            mask |= queue[column].fillna("").astype(str).str.lower().str.contains(query, regex=False)
        queue = queue[mask]
    queue["is_suppressed"] = [(row.rule_id, row.host) in suppressions for row in queue[["rule_id", "host"]].itertuples(index=False)]
    queue = queue[~queue["is_suppressed"]].sort_values("score_model", ascending=False).head(queue_size).copy()
    st.caption(f"Showing {len(queue):,} of {int((current_meta['score_model'] >= min_score).sum()):,} matching meta-alerts · suppression is temporary for this browser session.")
    if queue.empty:
        st.success("No alerts match these filters. Try lowering the risk threshold or selecting more sensors.")
    else:
        queue["select"] = False
        queue["risk"] = queue["score_model"]
        queue["time"] = queue["start_dt"].map(lambda x: fmt_time(x, "%b %d · %H:%M:%S"))
        queue["why"] = queue["reasons"].map(reason_text)
        editor = st.data_editor(
            queue[["select", "risk", "time", "pred_stage", "source", "host", "src_ip", "rule_desc", "n_alerts", "why"]]
            .rename(columns={"pred_stage": "stage", "source": "sensor", "rule_desc": "detection", "n_alerts": "events"}),
            hide_index=True, width="stretch", height=540,
            disabled=["risk", "time", "stage", "sensor", "host", "src_ip", "detection", "events", "why"],
            column_config={"select": st.column_config.CheckboxColumn("Select", help="Select related alerts to suppress for this session."),
                           "risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=1, format="%.3f"),
                           "why": st.column_config.TextColumn("Why it surfaced", width="large"),
                           "detection": st.column_config.TextColumn("Detection", width="large")},
            key=f"triage_editor_{network}_{min_score}_{','.join(selected_sources)}",
        )
        chosen = editor[editor["select"]]
        action_col, clear_col, _ = st.columns([1.3, 1.3, 4])
        with action_col:
            if st.button("Suppress selected", type="primary", disabled=chosen.empty):
                for row in chosen.itertuples():
                    suppressions.add((queue.loc[row.Index, "rule_id"], queue.loc[row.Index, "host"]))
                st.rerun()
        with clear_col:
            if st.button("Clear session suppressions", disabled=not suppressions):
                suppressions.clear()
                st.rerun()
        if not chosen.empty:
            st.info(f"{len(chosen)} selected. Matching rule and host pairs will be hidden until this session ends.")

# -----------------------------------------------------------------------------
# Model quality
else:
    page_heading("EVALUATION", "Model quality", "See how AlertLens ranked the held-out AIT-ADS networks and where its detections came from.")
    summary = results["summary"].rename(index=METHOD_NAMES)
    model_row = results["summary"].loc["model"]
    cards = st.columns(3)
    cards[0].metric("PR-AUC", f"{model_row['pr_auc']:.3f}", "Attack vs. benign meta-alerts")
    cards[1].metric("Precision · top 20", f"{model_row['p@20']:.0%}", "Across held-out networks")
    cards[2].metric("Benign alerts suppressed", f"{model_row['fp_suppressed@90recall']:.0%}", "At 90% attack recall")

    m1, m2 = st.columns(2)
    with m1:
        st.markdown('<div class="section-head"><h3>Ranking performance</h3><span class="section-note">Mean across 8 held-out networks</span></div>', unsafe_allow_html=True)
        plot_data = summary.reset_index(names="method")
        plot_data["method"] = plot_data["method"].map(lambda x: x)
        fig = px.bar(plot_data, x="pr_auc", y="method", orientation="h", text_auto=".3f", color="method",
                     color_discrete_map={"AlertLens": "#3569e8", "Isolation Forest": "#8b9ab0", "Rule rarity": "#8b9ab0", "Wazuh severity": "#8b9ab0"})
        fig.update_layout(height=330, margin=dict(l=12, r=12, t=10, b=10), xaxis_title="PR-AUC", yaxis_title=None, showlegend=False)
        fig.update_xaxes(gridcolor="#edf0f5")
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
    with m2:
        st.markdown('<div class="section-head"><h3>Features that matter</h3><span class="section-note">Mean LightGBM gain</span></div>', unsafe_allow_html=True)
        importance = results["importance"].head(12).iloc[::-1].reset_index()
        name_col = importance.columns[0]
        fig = px.bar(importance, x="gain", y=name_col, orientation="h", color_discrete_sequence=["#30a68a"])
        fig.update_layout(height=330, margin=dict(l=12, r=12, t=10, b=10), xaxis_title="Relative gain", yaxis_title=None)
        fig.update_xaxes(gridcolor="#edf0f5")
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

    per_network = results["by_network"]
    if network != "All networks":
        per_network = per_network[per_network["scenario"] == network]
    per_network = per_network[per_network["method"] == "model"]
    st.markdown('<div class="section-head"><h3>Held-out network results</h3><span class="section-note">Evaluation metrics by network</span></div>', unsafe_allow_html=True)
    st.dataframe(per_network.drop(columns="method", errors="ignore").round(3), hide_index=True, width="stretch")

    with st.expander("How to read these results"):
        st.markdown("""
- **PR-AUC** summarizes how well the model ranks attack-related alerts above benign alerts.
- **Precision at 20** is the share of the top 20 alerts that overlap a labeled attack window.
- **False positives suppressed** estimates the queue reduction while retaining 90% attack recall.
- Results use leave-one-network-out validation. They describe this synthetic evaluation dataset, not a live SOC feed.
""")
