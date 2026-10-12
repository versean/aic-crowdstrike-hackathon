"""AlertLens — a friendly SOC workspace for the AIT-ADS evaluation dataset."""
from __future__ import annotations

import html
import hmac
import json
import os
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
    workspace_context,
)
from blueteam.stages import STAGE_MITRE, STAGE_ORDER
from alertlens_design import apply_design, style_chart

ACCENT = "#ff4057"
CYAN = "#38d9e6"
AMBER = "#f5bb46"
GRID_DARK = "#28333a"

st.set_page_config(
    page_title="AlertLens | Blue Team Workspace",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="auto",
)

apply_design()

LOGIN_USERNAME = os.getenv("ALERTLENS_USERNAME", "admin")
LOGIN_PASSWORD = os.getenv("ALERTLENS_PASSWORD", "alertlens")

if not st.session_state.get("authenticated", False):
    st.markdown(
        '<div class="eyebrow">ALERTLENS / SECURE ACCESS</div>'
        '<div class="page-title">Analyst sign in</div>'
        '<div class="page-subtitle">Sign in to open the Blue Team workspace.</div>',
        unsafe_allow_html=True,
    )
    _, login_column, _ = st.columns([1, 1.15, 1])
    with login_column:
        st.markdown('<div class="hero"><div class="hero-kicker">TRACK 02 · DETECT</div><h2>Welcome back, analyst.</h2><p>Use your AlertLens workspace credentials to continue.</p></div>', unsafe_allow_html=True)
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", key="login_username", autocomplete="username")
            password = st.text_input("Password", type="password", key="login_password", autocomplete="current-password")
            submitted = st.form_submit_button("Sign in ↗", type="primary", use_container_width=True, key="login_submit")
        if submitted:
            valid_user = hmac.compare_digest(username.encode("utf-8"), LOGIN_USERNAME.encode("utf-8"))
            valid_password = hmac.compare_digest(password.encode("utf-8"), LOGIN_PASSWORD.encode("utf-8"))
            if valid_user and valid_password:
                st.session_state["authenticated"] = True
                st.rerun()
            st.error("Username or password is incorrect.")
        if "ALERTLENS_USERNAME" not in os.environ and "ALERTLENS_PASSWORD" not in os.environ:
            st.caption("Demo credentials: admin / alertlens · configure ALERTLENS_USERNAME and ALERTLENS_PASSWORD before sharing this app.")
        else:
            st.caption("Credentials are configured by the application environment.")
    st.stop()

METHOD_NAMES = {
    "model": "AlertLens",
    "isoforest": "Isolation Forest",
    "rarity": "Rule rarity",
    "wazuh_level": "Wazuh severity",
}

@st.cache_data(show_spinner="Connecting to AlertLens results…")
def cached_results(data_dir: str, version: float):
    return load_results(Path(data_dir))


@st.cache_data(ttl=10, show_spinner=False)
def cached_backend_status(data_dir: str):
    return backend_status(Path(data_dir))


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


def compact_count(value: int) -> str:
    """Keep dashboard KPIs legible in Streamlit's narrow responsive columns."""
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f}M"
    if value >= 10_000:
        return f"{value / 1_000:.1f}K"
    if value >= 1_000:
        return f"{value / 1_000:.1f}K"
    return f"{value:,}"


def page_heading(kicker: str, title: str, subtitle: str):
    st.markdown(
        f'<div class="eyebrow">{html.escape(kicker)}</div><div class="page-title">{html.escape(title)}</div>'
        f'<div class="page-subtitle">{html.escape(subtitle)}</div>',
        unsafe_allow_html=True,
    )


def nice_network(network: str) -> str:
    return "All networks" if network == "All networks" else network.upper()


with st.sidebar:
    st.markdown('<div class="brand">ALERT<span>LENS</span></div>', unsafe_allow_html=True)
    st.markdown('<div class="tiny-muted">AI powered detection &amp; triage</div>', unsafe_allow_html=True)
    st.divider()
    page = st.radio(
        "Workspace",
        ["Overview", "Pipeline & data", "Incident investigations", "Alert triage", "Model quality", "Ground truth", "Settings"],
        label_visibility="collapsed",
        format_func=lambda p: {
            "Overview": "◫  Overview",
            "Pipeline & data": "⇢  Pipeline & data",
            "Incident investigations": "◎  Incidents",
            "Alert triage": "⌕  Triage queue",
            "Model quality": "⌁  Model quality",
            "Ground truth": "⌖  Ground truth",
            "Settings": "⚙  Settings",
        }[p],
    )

active_data_dir = Path(st.session_state.get("backend_data_dir", str(DATA_DIR))).expanduser().resolve()
status = cached_backend_status(str(active_data_dir))

def render_settings(available_networks=None):
    page_heading("WORKSPACE", "Settings", "Manage the connected results, dataset view, and account.")
    st.markdown('<div class="section-head"><h3>Backend source</h3><span class="section-note">Saved result bundle</span></div>', unsafe_allow_html=True)
    st.text_input(
        "Results folder",
        value=str(active_data_dir),
        key="backend_data_dir",
        help="Choose the `data/` folder written by the AlertLens backend branch.",
    )
    st.caption("Use the backend checkout’s `data/` folder. Refresh after a pipeline run.")
    if st.button("Connect / refresh results", type="primary", key="refresh_results"):
        cached_backend_status.clear()
        cached_results.clear()
        st.rerun()

    st.markdown('<div class="section-head"><h3>Connection status</h3><span class="section-note">Current backend and analyst</span></div>', unsafe_allow_html=True)
    st.markdown(
        '<span class="status-chip status-ok">● Result bundle connected</span>'
        if status["ready"]
        else '<span class="status-chip status-warn">● Result bundle incomplete</span>',
        unsafe_allow_html=True,
    )
    if status["model_ready"]:
        st.markdown(f'<span class="status-chip status-ok">● Analyst online</span><div class="tiny-muted">Local model · {html.escape(status["model"])}</div>', unsafe_allow_html=True)
    elif status["ollama_online"]:
        st.markdown('<span class="status-chip status-warn">● Model not installed</span>', unsafe_allow_html=True)
        st.caption(f"Run: ollama pull {status['model']}")
    else:
        st.markdown('<span class="status-chip status-warn">● Analyst offline</span><div class="tiny-muted">Reports already in the dataset remain available. Start Ollama to generate new reports or chat.</div>', unsafe_allow_html=True)

    if available_networks:
        st.markdown('<div class="section-head"><h3>Dataset view</h3><span class="section-note">Choose the network shown across the workspace</span></div>', unsafe_allow_html=True)
        options = ["All networks", *available_networks]
        selected = st.session_state.get("dataset_network", "All networks")
        if selected not in options:
            selected = "All networks"
        st.selectbox("Dataset network", options, index=options.index(selected), format_func=nice_network, key="dataset_network")

    st.markdown('<div class="section-head"><h3>Account</h3></div>', unsafe_allow_html=True)
    st.caption(f"Connected results: `{active_data_dir}`")
    if st.button("Log out", key="logout_button"):
        for key in ("authenticated", "login_username", "login_password", "workspace_chats", "incident_chats", "reports"):
            st.session_state.pop(key, None)
        st.rerun()

if not status["ready"]:
    if page == "Settings":
        render_settings()
        st.error("AlertLens backend results are not available in the selected folder.")
        st.write(f"Missing: {', '.join(status['missing'])}")
        st.stop()
    st.error("AlertLens backend results are not available in the selected folder.")
    st.write(f"Looking for result files in `{active_data_dir}`.")
    st.write("Missing: " + ", ".join(status["missing"]))
    st.info("Open **Settings** to select the backend `data/` output folder and connect its result bundle.")
    st.stop()

version = max((active_data_dir / name).stat().st_mtime for name in ("meta_explained.parquet", "incidents.json", "stats.json"))
results = cached_results(str(active_data_dir), version)
meta = results["meta"]
incidents = results["incidents"]
scenarios = sorted(meta["scenario"].dropna().astype(str).unique())
if page == "Settings":
    render_settings(scenarios)
    st.stop()

network = st.session_state.get("dataset_network", "All networks")
if network not in ["All networks", *scenarios]:
    network = "All networks"

accent = ACCENT
grid = GRID_DARK

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
    page_heading("TRACK 02 / DETECT", "From noisy alerts to a clear lead.", "The backend scores the AIT-ADS sample; this workspace helps an analyst inspect and evaluate its ranked results.")
    st.markdown(
        f'<div class="hero"><div class="hero-kicker">AlertLens · Investigation workspace</div>'
        f'<h2>Find the attack signals inside 2.66M synthetic alerts.</h2>'
        f'<p>The model has ranked and explained the sample alerts, then grouped related evidence into incidents. '
        f'You are reviewing <b>{html.escape(nice_network(network))}</b>. The labeled attack windows are the answer key used to evaluate the ranking.</p>'
        f'<span class="hero-pill">● BACKEND RESULTS LOADED · AIT-ADS BENCHMARK</span></div>',
        unsafe_allow_html=True,
    )
    cards = st.columns(4)
    cards[0].metric("Raw alerts", compact_count(raw_alert_count), help=f"{raw_alert_count:,} raw events represented by the selected meta-alerts")
    cards[1].metric("Grouped alerts", compact_count(meta_count), help=f"{meta_count:,} deduplicated meta-alerts")
    cards[2].metric("High-risk", f"{len(flagged):,}", f"{precision:.0%} labeled precision" if len(flagged) else "No alerts above threshold")
    cards[3].metric("Incidents", f"{incident_count:,}", "Ranked for investigation")

    st.markdown('<div class="section-head"><h3>Risk at a glance</h3><span class="section-note">Model score distribution</span></div>', unsafe_allow_html=True)
    hist = px.histogram(current_meta, x="score_model", nbins=30, color_discrete_sequence=[accent])
    hist.update_layout(height=280, margin=dict(l=12, r=12, t=10, b=10), xaxis_title="Risk score", yaxis_title="Meta-alerts", bargap=.08, showlegend=False)
    hist.update_xaxes(gridcolor=grid, zeroline=False)
    hist.update_yaxes(gridcolor=grid, zeroline=False)
    st.plotly_chart(style_chart(hist), width="stretch", theme=None, config={"displayModeBar": False})

    st.markdown('<div class="section-head"><h3>Signals by source</h3><span class="section-note">Grouped alert count</span></div>', unsafe_allow_html=True)
    source_counts = current_meta.groupby("source", dropna=False)["n_alerts"].sum().sort_values(ascending=True).reset_index()
    source_plot = px.bar(source_counts, x="n_alerts", y="source", orientation="h", text_auto=True,
                         color="source", color_discrete_map={"wazuh": accent, "suricata": "#f5bb46", "aminer": CYAN})
    source_plot.update_layout(height=220, margin=dict(l=12, r=16, t=10, b=10), xaxis_title="Raw alerts", yaxis_title=None, showlegend=False)
    source_plot.update_xaxes(gridcolor=grid, zeroline=False)
    st.plotly_chart(style_chart(source_plot), width="stretch", theme=None, config={"displayModeBar": False})

    st.markdown('<div class="section-head"><h3>Alert reduction funnel</h3><span class="section-note">From raw events to ranked incidents · logarithmic scale</span></div>', unsafe_allow_html=True)
    funnel = pd.DataFrame({
        "stage": ["Raw alerts", "Grouped alerts", "High-risk groups", "Incidents"],
        "count": [raw_alert_count, meta_count, len(flagged), incident_count],
    })
    funnel_plot = px.bar(
        funnel, x="count", y="stage", orientation="h", text="count", color="stage",
        color_discrete_map={"Raw alerts": "#67747a", "Grouped alerts": CYAN, "High-risk groups": ACCENT, "Incidents": AMBER},
    )
    funnel_plot.update_layout(height=245, margin=dict(l=12, r=28, t=8, b=8), xaxis_title="Items · log scale", yaxis_title=None, showlegend=False)
    funnel_plot.update_xaxes(type="log", gridcolor=grid, zeroline=False)
    funnel_plot.update_traces(texttemplate="%{x:,}", textposition="outside", cliponaxis=False)
    st.plotly_chart(style_chart(funnel_plot), width="stretch", theme=None, config={"displayModeBar": False})

    with st.expander("What is this service doing?", expanded=True):
        st.markdown("""
**This is a security-alert sorting demo.** The AIT-ADS files are the input, not a reference set that customer data is matched against. They contain simulated normal activity mixed with alerts from staged attacks.

The backend combines alerts into groups, gives each group a risk rank and explanation, and links related groups into incidents. `labels.csv` marks known attack-phase time windows; the dashboard uses those labels afterward to check whether high-risk results match the known attacks. The chatbot answers questions about the displayed evidence.
""")

    export_cols = [c for c in ["scenario", "incident_id", "start_dt", "end_dt", "score_model", "label", "phase", "pred_stage", "source", "host", "src_ip", "rule_desc", "n_alerts", "reasons"] if c in current_meta.columns]
    export_frame = current_meta.sort_values("score_model", ascending=False)[export_cols].copy()
    export_frame["reasons"] = export_frame["reasons"].map(reason_text)
    st.download_button(
        "Download ranked results (CSV)", export_frame.to_csv(index=False).encode("utf-8"),
        file_name=f"alertlens-ranked-{network.lower().replace(' ', '-')}.csv", mime="text/csv",
        help="Export the backend's ranked groups, explanations and evaluation labels for this network selection.",
    )

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
# Pipeline and data
elif page == "Pipeline & data":
    page_heading("TRACK 02 / DATA TO DETECTION", "Pipeline & data", "See what goes in, what the backend produces, and how the evaluation labels are used.")
    st.markdown(
        '<div class="hero"><div class="hero-kicker">AIT-ADS · synthetic benchmark</div>'
        '<h2>Input → detection output → analyst review</h2>'
        '<p>The connected backend has processed this sample and exported the results displayed in the workspace. '
        'Use the network filter to follow one scenario through the same pipeline.</p>'
        '<span class="hero-pill">● RESULT BUNDLE READY</span></div>',
        unsafe_allow_html=True,
    )
    flow = st.columns(4)
    steps = [
        ("01 · INPUT", f"{raw_alert_count:,} raw alerts", "Wazuh, Suricata and AMiner JSON from the selected scenario."),
        ("02 · GROUP", f"{meta_count:,} alert groups", "Repeated related detections are consolidated into meta-alerts."),
        ("03 · RANK", f"{len(flagged):,} high-risk groups", "The model adds risk scores, predicted attack stages and reasons."),
        ("04 · INVESTIGATE", f"{incident_count:,} incidents", "Related high-risk groups become ranked incidents with timelines."),
    ]
    for col, (label, value, detail) in zip(flow, steps):
        with col:
            st.metric(label, value, help=detail)

    st.markdown('<div class="section-head"><h3>What the sample contains</h3><span class="section-note">The input is simulated security activity</span></div>', unsafe_allow_html=True)
    data_cols = st.columns(3)
    data_cols[0].metric("Scenarios", f"{meta['scenario'].nunique():,}", "Separate synthetic network environments")
    data_cols[1].metric("Sensors", f"{meta['source'].nunique():,}", "Wazuh · Suricata · AMiner")
    data_cols[2].metric("Attack-related groups", f"{int(current_meta['label'].sum()):,}", "Based on saved benchmark labels")
    st.markdown("""
| File or output | Role in the demo |
| --- | --- |
| `*_wazuh.json`, `*_aminer.json` | Raw alert input from the three detection sources. |
| `labels.csv` | Evaluation answer key: known attack-phase start and end times. It is not used as new customer input. |
| Ranked alert results | Backend output: risk score, predicted stage, grouped events and plain-language reasons. |
| Incident results | Backend output: related high-risk groups, ordered for analyst review. |
| Dashboard and Lens | Frontend: filter, inspect, export and ask questions about the saved evidence. |
""")
    with st.expander("Why are labels shown if the AI is supposed to detect attacks?"):
        st.write("The labels let us measure the detector on this known benchmark: did the high-ranked groups overlap the attack windows, and how much benign activity was left in the review queue? In a real environment without known answers, analysts would investigate the ranked evidence instead.")

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
                                 color_continuous_scale=[[0, CYAN], [1, ACCENT]], range_color=(0, 1),
                                 hover_data={"rule_desc": True, "host": True, "src_ip": True, "n_alerts": True, "size": False},
                                 title="Evidence timeline · model-predicted stage")
            timeline.update_layout(height=340, margin=dict(l=12, r=12, t=48, b=10), xaxis_title="Time (UTC)", yaxis_title=None,
                                   coloraxis_colorbar_title="Risk")
            timeline.update_xaxes(gridcolor=grid)
            st.plotly_chart(style_chart(timeline), width="stretch", theme=None, config={"displayModeBar": False})

        left, right = st.columns([1.05, .95])
        context = incident_context(current_meta, incident)
        key = f"{incident['scenario']}#{incident['incident_id']}"
        with left:
            st.markdown('<div class="section-head"><h3>AI incident report</h3><span class="section-note">Grounded in ranked evidence</span></div>', unsafe_allow_html=True)
            cached_report = results["narratives"].get(key)
            generated_now = False
            if cached_report:
                st.markdown(cached_report)
            elif status["model_ready"]:
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
            if status["model_ready"]:
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
        triage_export = queue[[c for c in ["scenario", "incident_id", "start_dt", "end_dt", "score_model", "label", "phase", "pred_stage", "source", "host", "src_ip", "rule_desc", "n_alerts", "reasons"] if c in queue.columns]].copy()
        triage_export["reasons"] = triage_export["reasons"].map(reason_text)
        st.download_button(
            "Download filtered queue (CSV)", triage_export.to_csv(index=False).encode("utf-8"),
            file_name=f"alertlens-queue-{network.lower().replace(' ', '-')}.csv", mime="text/csv",
            help="Export the rows visible after the current network, sensor, risk, search and suppression filters.",
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

    with st.expander("Ground-truth check for the visible queue"):
        if queue.empty:
            st.info("There are no visible alerts to compare with the saved evaluation labels.")
        elif "label" not in queue:
            st.info("This result bundle does not include alert-level evaluation labels.")
        else:
            labeled = queue[queue["label"].notna()]
            related = int(labeled["label"].astype(bool).sum())
            check_cols = st.columns(3)
            check_cols[0].metric("Visible queue", f"{len(queue):,}")
            check_cols[1].metric("Labeled attack-related", f"{related:,}")
            check_cols[2].metric("Labeled precision", f"{related / len(labeled):.0%}" if len(labeled) else "—")
            check = labeled.sort_values("score_model", ascending=False).head(100).copy()
            check["risk"] = check["score_model"]
            st.dataframe(
                check[["risk", "label", "phase", "host", "src_ip", "rule_desc"]]
                .rename(columns={"label": "attack-related", "phase": "labeled phase", "rule_desc": "detection"}),
                hide_index=True, width="stretch", height=300,
                column_config={"risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=1, format="%.3f"),
                               "detection": st.column_config.TextColumn("Detection", width="large")},
            )
            st.caption("Labels describe this saved evaluation dataset. They are for model review and do not establish live incident status.")

# -----------------------------------------------------------------------------
# Model quality
elif page == "Model quality":
    page_heading("EVALUATION", "Model quality", "See how AlertLens ranked the held-out AIT-ADS networks and where its detections came from.")
    summary = results["summary"].rename(index=METHOD_NAMES)
    model_row = results["summary"].loc["model"]
    cards = st.columns(5)
    cards[0].metric("PR-AUC", f"{model_row['pr_auc']:.3f}", "Attack vs. benign meta-alerts")
    cards[1].metric("Precision · top 20", f"{model_row['p@20']:.0%}", "Across held-out networks")
    cards[2].metric("Review · 90% recall", f"{model_row['queue_size@90recall']:.0f}", "Items to catch 90% of attacks")
    cards[3].metric("Attack phase recall", f"{results['stats']['phase_recall_flagged']:.0%}", "Phases surfaced by the model")
    cards[4].metric("Stage accuracy", f"{results['stats']['stage_accuracy']:.0%}", "Predicted kill-chain stage")

    m1, m2 = st.columns(2)
    with m1:
        st.markdown('<div class="section-head"><h3>Ranking performance</h3><span class="section-note">Mean across 8 held-out networks</span></div>', unsafe_allow_html=True)
        plot_data = summary.reset_index(names="method")
        plot_data["method"] = plot_data["method"].map(lambda x: x)
        fig = px.bar(plot_data, x="pr_auc", y="method", orientation="h", text_auto=".3f", color="method",
                     color_discrete_map={"AlertLens": accent, "Isolation Forest": "#8b9ab0", "Rule rarity": "#8b9ab0", "Wazuh severity": "#8b9ab0"})
        fig.update_layout(height=330, margin=dict(l=12, r=12, t=10, b=10), xaxis_title="PR-AUC", yaxis_title=None, showlegend=False)
        fig.update_xaxes(gridcolor=grid)
        st.plotly_chart(style_chart(fig), width="stretch", theme=None, config={"displayModeBar": False})
    with m2:
        st.markdown('<div class="section-head"><h3>Features that matter</h3><span class="section-note">Mean LightGBM gain</span></div>', unsafe_allow_html=True)
        importance = results["importance"].head(12).iloc[::-1].reset_index()
        name_col = importance.columns[0]
        fig = px.bar(importance, x="gain", y=name_col, orientation="h", color_discrete_sequence=[CYAN])
        fig.update_layout(height=330, margin=dict(l=12, r=12, t=10, b=10), xaxis_title="Relative gain", yaxis_title=None)
        fig.update_xaxes(gridcolor=grid)
        st.plotly_chart(style_chart(fig), width="stretch", theme=None, config={"displayModeBar": False})

    st.markdown('<div class="section-head"><h3>Review burden at equal attack recall</h3><span class="section-note">Mean across held-out networks · lower is better</span></div>', unsafe_allow_html=True)
    queue_plot = px.bar(
        summary.reset_index(names="method"),
        x="queue_size@90recall", y="method", orientation="h", text_auto=".0f", color="method",
        color_discrete_map={"AlertLens": ACCENT, "Isolation Forest": "#89949a", "Rule rarity": "#89949a", "Wazuh severity": AMBER},
    )
    queue_plot.update_layout(height=290, margin=dict(l=12, r=26, t=8, b=8), xaxis_title="Items to review · log scale", yaxis_title=None, showlegend=False)
    queue_plot.update_xaxes(type="log", gridcolor=grid, zeroline=False)
    st.plotly_chart(style_chart(queue_plot), width="stretch", theme=None, config={"displayModeBar": False})

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

elif page == "Ground truth":
    page_heading("EVALUATION / LABEL REVIEW", "Ground truth over time", "Compare ranked evidence with the attack phases in the saved AIT-ADS evaluation labels.")
    labels = results["labels"]
    if labels.empty:
        st.info("No labels.csv was found beside the configured data directory. The ground-truth timeline requires this optional file.")
    else:
        labeled_networks = sorted(set(labels["scenario"].dropna().astype(str)) & set(meta["scenario"].dropna().astype(str)))
        if not labeled_networks:
            st.info("The saved label file has no networks that match this result bundle.")
        else:
            selected_truth_network = network if network in labeled_networks else st.selectbox(
                "Evaluation network", labeled_networks, key="ground_truth_network"
            )
            truth_labels = labels[labels["scenario"].astype(str) == selected_truth_network].copy()
            truth_meta = meta[meta["scenario"].astype(str) == selected_truth_network].copy()
            if not truth_meta.empty:
                flagged_truth = truth_meta[truth_meta["score_model"] >= 0.5]
                truth_metrics = st.columns(4)
                truth_metrics[0].metric("Attack-related groups", f"{int(truth_meta['label'].sum()):,}")
                truth_metrics[1].metric("Saved attack phases", f"{len(truth_labels):,}")
                truth_metrics[2].metric("Groups above 0.5 risk", f"{len(flagged_truth):,}")
                truth_metrics[3].metric("Labeled precision above 0.5", f"{flagged_truth['label'].mean():.0%}" if len(flagged_truth) else "—")

                truth_meta["risk_class"] = np.where(truth_meta["label"].astype(bool), "Attack-related", "Other")
                timeline = px.scatter(
                    truth_meta[truth_meta["score_model"] >= 0.05],
                    x="start_dt", y="score_model", color="risk_class",
                    color_discrete_map={"Attack-related": ACCENT, "Other": CYAN},
                    size=np.log1p(truth_meta.loc[truth_meta["score_model"] >= 0.05, "n_alerts"]) * 2 + 4,
                    hover_data={"rule_desc": True, "host": True, "src_ip": True, "phase": True, "n_alerts": True, "risk_class": False},
                    labels={"start_dt": "Time (UTC)", "score_model": "Model risk", "risk_class": "Saved label"},
                )
                for label_row in truth_labels.itertuples():
                    timeline.add_vrect(
                        x0=label_row.start_dt, x1=max(label_row.end_dt, label_row.start_dt + pd.Timedelta(seconds=60)),
                        fillcolor=AMBER, opacity=0.12, line_width=0,
                    )
                timeline.add_hline(y=0.5, line_dash="dash", line_color=AMBER, opacity=0.75)
                timeline.update_layout(height=480, margin=dict(l=20, r=20, t=55, b=25), yaxis_title="Model risk score", xaxis_title="Time (UTC)")
                timeline.update_yaxes(range=[0, 1], gridcolor=grid, zeroline=False)
                st.plotly_chart(style_chart(timeline), width="stretch", theme=None, config={"displayModeBar": False})
                st.caption("Amber bands mark labeled attack phases; red points are attack-related meta-alerts. The saved labels support retrospective evaluation and do not indicate live security status.")

                with st.expander("Labeled attack phase windows"):
                    phase_view = truth_labels.assign(
                        phase=truth_labels["attack"].astype(str).str.replace("_", " ", regex=False),
                        start_utc=truth_labels["start_dt"].dt.strftime("%b %d · %H:%M UTC"),
                        end_utc=truth_labels["end_dt"].dt.strftime("%b %d · %H:%M UTC"),
                    )
                    st.dataframe(phase_view[["phase", "start_utc", "end_utc"]], hide_index=True, width="stretch")

                with st.expander("Review highest-risk evidence for this network"):
                    ranked = truth_meta.sort_values("score_model", ascending=False).head(100).copy()
                    ranked["risk"] = ranked["score_model"]
                    ranked["time"] = ranked["start_dt"].map(lambda value: fmt_time(value, "%b %d · %H:%M:%S"))
                    ranked["why"] = ranked["reasons"].map(reason_text)
                    st.dataframe(
                        ranked[["risk", "label", "phase", "time", "host", "src_ip", "rule_desc", "why"]]
                        .rename(columns={"label": "attack-related", "phase": "labeled phase", "rule_desc": "detection"}),
                        hide_index=True, width="stretch", height=420,
                        column_config={"risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=1, format="%.3f"),
                                       "why": st.column_config.TextColumn("Why it surfaced", width="large"),
                                       "detection": st.column_config.TextColumn("Detection", width="large")},
                    )

# A native Streamlit panel keeps chat state and local model calls on the server.
# Its keyed container is positioned by alertlens_design.py and rendered on every workspace page.
with st.container(key="security_assistant"):
    st.markdown('<div class="assistant-title"><span>◉</span> Lens assistant</div>', unsafe_allow_html=True)
    expanded = st.toggle("Open security chat", key="assistant_open", value=False)
    if expanded:
        st.markdown('<div class="assistant-note">LOCAL AI · EVALUATION SNAPSHOT</div><style>.st-key-security_assistant { width:min(340px,calc(100vw - 28px)); padding:12px; }</style>', unsafe_allow_html=True)
        st.caption(f"Context: {nice_network(network)} · {page}")
        st.caption("Saved evidence only. Live security status is unknown; verify AI suggestions.")
        chats = st.session_state.setdefault("workspace_chats", {})
        history = chats.setdefault(network, [])
        with st.container(height=190, key="assistant_history"):
            if not history:
                st.markdown("Ask **What needs attention?**, **Which hosts are affected?**, or **What should I investigate first?**")
            for message in history:
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])
        if not status["model_ready"]:
            if status["ollama_online"]:
                st.warning(f"Model missing. Run: ollama pull {status['model']}")
            else:
                st.info("Start the local analyst with frontend/scripts/start-local.sh, then refresh connection.")
        with st.form("workspace_chat_form", clear_on_submit=True):
            question = st.text_input("Ask about security", placeholder="What needs attention?", max_chars=2000, disabled=not status["model_ready"])
            submitted = st.form_submit_button("Ask Lens ↗", disabled=not status["model_ready"], use_container_width=True)
        if submitted and question.strip():
            context = workspace_context(current_meta, current_incidents, network, page)
            if page == "Incident investigations" and not current_incidents.empty:
                context += "\nSelected incident details:\n" + incident_context(current_meta, incident)
            try:
                with st.spinner("Reviewing the evidence…"):
                    answer = "".join(ask_analyst(context, question.strip(), history))
                if not answer.strip():
                    raise ValueError("The model returned no answer. Try again.")
                history.extend([{"role": "user", "content": question.strip()}, {"role": "assistant", "content": answer}])
                del history[:-20]
                st.rerun()
            except Exception as exc:
                st.error(f"Local analyst unavailable: {exc}")
        if history and st.button("Clear conversation", key="clear_workspace_chat"):
            history.clear()
            st.rerun()
