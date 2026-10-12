"""AlertLens - AI-powered Blue Team triage over the AIT Alert Data Set (streamlit run app.py)."""
import html
import json

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.io as pio
import streamlit as st

from blueteam.baseline import LEARNING_HOURS, display_value, feature_info
from blueteam.explain import STAGE_MITRE, STAGE_ORDER, confidence_tier
from blueteam.ingest import DATA_DIR
from blueteam import llm, threathunt
from blueteam.design import apply_design

st.set_page_config(page_title="AlertLens", layout="wide")
apply_design()

RED, BLUE, AMBER, GRAY, MUTED, LINE = "#ff4964", "#49e5ee", "#f3c66a", "#9a9a9a", "#444444", "#222222"
METHOD_NAMES = {
    "model": "AlertLens",
    "isoforest": "Isolation Forest",
    "rarity": "Rarest rule first",
    "wazuh_level": "Wazuh severity (today)",
}

pio.templates["alertlens"] = go.layout.Template(layout=dict(
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter, -apple-system, Helvetica Neue, Arial, sans-serif", color="#c9d3d4", size=12),
    title=dict(font=dict(size=13, color="#f4f7f5", family="Space Grotesk, Inter, sans-serif"), x=0, xanchor="left"),
    xaxis=dict(gridcolor=LINE, zerolinecolor=LINE, linecolor=LINE),
    yaxis=dict(gridcolor=LINE, zerolinecolor=LINE, linecolor=LINE),
    colorway=[RED, BLUE, AMBER, GRAY], hoverlabel=dict(bgcolor="#111111", bordercolor=LINE)))
pio.templates.default = "alertlens"

st.markdown("""
<style>
:root { color-scheme:dark; --bg:#000; --panel:#0a0a0a; --panel-raised:#101010; --ink:#f2f2f2; --muted:#9a9a9a;
        --line:#222; --grid:transparent; --hero:#0a0a0a; --sidebar:#000; --shadow:none; }
[data-testid="stAppViewContainer"], [data-testid="stHeader"], [data-testid="stSidebar"] {
  background:#000 !important; background-image:none !important; box-shadow:none !important; backdrop-filter:none !important;}
[data-testid="stAppViewContainer"]::before, .hero::before, .hero::after, [data-testid="stMetric"]::after {display:none !important;}
*, *::before, *::after {animation:none !important;}
.brand::before, .brand span {text-shadow:none !important;}
.hero {background:var(--panel) !important; border-left:2px solid var(--accent) !important; box-shadow:none !important;}
[data-testid="stMetric"] {background:var(--panel) !important; border-top:1px solid var(--line) !important;}
[data-testid="stMetric"]:hover, div[data-testid="stPlotlyChart"]:hover {transform:none; box-shadow:none;}
.status-chip { background:transparent; }
#MainMenu, footer, [data-testid="stDecoration"] {visibility: hidden;}
.chip {display: inline-block; padding: 2px 10px; border-radius: 999px; font: 600 .62rem 'IBM Plex Mono', monospace;
       letter-spacing: .08em; vertical-align: middle; border: 1px solid currentColor;}
.chip-high {color: var(--accent); background: color-mix(in srgb, var(--accent) 10%, transparent);}
.chip-medium {color: var(--amber); background: color-mix(in srgb, var(--amber) 8%, transparent);}
.chip-low {color: var(--muted); background: transparent;}
.inc-title {font: 700 1.35rem 'Space Grotesk', Inter, sans-serif; letter-spacing: -.03em; color: var(--ink);
            margin: 18px 0 8px;}
.inc-title .when {color: var(--muted); font: 400 .82rem 'IBM Plex Mono', monospace; letter-spacing: 0; margin-left: 10px;}
.kv {color: var(--muted); font-size: .76rem; line-height: 1.75;}
.kv b {color: var(--ink); font-weight: 500;}
.kv .lbl {font-family: 'IBM Plex Mono', monospace; font-size: .6rem; letter-spacing: .1em; text-transform: uppercase;}
</style>
""", unsafe_allow_html=True)


def page_heading(kicker: str, title: str, subtitle: str):
    st.markdown(f'<div class="eyebrow">{html.escape(kicker)}</div><div class="page-title">{html.escape(title)}</div>'
                f'<div class="page-subtitle">{subtitle}</div>', unsafe_allow_html=True)


def section(title: str, note: str = ""):
    st.markdown(f'<div class="section-head"><h3>{html.escape(title)}</h3>'
                f'<span class="section-note">{html.escape(note)}</span></div>', unsafe_allow_html=True)


def chart(fig, where=st):
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    fig.update_xaxes(automargin=True)
    fig.update_yaxes(automargin=True)
    where.plotly_chart(fig, width="stretch", theme=None, config={"displayModeBar": False})


def chip(tier: str) -> str:
    return f'<span class="chip chip-{tier}">{tier.upper()}</span>'


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
networks = sorted(meta["scenario"].unique())

PAGES = {"Overview": "◫  Overview", "Incidents": "◎  Incidents", "Why suspicious": "⌁  Why suspicious",
         "Alert queue": "⌕  Alert queue", "Threat hunt": "⌖  Threat hunt", "Ground truth": "✓  Ground truth"}

with st.sidebar:
    st.markdown('<div class="brand">ALERT<span>LENS</span></div>', unsafe_allow_html=True)
    st.markdown('<div class="tiny-muted">AI-powered detection &amp; triage</div>', unsafe_allow_html=True)
    st.divider()
    page = st.radio("Workspace", list(PAGES), format_func=PAGES.get, label_visibility="collapsed")
    st.divider()
    net = st.selectbox("Network", networks, index=networks.index("santos"))
    n_inc = int((incidents["scenario"] == net).sum())
    n_flag = int(((meta["scenario"] == net) & (meta["score_model"] >= 0.5)).sum())
    st.markdown(f'<div class="kv">Incidents <b>{n_inc}</b> &nbsp;·&nbsp; flagged alerts <b>{n_flag}</b></div>',
                unsafe_allow_html=True)
    st.divider()
    st.markdown(
        '<div class="kv"><span class="lbl">Detection</span><br><b>LightGBM, 5-seed ensemble</b><br>'
        '<span class="lbl">Validation</span><br><b>leave-one-network-out</b><br>'
        '<span class="lbl">Features</span><br><b>past alerts only (streaming-safe)</b><br>'
        '<span class="lbl">Analyst LLM</span><br><b>qwen3:14b, local (Ollama)</b><br>'
        f'<span class="lbl">Suppression rules</span><br><b>{len(st.session_state["suppressed"])}</b></div>',
        unsafe_allow_html=True)

# ------------------------------------------------------------------ overview
if page == "Overview":
    page_heading("TRACK 02 / DETECT", "From noisy alerts to a clear lead.",
                 "Wazuh · Suricata · AMiner. Every score comes from a model that never trained on that network.")
    st.markdown(
        f'<div class="hero"><div class="hero-kicker">AlertLens · Investigation workspace</div>'
        f'<h2>{stats["n_alerts"] / 1e6:.2f}M alerts in, {stats["n_incidents"]} ranked incidents out.</h2>'
        f'<p>Duplicates are merged into meta-alerts, scored with LightGBM, explained with SHAP and chained into '
        f'incidents. A local LLM writes the report. You are reviewing <b>{html.escape(net.upper())}</b>.</p>'
        f'<span class="hero-pill">● #1 INCIDENT IS THE REAL ATTACK IN 8 OF 8 NETWORKS</span></div>',
        unsafe_allow_html=True)
    c = st.columns(5)
    c[0].metric("Raw alerts", f"{stats['n_alerts'] / 1e6:.2f}M")
    c[1].metric("Meta-alerts", f"{stats['n_meta'] / 1e3:.0f}K", help="Duplicates merged: same host, rule, source within 5 min")
    c[2].metric("Flagged", f"{stats['n_flagged_meta']:,}", help=f"{stats['flagged_precision']:.0%} are real attack")
    c[3].metric("Incidents", stats["n_incidents"], help="#1 incident is the real attack in 8 of 8 networks")
    c[4].metric("Phases found", f"{stats['phase_recall_flagged']:.0%}",
                help=f"Attack stage predicted correctly: {stats['stage_accuracy']:.0%}")

    def hbar(y, x, text, colors, title, log=False, rng=None):
        fig = go.Figure(go.Bar(y=y, x=x, orientation="h", text=text, textposition="outside", marker_color=colors,
                               cliponaxis=False))
        fig.update_xaxes(type="log" if log else "linear", range=rng, showgrid=False, showticklabels=False,
                         zeroline=False)
        fig.update_yaxes(autorange="reversed", showgrid=False)
        fig.update_layout(height=270, margin=dict(l=10, r=60, t=40, b=10), title=title, bargap=0.35)
        return fig

    cols = st.columns(3, gap="large")
    vals = [stats["n_alerts"], stats["n_meta"], stats["n_flagged_meta"], stats["n_incidents"]]
    chart(hbar(["Raw alerts", "Meta-alerts", "Flagged", "Incidents"], vals, [f"{v:,}" for v in vals],
               [MUTED, BLUE, AMBER, RED], "From alerts to incidents", log=True, rng=[0, 7.3]), cols[0])
    s = summary.rename(index=METHOD_NAMES)
    colors = [RED if m == "AlertLens" else MUTED for m in s.index]
    chart(hbar(s.index, s["pr_auc"], [f"{v:.2f}" for v in s["pr_auc"]], colors,
               "Ranking quality (PR-AUC, 1 = perfect)", rng=[0, 1.2]), cols[1])
    chart(hbar(s.index, s["queue_size@90recall"], [f"{v:,.0f}" for v in s["queue_size@90recall"]], colors,
               "Items to review for 90% of the attack", log=True, rng=[1, 4.5]), cols[2])
    st.markdown(
        f"At 90% attack recall AlertLens hides **{summary.loc['model', 'fp_suppressed@90recall']:.2%}** of benign "
        f"meta-alerts: the review queue per network drops from about "
        f"{summary.loc['wazuh_level', 'queue_size@90recall']:,.0f} (sorted by Wazuh severity) to "
        f"**{summary.loc['model', 'queue_size@90recall']:.0f}**.")

    with st.expander("Per-network results"):
        st.dataframe(by_sc[by_sc.method == "model"].drop(columns="method").round(3), hide_index=True)
    abl_path = DATA_DIR / "ablation.csv"
    if abl_path.exists():
        with st.expander("Ablation: which feature groups matter"):
            abl = pd.read_csv(abl_path)
            st.dataframe(abl[["config", "n_features", "pr_auc", "p@20", "p@50", "phases@50", "queue_size@90recall"]]
                         .round(3), hide_index=True)
            st.caption("Knowing only what a rule is (semantics only) gives PR-AUC 0.49. Behavioural context (rarity, "
                       "novelty, burst shape, actor history) lifts it to 0.96. Removing the time-window context "
                       "features costs only 0.02, so the model is not just learning when the attack happened.")
    with st.expander("What drives the risk score"):
        top = imp.head(15).iloc[::-1]
        f = go.Figure(go.Bar(x=top["gain"], y=top.index, orientation="h", marker_color=BLUE))
        f.update_layout(height=420, margin=dict(l=10, r=10, t=10, b=10), xaxis_title="mean LightGBM gain")
        chart(f)
    with st.expander("How it works"):
        st.markdown("""
1. **Ingest** 2.66M alerts from Wazuh, Suricata and AMiner into one schema.
2. **Deduplicate** into meta-alerts: same network, host, rule and source IP within 5 minutes.
3. **Feature calcers**, computed per network from past alerts only: rule rarity and novelty, source-IP novelty, burst
   shape, multi-sensor activity in a 10-minute window, rule semantics and MITRE tactic, attacker vs. admin indicators
   in the raw log lines, account novelty.
4. **LightGBM** (tuned, 5-seed ensemble), trained leave-one-network-out so scores reflect an unseen environment.
5. **Explain**: SHAP contributions become plain-English reasons; a second model predicts the kill-chain stage and
   MITRE ATT&CK technique.
6. **Incidents**: flagged meta-alerts chained by time (≤ 60 min gap), ranked by risk and number of stages.
7. **Local LLM** (Ollama, qwen3:14b; no telemetry leaves the SOC) writes the report and answers questions, using
   only the ranked evidence.
""")

# ------------------------------------------------------------------ incidents
if page == "Incidents":
    page_heading("INVESTIGATE", "Incident investigations.", "Flagged meta-alerts chained by time, ranked by risk and number of kill-chain stages.")
    inc_sc = incidents[incidents["scenario"] == net].sort_values("rank_in_scenario")
    view = inc_sc.assign(
        window=inc_sc["start_dt"].dt.strftime("%m-%d %H:%M") + " – " + inc_sc["end_dt"].dt.strftime("%H:%M"),
        stages=inc_sc["stages"].apply(" › ".join),
        confidence=[confidence_tier(r).upper() for r in inc_sc.to_dict("records")],
    )[["rank_in_scenario", "risk", "confidence", "window", "n_meta", "n_alerts", "stages", "sensors"]]
    st.dataframe(view.rename(columns={"rank_in_scenario": "#", "n_meta": "meta-alerts", "n_alerts": "raw alerts"}),
                 hide_index=True, width="stretch",
                 column_config={"risk": st.column_config.ProgressColumn("risk", min_value=0, format="%.2f",
                                                                        max_value=float(incidents["risk"].max()))})
    rank = st.segmented_control("Open incident", inc_sc["rank_in_scenario"].tolist(), default=1,
                                format_func=lambda r: f"#{r}", key=f"inc_pick_{net}") or 1
    inc = inc_sc[inc_sc["rank_in_scenario"] == rank].iloc[0].to_dict()
    m = meta[(meta["scenario"] == net) & (meta["incident_id"] == inc["incident_id"])].copy()

    st.markdown(
        f'<div class="inc-title">Incident #{rank} &nbsp;{chip(confidence_tier(inc))}'
        f'<span class="when">{inc["start_dt"]:%b %d, %H:%M} – {inc["end_dt"]:%H:%M} UTC · '
        f'{", ".join(inc["hosts"][:4])}</span></div>', unsafe_allow_html=True)
    c = st.columns(4)
    c[0].metric("Risk", f"{inc['risk']:.2f}")
    c[1].metric("Raw alerts collapsed", f"{inc['n_alerts']:,}")
    c[2].metric("Kill-chain stages", inc["n_stages"])
    c[3].metric("Hosts involved", len(inc["hosts"]))

    m["stage"] = pd.Categorical(m["pred_stage"], categories=STAGE_ORDER[::-1], ordered=True)
    m = m.sort_values("stage")
    f = go.Figure(go.Scatter(
        x=m["start_dt"], y=m["stage"].astype(str), mode="markers",
        marker=dict(size=np.log1p(m["n_alerts"]) * 4 + 7, color=m["score_model"], cmin=0.5, cmax=1,
                    colorscale=[[0, AMBER], [1, RED]], line=dict(width=1, color="#0B1220"),
                    colorbar=dict(title="risk", thickness=10)),
        customdata=m[["rule_desc", "host", "src_ip", "n_alerts"]].fillna("").to_numpy(),
        hovertemplate="%{customdata[0]}<br>%{customdata[1]} · %{customdata[2]}<br>%{customdata[3]} alerts"
                      "<br>risk %{marker.color:.2f}<extra></extra>"))
    f.update_yaxes(categoryorder="array", categoryarray=[s for s in STAGE_ORDER if s in set(m["pred_stage"])])
    f.update_layout(height=340, margin=dict(l=10, r=10, t=40, b=10), title="Kill chain (predicted stage per meta-alert)",
                    xaxis_title="UTC")
    chart(f)

    left, right = st.columns([3, 2], gap="large")
    key = f"{net}#{inc['incident_id']}"
    ctx = llm.incident_context(meta, inc)
    with left:
        section("Analyst report", "Local qwen3:14b · evidence only")
        narratives = load_narratives()
        if key in narratives:
            with st.container(border=True):
                st.markdown(narratives[key])
        elif st.button("Generate report", key=f"gen_{key}"):
            st.write_stream(llm.narrate(ctx, stream=True))
        else:
            st.info("No report cached for this incident yet. Generating one takes about 1–2 minutes locally.")
    with right:
        section("Ask about this incident", "Grounded in ranked evidence")
        hist = st.session_state["chat"].setdefault(key, [])
        for msg in hist:
            st.chat_message(msg["role"]).markdown(msg["content"])
        q = st.chat_input("Which IP is the attacker? Is this a false positive?", key=f"chat_{key}")
        if q:
            st.chat_message("user").markdown(q)
            with st.chat_message("assistant"):
                ans = st.write_stream(llm.ask(ctx, q, history=hist, stream=True))
            hist += [{"role": "user", "content": q}, {"role": "assistant", "content": ans}]
        section("MITRE ATT&CK", "Predicted techniques")
        st.dataframe(pd.DataFrame({"stage": inc["stages"], "technique": [STAGE_MITRE.get(s, "") for s in inc["stages"]]}),
                     hide_index=True, width="stretch")

    section("Evidence, ranked by risk", "Sorted by model risk")
    ev = m.sort_values("score_model", ascending=False)
    ev = ev.assign(why=ev["reasons"].apply(lambda r: " · ".join(x["text"] for x in json.loads(r or "[]")[:3])),
                   time=ev["start_dt"].dt.strftime("%m-%d %H:%M:%S"))
    st.dataframe(ev[["score_model", "time", "pred_stage", "source", "host", "src_ip", "rule_desc", "n_alerts", "why"]],
                 hide_index=True, width="stretch",
                 column_config={"score_model": st.column_config.ProgressColumn("risk", min_value=0, max_value=1, format="%.3f"),
                                "pred_stage": "stage", "rule_desc": "rule", "n_alerts": "alerts"})


# ------------------------------------------------------------------ why suspicious
def why_view():
    if not all((DATA_DIR / f).exists() for f in BASELINE_FILES):
        st.info("Run `python -m blueteam.baseline` to build the baseline / learning-period view.")
        return
    lp, fb, rh, ns, bd = load_baseline(max((DATA_DIR / f).stat().st_mtime for f in BASELINE_FILES))
    cand = meta[(meta["scenario"] == net) & meta.index.isin(bd.index)].sort_values("score_model", ascending=False)
    pick = st.selectbox(
        "Alert (ranked by risk)", cand.index, key=f"why_pick_{net}",
        format_func=lambda i: f"{cand.at[i, 'score_model']:.2f}   {cand.at[i, 'start_dt']:%m-%d %H:%M}   "
                              f"{cand.at[i, 'host']}   {cand.at[i, 'rule_desc'][:80]}")
    row, b, L = meta.loc[pick], bd.loc[pick], lp.loc[net]
    t0, learn_end = pd.to_datetime(L["t0"], unit="s"), pd.to_datetime(L["learn_end"], unit="s")
    in_learning = row["start"] < L["learn_end"]

    k = st.columns(4)
    k[0].metric("Risk score", f"{row['score_model']:.1%}",
                help="From models trained on the other 7 networks only (leave-one-network-out).")
    k[1].metric("Predicted stage", row["pred_stage"] if pd.notna(row["pred_stage"]) else "not flagged")
    k[2].metric("History before this alert", f"{(row['start'] - L['t0']) / 3600:.0f} h")
    k[3].metric("Baseline", "still learning" if in_learning else "established")
    st.caption(
        f"Learning period for {net}: the first {LEARNING_HOURS} h of monitoring ({t0:%m-%d %H:%M} – "
        f"{learn_end:%m-%d %H:%M} UTC), {L['n_alerts_learning']:,.0f} alerts from {L['n_rules_learning']:.0f} rules. "
        "\"Normal\" below is what a typical alert in this network looked like during that period. After it, every "
        "feature keeps using all alerts before the one being scored, never after.")
    if in_learning:
        st.warning("This alert falls inside the learning period, so the baseline is still forming. Treat the score "
                   "with lower confidence.")

    contrib = json.loads(b["contrib"])
    section("Baseline vs. this alert", "Learning-period baseline")
    rows = []
    for feat, v, cval in contrib:
        label, kind = feature_info(feat)
        base = fb.loc[(net, feat)] if (net, feat) in fb.index else None
        if base is None:
            normal = "–"
        elif kind == "flag":
            normal = f"present in {base['nonzero']:.1%} of alerts"
        else:
            normal = f"{display_value(feat, base['median'])}  (95% of alerts ≤ {display_value(feat, base['p95'])})"
        rows.append({"signal": label, "this alert": display_value(feat, v), "normal in this network": normal,
                     "push on score": cval, "effect": "more suspicious" if cval > 0 else "less suspicious"})
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", column_config={
        "push on score": st.column_config.NumberColumn(format="%+.2f", help="Tree-SHAP contribution in log-odds")})

    names = ["Typical alert (prior)"] + [feature_info(f)[0] for f, _, _ in contrib] + ["All other signals",
                                                                                      "This alert"]
    vals = [b["bias"]] + [cv for _, _, cv in contrib] + [b["rest"], 0]
    f = go.Figure(go.Waterfall(
        orientation="h", y=names, x=vals, measure=["absolute"] + ["relative"] * (len(contrib) + 1) + ["total"],
        increasing=dict(marker_color=RED), decreasing=dict(marker_color=BLUE),
        totals=dict(marker_color=GRAY), connector=dict(line=dict(color=LINE)),
        text=[f"{v:+.2f}" for v in vals[:-1]] + [f"{row['score_model']:.1%}"],
        textposition="outside", cliponaxis=False))
    f.update_layout(
        height=480, margin=dict(l=10, r=90, t=50, b=10), yaxis=dict(autorange="reversed"),
        xaxis_title="log-odds of attack (0 = 50/50)",
        title=f"Score breakdown: from {sigmoid(b['bias']) * 100:.2g}% for a typical alert to {row['score_model']:.1%}")
    chart(f)

    at = pd.to_datetime(row["start"], unit="s")

    def mark(fig):
        fig.add_vrect(x0=t0, x1=learn_end, fillcolor=BLUE, opacity=0.12, line_width=0, layer="below",
                      annotation_text="learning period", annotation_position="top left",
                      annotation_font_color=GRAY)
        fig.add_vrect(x0=at, x1=at + pd.Timedelta(minutes=30), fillcolor=RED, opacity=0.6, line_width=0,
                      layer="below", annotation_text="this alert", annotation_position="top right",
                      annotation_font_color=RED)

    left, right = st.columns(2)
    with left:
        hours = pd.RangeIndex(int(L["t0"] // 3600 * 3600), int(L["t_end"]) + 3600, 3600)
        h = rh[(rh["scenario"] == net) & (rh["rule_id"] == row["rule_id"])].set_index("hour")["n"]
        h = h.reindex(hours, fill_value=0)
        learn = h[h.index < L["learn_end"]]
        f = go.Figure(go.Bar(x=pd.to_datetime(h.index, unit="s"), y=h.to_numpy(), marker_color=MUTED,
                             marker_line_width=0, name="alerts / hour"))
        mark(f)
        f.add_hline(y=learn.quantile(0.95), line_dash="dot", line_color=BLUE,
                    annotation_text="baseline: 95th pct of hourly count", annotation_font_color=BLUE)
        f.update_layout(height=340, margin=dict(l=10, r=10, t=50, b=10), showlegend=False, bargap=0,
                        title="This rule over time (alerts per hour)")
        chart(f)
        st.caption(f"{row['rule_desc']}: during learning {learn.mean():.1f} alerts/hour, active in "
                   f"{(learn > 0).mean():.0%} of hours. In the hour of this alert: "
                   f"{int(h.get(int(row['start'] // 3600 * 3600), 0)):,} alerts.")
    with right:
        n = ns[ns["scenario"] == net]
        nl = n[n["bucket"] < L["learn_end"]]
        f = go.Figure(go.Scatter(x=pd.to_datetime(n["bucket"], unit="s"), y=n["rare_rules"], mode="lines",
                                 line=dict(color=GRAY, width=1), name="rarely-seen detections / 10 min"))
        mark(f)
        f.add_hline(y=nl["rare_rules"].quantile(0.95), line_dash="dot", line_color=BLUE,
                    annotation_text="baseline: 95th pct", annotation_font_color=BLUE)
        f.update_layout(height=340, margin=dict(l=10, r=10, t=50, b=10), showlegend=False,
                        title="Whole network: rarely-seen detections per 10 min")
        chart(f)
        st.caption(f"The model's strongest signal. During learning: median {nl['rare_rules'].median():.0f}, "
                   f"95th pct {nl['rare_rules'].quantile(0.95):.0f} per 10 min.")

    section("Raw evidence", "Top SHAP reasons and log line")
    reasons = json.loads(row["reasons"] or "[]")
    st.markdown("\n".join(f"- {r['text']}" for r in reasons))
    raw = next((str(v) for v in (row["sample_log"], row["sample_url"]) if pd.notna(v) and str(v)), "")
    st.code(raw[:1500] or "(no raw log line)", language=None, wrap_lines=True)
    with st.expander("Ground truth for this alert (judges' view)"):
        phase = row["phase"] if pd.notna(row["phase"]) else "–"
        st.write(f"label: **{'attack' if row['label'] else 'benign'}** · phase: {phase} · "
                 f"attack share of its raw alerts: {row['attack_share']:.0%}")


if page == "Why suspicious":
    page_heading("EXPLAIN", "Why is this alert suspicious?", "What normal looks like in this network, how much history the model had seen, and how much each signal pushed the score.")
    why_view()

# ------------------------------------------------------------------ triage
if page == "Alert queue":
    page_heading("TRIAGE", "Alert queue.", "Ranked meta-alerts with the top reasons for each score.")
    st.caption("Ranked meta-alerts with the top reasons for each score. Mark false positives and AlertLens "
               "suppresses the same rule on the same host from then on.")
    show_k = st.slider("Queue length", 10, 200, 50)
    q = meta[meta["scenario"] == net].copy()
    sup = st.session_state["suppressed"]
    q["suppressed"] = [(r, h) in sup for r, h in zip(q["rule_id"], q["host"])]
    q = q[~q["suppressed"]].sort_values("score_model", ascending=False).head(show_k)
    q["why"] = q["reasons"].apply(lambda r: " · ".join(x["text"] for x in json.loads(r or "[]")[:3]))
    q["time"] = q["start_dt"].dt.strftime("%m-%d %H:%M:%S")
    q["mark_fp"] = False
    edited = st.data_editor(
        q[["mark_fp", "score_model", "time", "pred_stage", "source", "host", "src_ip", "rule_desc", "n_alerts", "why"]],
        hide_index=True, width="stretch", disabled=[c for c in q.columns if c != "mark_fp"],
        column_config={"score_model": st.column_config.ProgressColumn("risk", min_value=0, max_value=1, format="%.3f"),
                       "mark_fp": st.column_config.CheckboxColumn("FP"), "pred_stage": "stage",
                       "rule_desc": "rule", "n_alerts": "alerts"}, key=f"editor_{net}")
    b1, b2, _ = st.columns([2, 2, 6])
    if b1.button("Suppress marked", type="primary"):
        for i in edited.index[edited["mark_fp"]]:
            sup.add((q.at[i, "rule_id"], q.at[i, "host"]))
        st.rerun()
    if sup and b2.button(f"Clear {len(sup)} suppressions"):
        sup.clear()
        st.rerun()
    with st.expander("Ground truth for this queue (judges' view)"):
        top = meta[meta["scenario"] == net]
        top = top[~np.array([(r, h) in sup for r, h in zip(top["rule_id"], top["host"])], dtype=bool)]
        top = top.sort_values("score_model", ascending=False).head(show_k)
        st.metric(f"Precision of top-{show_k}", f"{top['label'].mean():.0%}")
        st.dataframe(top[["score_model", "rule_desc", "label", "phase"]], hide_index=True)

# ------------------------------------------------------------------ threat hunt
if page == "Threat hunt":
    page_heading("HUNT", "Threat hunt.", "Unsupervised hunting over raw alerts: an Isolation Forest flags unusual source IPs per hour.")
    threathunt.render()

# ------------------------------------------------------------------ ground truth
if page == "Ground truth":
    page_heading("EVALUATE", "Ground truth.", "Model risk over time against the labeled attack phases (the judges' answer key).")
    lab = labels[labels["scenario"] == net].assign(
        s=lambda d: pd.to_datetime(d["start"], unit="s"), e=lambda d: pd.to_datetime(d["end"], unit="s"))
    mm = meta[(meta["scenario"] == net) & (meta["score_model"] >= 0.05)]
    f = go.Figure()
    for r in lab.itertuples():
        f.add_vrect(x0=r.s, x1=max(r.e, r.s + pd.Timedelta(seconds=60)), fillcolor=AMBER, opacity=0.18, line_width=0,
                    annotation_text=r.attack, annotation_position="top left", annotation_textangle=-90,
                    annotation_font_color=GRAY)
    f.add_trace(go.Scatter(x=mm["start_dt"], y=mm["score_model"], mode="markers",
                           marker=dict(size=np.log1p(mm["n_alerts"]) * 2 + 4, color=mm["label"],
                                       colorscale=[[0, BLUE], [1, RED]], line=dict(width=0)),
                           text=mm["rule_desc"], hovertemplate="%{text}<br>risk %{y:.2f}<extra></extra>"))
    f.update_layout(height=450, title="Model risk over time vs. labeled attack phases (red = attack-related meta-alert)",
                    yaxis_title="risk", margin=dict(l=10, r=10, t=40, b=10))
    chart(f)
    st.caption("Amber bands are attack phases from labels.csv. Zoom into the attack day to see each phase light up.")
