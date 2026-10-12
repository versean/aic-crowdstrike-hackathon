"""Cyberpunk-inspired AlertLens design tokens and Streamlit styling."""
import plotly.graph_objects as go
import plotly.io as pio
import plotly.express as px
import streamlit as st


ACCENT = "#ff4057"
CYAN = "#38d9e6"
AMBER = "#f5bb46"
GRID_DARK = "#28333a"


def apply_design():
    """Apply AlertLens' adaptive cyberpunk interface and motion system."""
    st.markdown("""<style>
    @import url('https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@500;600;700;800&family=IBM+Plex+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');
    :root {
      color-scheme:dark light;
      --bg:#0b0f12; --panel:#11171b; --panel-raised:#172025; --ink:#f4f7f5;
      --muted:#98a6a9; --line:#29363b; --accent:#ff4964; --cyan:#49e5ee; --amber:#f3c66a;
      --grid:rgba(151,226,230,.035); --hero:#111a1e; --sidebar:#0a0e11;
      --shadow:0 18px 48px rgba(0,0,0,.24); --focus:rgba(73,229,238,.5);
    }
    @media(prefers-color-scheme:light) {
      :root { color-scheme:light; --bg:#e9eeec; --panel:#f7f9f7; --panel-raised:#fff; --ink:#1d292c; --muted:#617276; --line:#cbd7d7; --grid:rgba(18,68,72,.045); --hero:#e1eceb; --sidebar:#f4f7f5; --shadow:0 16px 38px rgba(23,55,58,.09); --focus:rgba(8,142,155,.4); }
      .brand-sub,.tiny-muted { color:var(--muted)!important; }
      .status-chip { background:rgba(255,255,255,.52); }
    }
    * { box-sizing:border-box; }
    html,body,[class*="css"] { font-family:'Inter',sans-serif; }
    [data-testid="stAppViewContainer"] { position:relative; color:var(--ink); background-color:var(--bg); background-image:radial-gradient(ellipse at 80% -10%,color-mix(in srgb,var(--cyan) 8%,transparent),transparent 42%),linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px); background-size:auto,36px 36px,36px 36px; }
    [data-testid="stAppViewContainer"]::before { content:""; position:fixed; inset:0; z-index:0; pointer-events:none; opacity:.22; background:repeating-linear-gradient(0deg,transparent 0 3px,rgba(255,255,255,.018) 4px); mask-image:linear-gradient(to bottom,black,transparent 70%); }
    [data-testid="stHeader"] { background:color-mix(in srgb,var(--bg) 90%,transparent); backdrop-filter:blur(14px); }
    [data-testid="stSidebar"] { background:color-mix(in srgb,var(--sidebar) 96%,transparent); border-right:1px solid var(--line); box-shadow:8px 0 28px rgba(0,0,0,.1); }
    [data-testid="stSidebar"] [data-testid="stVerticalBlock"] { gap:.65rem; }
    [data-testid="stSidebar"] [data-testid="stRadio"] label { padding:9px 12px; border-radius:7px; border:1px solid transparent; border-left:2px solid transparent; transition:background .18s ease,border-color .18s ease,transform .18s ease; }
    [data-testid="stSidebar"] [data-testid="stRadio"] label:hover { background:var(--panel-raised); border-color:var(--line); border-left-color:var(--cyan); transform:translateX(2px); }
    [data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) { background:linear-gradient(90deg,color-mix(in srgb,var(--accent) 14%,var(--panel)),var(--panel)); border-color:color-mix(in srgb,var(--accent) 28%,var(--line)); border-left-color:var(--accent); box-shadow:inset 0 0 20px color-mix(in srgb,var(--accent) 6%,transparent); }
    [data-testid="stSidebar"] [data-baseweb="select"]>div { background:var(--panel); border-color:var(--line); border-radius:7px; }
    .block-container { position:relative; z-index:1; max-width:1480px; padding-top:2rem; padding-bottom:8rem; }
    h1,h2,h3,.page-title { color:var(--ink); font-family:'Space Grotesk','Inter',sans-serif; letter-spacing:-.04em; }
    .page-title { font-size:clamp(2.1rem,4vw,3.2rem); font-weight:700; line-height:.98; margin:0; text-wrap:balance; }
    .page-subtitle { color:var(--muted); margin:.65rem 0 1.45rem; font-size:.94rem; max-width:820px; line-height:1.55; }
    .eyebrow,.hero-kicker,.hero-pill,.section-note,.assistant-note { font-family:'IBM Plex Mono',monospace; text-transform:uppercase; letter-spacing:.12em; }
    .eyebrow { color:var(--cyan); font-size:.66rem; margin-bottom:.55rem; }
    .brand { color:var(--ink); font:700 1.65rem 'Barlow Condensed',sans-serif; letter-spacing:.1em; }
    .brand::before { content:'//'; color:var(--accent); margin-right:.42rem; }
    .brand span { color:var(--accent); text-shadow:0 0 18px color-mix(in srgb,var(--accent) 55%,transparent); }
    .brand-sub { color:var(--muted); font-size:.64rem; letter-spacing:.16em; text-transform:uppercase; margin:0 0 .55rem; }
    .tiny-muted { color:var(--muted); font-size:.72rem; line-height:1.55; overflow-wrap:anywhere; }
    .hero { position:relative; isolation:isolate; overflow:hidden; background:linear-gradient(112deg,color-mix(in srgb,var(--panel) 80%,transparent),var(--hero)); border:1px solid var(--line); border-left:3px solid var(--accent); border-radius:10px; padding:clamp(22px,3vw,34px); margin:.45rem 0 1.35rem; box-shadow:var(--shadow); }
    .hero::before { content:""; position:absolute; z-index:-1; top:0; left:-30%; width:28%; height:2px; background:linear-gradient(90deg,transparent,var(--cyan),transparent); box-shadow:0 0 18px var(--cyan); animation:scan 7s ease-in-out infinite; }
    .hero::after { content:'2077'; position:absolute; right:24px; bottom:-.33em; z-index:-1; font:800 clamp(5rem,12vw,9rem)/1 'Barlow Condensed',sans-serif; color:color-mix(in srgb,var(--ink) 4%,transparent); letter-spacing:-.04em; pointer-events:none; }
    .hero-kicker { color:var(--accent); font-size:.64rem; }
    .hero h2 { position:relative; z-index:1; color:var(--ink); font-size:clamp(1.55rem,2.5vw,2.3rem); line-height:1.08; margin:.65rem 0 .5rem; text-wrap:balance; }
    .hero p { position:relative; z-index:1; color:var(--muted); margin:0; max-width:780px; line-height:1.6; }
    .hero-pill { display:inline-flex; align-items:center; gap:.5rem; position:relative; z-index:1; color:var(--amber); border:1px solid color-mix(in srgb,var(--amber) 35%,transparent); border-radius:999px; background:color-mix(in srgb,var(--amber) 7%,transparent); padding:6px 10px; margin-top:16px; font-size:.58rem; }
    .section-head { display:flex; align-items:baseline; justify-content:space-between; gap:1rem; border-bottom:1px solid var(--line); padding-bottom:.55rem; margin:.75rem 0 .85rem; }
    .section-head h3 { margin:0; font-size:1.22rem; font-weight:700; letter-spacing:-.035em; }
    .section-note { color:var(--muted); font-size:.58rem; text-align:right; }
    .status-chip { display:inline-flex; align-items:center; gap:7px; border:1px solid currentColor; border-radius:999px; padding:5px 9px; font:600 .6rem 'IBM Plex Mono',monospace; letter-spacing:.035em; }
    .status-ok { color:var(--cyan); background:color-mix(in srgb,var(--cyan) 8%,transparent); }
    .status-warn { color:var(--amber); background:color-mix(in srgb,var(--amber) 8%,transparent); }
    [data-testid="stMetric"] { position:relative; overflow:hidden; background:linear-gradient(145deg,var(--panel-raised),var(--panel)); border:1px solid var(--line); border-radius:9px; border-top:2px solid var(--accent); padding:15px 17px; transition:transform .2s ease,border-color .2s ease,box-shadow .2s ease; }
    [data-testid="stMetric"]::after { content:""; position:absolute; width:64px; height:64px; right:-28px; top:-30px; background:var(--accent); opacity:.06; filter:blur(24px); border-radius:50%; }
    [data-testid="stMetric"]:hover { transform:translateY(-2px); border-color:color-mix(in srgb,var(--accent) 48%,var(--line)); box-shadow:0 9px 28px rgba(0,0,0,.13); }
    [data-testid="stMetricLabel"] { color:var(--muted); font:500 .65rem 'IBM Plex Mono',monospace; letter-spacing:.075em; line-height:1.25; text-transform:uppercase; white-space:normal; overflow-wrap:anywhere; }
    [data-testid="stMetricValue"] { color:var(--ink); font:700 2rem 'Barlow Condensed',sans-serif; }
    [data-testid="stMetricDelta"] { font-size:.7rem; }
    div[data-testid="stDataFrame"],div[data-testid="stDataEditor"] { background:var(--panel); border:1px solid var(--line); border-radius:9px; overflow:hidden; }
    div[data-testid="stPlotlyChart"] { background:var(--panel); border:1px solid var(--line); border-radius:9px; padding:6px; transition:border-color .2s ease,box-shadow .2s ease; }
    div[data-testid="stPlotlyChart"]:hover { border-color:color-mix(in srgb,var(--cyan) 34%,var(--line)); box-shadow:0 8px 26px rgba(0,0,0,.1); }
    [data-testid="stButton"] button,[data-testid="stFormSubmitButton"] button,[data-testid="stDownloadButton"] button { color:var(--ink); background:var(--panel-raised); border:1px solid var(--line); border-radius:7px; font:600 .67rem 'IBM Plex Mono',monospace; letter-spacing:.035em; min-height:2.45rem; text-transform:uppercase; transition:transform .16s ease,background .16s ease,border-color .16s ease,box-shadow .16s ease; }
    [data-testid="stButton"] button:hover,[data-testid="stFormSubmitButton"] button:hover,[data-testid="stDownloadButton"] button:hover { color:var(--cyan); border-color:var(--cyan); transform:translateY(-1px); box-shadow:0 5px 18px color-mix(in srgb,var(--cyan) 13%,transparent); }
    [data-testid="stButton"] button[kind="primary"],[data-testid="stFormSubmitButton"] button[kind="primary"] { color:#fff; background:linear-gradient(105deg,#ef3657,var(--accent)); border-color:var(--accent); box-shadow:0 6px 22px color-mix(in srgb,var(--accent) 18%,transparent); }
    [data-testid="stButton"] button[kind="primary"] p,[data-testid="stFormSubmitButton"] button[kind="primary"] p { color:#fff; }
    [data-testid="stTextInput"] input,[data-testid="stNumberInput"] input,[data-baseweb="select"]>div { background:var(--panel); color:var(--ink); border-color:var(--line); border-radius:7px; transition:border-color .16s ease,box-shadow .16s ease; }
    [data-testid="stTextInput"] input:focus,[data-testid="stNumberInput"] input:focus,[data-baseweb="select"]>div:focus-within { border-color:var(--cyan); box-shadow:0 0 0 2px var(--focus); }
    :focus-visible { outline:2px solid var(--cyan)!important; outline-offset:2px!important; }
    [data-testid="stChatMessage"] { background:var(--panel-raised); border:1px solid var(--line); border-radius:9px; }
    [data-testid="stExpander"] { background:color-mix(in srgb,var(--panel) 74%,transparent); border:1px solid var(--line); border-radius:8px; }
    hr { border-color:var(--line); }
    .st-key-security_assistant { position:fixed; bottom:20px; right:20px; z-index:999; width:min(250px,calc(100vw - 28px)); padding:9px 11px; background:color-mix(in srgb,var(--panel) 96%,transparent); backdrop-filter:blur(18px); border:1px solid var(--line); border-top:2px solid var(--cyan); border-radius:11px; box-shadow:0 16px 50px rgba(0,0,0,.28); max-height:calc(100dvh - 28px); overflow-y:auto; transition:box-shadow .2s ease; }
    .st-key-security_assistant:hover { box-shadow:0 18px 54px color-mix(in srgb,var(--cyan) 12%,#000); }
    .assistant-title { color:var(--ink); font:700 1rem 'Space Grotesk',sans-serif; letter-spacing:-.025em; }
    .assistant-title span { color:var(--cyan); margin-right:8px; text-shadow:0 0 12px color-mix(in srgb,var(--cyan) 60%,transparent); }
    .assistant-note { color:var(--muted); font-size:.56rem; margin:4px 0 9px; }
    .st-key-assistant_history { max-height:38vh; }
    .st-key-security_assistant [data-testid="stForm"] { border:0; padding:0; }
    @media(prefers-reduced-motion:no-preference) {
      .hero,[data-testid="stMetric"],div[data-testid="stPlotlyChart"],.page-title { animation:rise .44s cubic-bezier(.2,.7,.2,1) both; }
      .brand::before { animation:brand-signal 3.2s ease-in-out infinite; }
      .brand span { animation:brand-glow 2.8s ease-in-out infinite alternate; }
      @keyframes rise { from { opacity:0; transform:translateY(9px); } to { opacity:1; transform:none; } }
      @keyframes scan { 0%,100% { left:-30%; opacity:0; } 10% { opacity:.8; } 42% { left:110%; opacity:0; } }
      @keyframes brand-signal { 0%,100% { opacity:.78; text-shadow:0 0 5px color-mix(in srgb,var(--accent) 35%,transparent); } 50% { opacity:1; text-shadow:0 0 13px color-mix(in srgb,var(--cyan) 72%,transparent); } }
      @keyframes brand-glow { from { text-shadow:0 0 8px color-mix(in srgb,var(--accent) 36%,transparent); } to { text-shadow:0 0 20px color-mix(in srgb,var(--accent) 72%,transparent),0 0 32px color-mix(in srgb,var(--accent) 24%,transparent); } }
    }
    @media(prefers-reduced-motion:reduce) { *,*::before,*::after { animation:none!important; transition:none!important; scroll-behavior:auto!important; } }
    @media(max-width:1150px) {
      .block-container { padding-left:1.5rem; padding-right:1.5rem; }
      .page-title { font-size:clamp(1.85rem,4vw,2.7rem); }
      [data-testid="stMetric"] { padding:12px 13px; }
      [data-testid="stMetricLabel"] { font-size:.52rem; letter-spacing:.035em; }
      [data-testid="stMetricValue"] { font-size:clamp(1.15rem,2.7vw,1.8rem); }
      [data-testid="stHorizontalBlock"] { flex-wrap:wrap; gap:.7rem; }
      [data-testid="stHorizontalBlock"]>[data-testid="stColumn"] { flex:1 1 calc(50% - .7rem)!important; min-width:calc(50% - .7rem)!important; }
      .st-key-security_assistant:not(:has(.assistant-note)) { width:min(205px,calc(100vw - 24px)); }
    }
    @media(max-width:800px) { .block-container { padding:1.35rem 1rem 7rem; } .page-title { font-size:2.2rem; } .hero { padding:21px; } .hero h2 { max-width:88%; font-size:1.6rem; } .hero::after { right:8px; } .section-head { align-items:flex-start; flex-direction:column; gap:.25rem; } .section-note { text-align:left; } .st-key-security_assistant { bottom:10px; right:10px; } }
    @media(max-width:620px) {
      .page-title { font-size:1.9rem; }
      [data-testid="stHorizontalBlock"]>[data-testid="stColumn"] { flex-basis:100%!important; min-width:100%!important; }
      .hero::after { opacity:.55; }
      .st-key-security_assistant { width:min(198px,calc(100vw - 20px)); bottom:8px; right:8px; }
    }
    </style>""", unsafe_allow_html=True)
    template = go.layout.Template(layout=dict(
        paper_bgcolor="#171b1e", plot_bgcolor="#171b1e",
        font=dict(color="#f2f0ec", family="Inter"),
        colorway=[ACCENT, CYAN, AMBER, "#a88cff"],
        xaxis=dict(gridcolor=GRID_DARK, zerolinecolor=GRID_DARK),
        yaxis=dict(gridcolor=GRID_DARK, zerolinecolor=GRID_DARK),
    ))
    pio.templates["alertlens"] = template
    px.defaults.template = "alertlens"


def style_chart(figure):
    """Apply the fixed instrument-panel chart treatment."""
    figure.update_layout(
        paper_bgcolor="#171b1e", plot_bgcolor="#171b1e",
        font=dict(color="#f2f0ec", family="Inter"),
        margin=dict(l=65, r=25, b=55),
    )
    figure.update_xaxes(automargin=True, gridcolor=GRID_DARK, zerolinecolor=GRID_DARK)
    figure.update_yaxes(automargin=True, gridcolor=GRID_DARK, zerolinecolor=GRID_DARK)
    return figure
