"""Slide-ready figures for the AlertLens deck. Run from the repo root: python presentation/make_figures.py"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier, plot_tree

from blueteam.baseline import display_value, feature_info

DATA = Path("data")
OUT = Path("presentation/figs")
OUT.mkdir(parents=True, exist_ok=True)

RED, BLUE, GRAY, NAVY, ORANGE = "#D7263D", "#3A7DC9", "#9AA5B1", "#14213D", "#F4A261"
plt.rcParams.update({
    "figure.dpi": 200, "font.size": 15, "axes.titlesize": 17, "axes.titleweight": "bold",
    "axes.spines.top": False, "axes.spines.right": False, "axes.edgecolor": "#555",
    "axes.titlecolor": NAVY, "axes.labelcolor": "#333", "font.family": ["Helvetica Neue", "DejaVu Sans"],
})

alerts = pd.read_parquet(DATA / "alerts.parquet", columns=["scenario", "ts"])
meta = pd.read_parquet(DATA / "meta_explained.parquet")
X = pd.read_parquet(DATA / "features.parquet")
labels = pd.read_csv("labels.csv")
incidents = json.load(open(DATA / "incidents.json"))
breakdown = pd.read_parquet(DATA / "score_breakdown.parquet").set_index("row")
baseline = pd.read_parquet(DATA / "feature_baseline.parquet").set_index(["scenario", "feature"])
dt = lambda s: pd.to_datetime(s, unit="s")
ATTACK, OK = 37116, 26181


def save(fig, name):
    fig.savefig(OUT / name, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("saved", name)


# 1. alert volume in santos with attack bands
s = alerts[alerts.scenario == "santos"]
fig, ax = plt.subplots(figsize=(13, 4.2))
ax.hist(dt(s.ts), bins=int((s.ts.max() - s.ts.min()) // 3600), color=GRAY)
for r in labels[labels.scenario == "santos"].itertuples():
    ax.axvspan(dt(r.start), dt(max(r.end, r.start + 600)), color=RED, alpha=0.55, lw=0)
ax.set_yscale("log")
ax.set_ylabel("alerts per hour")
ax.set_title(f"One network (santos): {len(s):,} alerts in 4 days. Red = the real attack")
ax.xaxis.set_major_formatter(matplotlib.dates.DateFormatter("%b %d"))
save(fig, "volume.png")

# 2. severity does not separate attack from normal
lvl = meta.groupby("label")["max_level"].value_counts(normalize=True).unstack(0).fillna(0).sort_index()
fig, ax = plt.subplots(figsize=(11, 4.2))
x = np.arange(len(lvl))
ax.bar(x - 0.2, lvl[0] * 100, 0.4, color=BLUE, label="normal")
ax.bar(x + 0.2, lvl[1] * 100, 0.4, color=RED, label="attack")
ax.set_xticks(x, [f"{v:.0f}" for v in lvl.index])
ax.set_xlabel("Wazuh severity level")
ax.set_ylabel("% of alerts")
ax.legend(frameon=False)
ax.set_title("Attack and normal alerts have the same severity levels")
save(fig, "severity.png")

# 3. funnel
stats = json.load(open(DATA / "stats.json"))
steps = [("Raw alerts", stats["n_alerts"], GRAY), ("Meta-alerts\n(duplicates merged)", stats["n_meta"], BLUE),
         ("Flagged by model", 451, ORANGE), ("Incidents", len(incidents), RED)]
fig, ax = plt.subplots(figsize=(11, 4.6))
for k, (name, v, c) in enumerate(steps):
    ax.barh(k, np.log10(v), color=c, height=0.7)
    ax.text(np.log10(v) + 0.08, k, f"{v:,}", va="center", fontsize=20, fontweight="bold", color=NAVY)
ax.set_yticks(range(len(steps)), [n for n, *_ in steps], fontsize=16)
ax.invert_yaxis()
ax.set_xticks([])
ax.spines["bottom"].set_visible(False)
ax.set_xlim(0, 7.6)
save(fig, "funnel.png")

# 4. normal vs attack on three questions
fig, axs = plt.subplots(1, 3, figsize=(16, 4.6))
for ax, f, bins, ttl in [(axs[0], "rule_hour_frac", np.linspace(0, 1, 21), "How often is this rule\nactive here? (share of hours)"),
                         (axs[1], "ctx_rare_rules", np.arange(0, 25), "How many rare detections\nnetwork-wide, same 10 min?")]:
    for lab_, c, name in [(0, BLUE, "normal"), (1, RED, "attack")]:
        ax.hist(X.loc[meta.label == lab_, f].dropna(), bins=bins, density=True, alpha=0.65, color=c, label=name)
    ax.set_title(ttl, fontsize=15)
    ax.set_yticks([])
    ax.legend(frameon=False)
share = X.assign(y=meta.label).groupby("y")["ioc_attacker_score"].apply(lambda v: (v > 0).mean() * 100)
axs[2].bar(["normal", "attack"], share.values, color=[BLUE, RED], width=0.6)
for k, v in enumerate(share.values):
    axs[2].text(k, v + 1.5, f"{v:.1f}%", ha="center", fontsize=16, fontweight="bold", color=NAVY)
axs[2].set_title("Raw log shows attacker\nbehaviour?", fontsize=15)
axs[2].set_ylim(0, 65)
axs[2].set_yticks([])
plt.tight_layout()
save(fig, "features.png")

# 5. a small decision tree (train on 7 networks)
feats = ["rule_hour_frac", "ctx_rare_rules", "ioc_attacker_score", "log_rule_meta_count"]
short = {"rule_hour_frac": "rule active in share of hours", "ctx_rare_rules": "rare detections, same 10 min",
         "ioc_attacker_score": "attacker indicators", "log_rule_meta_count": "earlier bursts of rule"}
Xf = X[feats].fillna(-1)
train = (meta.scenario != "santos").to_numpy()
tree = DecisionTreeClassifier(max_depth=2, class_weight="balanced", random_state=0).fit(Xf[train], meta.label[train])
fig, ax = plt.subplots(figsize=(15, 6.2))
art = plot_tree(tree, feature_names=[short[f] for f in feats], class_names=["NORMAL", "ATTACK"], filled=True,
                impurity=False, proportion=True, fontsize=14, ax=ax, rounded=True)
for a in art:
    t = a.get_text()
    t = "\n".join(line for line in t.split("\n") if not line.startswith("value"))
    a.set_text(t.replace("samples = ", "share of alerts: ").replace("class = ", "verdict: "))
save(fig, "tree.png")

# 6. leave-one-network-out grid
nets = sorted(meta.scenario.unique())
fig, ax = plt.subplots(figsize=(10, 5.6))
ax.imshow(np.eye(8), cmap=matplotlib.colors.ListedColormap(["#D6E6F7", RED]))
ax.set_xticks(range(8), nets, rotation=30, ha="right")
ax.set_yticks(range(8), [f"round {i + 1}" for i in range(8)])
for i in range(8):
    ax.text(i, i, "TEST", ha="center", va="center", color="white", fontsize=11, fontweight="bold")
ax.set_xticks(np.arange(-0.5, 8), minor=True)
ax.set_yticks(np.arange(-0.5, 8), minor=True)
ax.grid(which="minor", color="white", lw=2)
ax.tick_params(which="minor", length=0)
for sp in ax.spines.values():
    sp.set_visible(False)
ax.set_title("Blue = train on these 7 networks   ·   Red = test on the unseen one")
save(fig, "loso.png")

# 7. results vs baselines
summ = pd.read_csv(DATA / "metrics_summary.csv", index_col=0)
names = {"model": "AlertLens", "isoforest": "Generic anomaly\ndetector", "rarity": "Rarest rule\nfirst",
         "wazuh_level": "Sort by severity\n(today)"}
order = ["model", "isoforest", "rarity", "wazuh_level"]
cols = [RED, GRAY, GRAY, "#C9D1D9"]
fig, axs = plt.subplots(1, 2, figsize=(15, 4.8))
axs[0].barh(range(4), summ.loc[order, "pr_auc"], color=cols)
for k, v in enumerate(summ.loc[order, "pr_auc"]):
    axs[0].text(v + 0.02, k, f"{v:.2f}", va="center", fontsize=17, fontweight="bold", color=NAVY)
axs[0].set_xlim(0, 1.15)
axs[0].set_title("Ranking quality (PR-AUC, 1.0 = perfect)")
q = summ.loc[order, "queue_size@90recall"]
axs[1].barh(range(4), q, color=cols)
for k, v in enumerate(q):
    axs[1].text(v * 1.15, k, f"{v:,.0f}", va="center", fontsize=17, fontweight="bold", color=NAVY)
axs[1].set_xscale("log")
axs[1].set_xlim(30, 60000)
axs[1].set_xticks([], minor=True)
axs[1].set_title("Items to review to catch 90% of the attack")
for ax in axs:
    ax.set_yticks(range(4), [names[m] for m in order])
    ax.invert_yaxis()
    ax.set_xticks([])
    ax.spines["bottom"].set_visible(False)
axs[1].set_yticklabels([])
plt.tight_layout()
save(fig, "results.png")

# 8. kill chain timeline for santos incident #1
inc = next(i for i in incidents if i["scenario"] == "santos" and i["rank_in_scenario"] == 1)
m = meta[(meta.scenario == "santos") & (meta.incident_id == inc["incident_id"])]
stages = ["Reconnaissance", "Web discovery", "Initial access (webshell upload)", "Credential access",
          "Execution (reverse shell)", "Privilege escalation", "Impact / exfiltration"]
nice = ["1 Scouting the network", "2 Scanning the website", "3 Uploading a backdoor", "4 Cracking a password",
        "5 Remote control (reverse shell)", "6 Becoming admin (root)", "7 Stealing data"]
fig, ax = plt.subplots(figsize=(15, 5.4))
y = m.pred_stage.map({s_: k for k, s_ in enumerate(stages)})
sc = ax.scatter(dt(m.start), y, s=np.log1p(m.n_alerts) * 45 + 30, c=m.score_model, cmap="Reds", vmin=0.4, vmax=1,
                edgecolors=NAVY, linewidths=0.6, zorder=3)
ax.scatter(dt(meta.loc[ATTACK, "start"]), stages.index(meta.loc[ATTACK, "pred_stage"]), s=900, facecolors="none",
           edgecolors=NAVY, linewidths=2.5, zorder=4)
ax.annotate("web server account became\nuser gmorgan: score 99%", (dt(meta.loc[ATTACK, "start"]), 5), xytext=(-170, 25),
            textcoords="offset points", fontsize=13, color=NAVY, arrowprops=dict(arrowstyle="->", color=NAVY))
ax.set_yticks(range(len(nice)), nice)
ax.set_ylim(-0.6, 6.6)
ax.grid(axis="y", color="#eee")
ax.xaxis.set_major_formatter(matplotlib.dates.DateFormatter("%H:%M"))
ax.set_xlabel("17 January (UTC)")
ax.set_title(f"santos: {inc['n_alerts']:,} raw alerts become ONE incident with {inc['n_stages']} attack stages")
cb = plt.colorbar(sc, pad=0.01)
cb.set_label("model score")
save(fig, "killchain.png")


# 9. SHAP waterfalls
def waterfall(i, title, name, k_show=7):
    b = breakdown.loc[i]
    contrib = json.loads(b.contrib)[:k_show]
    rest = b.rest + sum(c for *_, c in json.loads(b.contrib)[k_show:])
    names_ = ["Starting point: a typical alert"] + [feature_info(f)[0] for f, _, _ in contrib] + ["All other signals"]
    vals = np.array([b.bias] + [c for *_, c in contrib] + [rest])
    starts = np.r_[0, np.cumsum(vals)[:-1]]
    colors = [GRAY] + [RED if v > 0 else BLUE for v in vals[1:]]
    fig, ax = plt.subplots(figsize=(13, 6))
    ax.barh(range(len(vals)), vals, left=starts, color=colors, height=0.7)
    total = vals.sum()
    ax.barh(len(vals), total, color=NAVY, height=0.7)
    ax.set_yticks(range(len(vals) + 1), names_ + [f"FINAL SCORE = {1 / (1 + np.exp(-total)):.1%}"], fontsize=14)
    ax.get_yticklabels()[-1].set_fontweight("bold")
    ax.invert_yaxis()
    ax.axvline(0, ls=":", color="k")
    for k, (s0, v) in enumerate(zip(starts, vals)):
        if k == 0:
            ax.text(s0 + v / 2, k, f"≈ {1 / (1 + np.exp(-v)):.3%} chance of attack", va="center", ha="center",
                    color="white", fontsize=13, fontweight="bold")
        else:
            ax.text(s0 + v + (0.12 if v >= 0 else -0.12), k, f"{v:+.1f}", va="center",
                    ha="left" if v >= 0 else "right", fontsize=13)
    ax.set_xlabel("blue = pushes towards NORMAL          red = pushes towards ATTACK")
    ax.set_xticks([])
    ax.set_title(title)
    save(fig, name)


waterfall(ATTACK, "Why 'web server became user gmorgan' scored 99%", "shap_attack.png")
waterfall(OK, f"Admin SSH key login: rare rule, but only {meta.loc[OK, 'score_model']:.1%}", "shap_admin.png", k_show=6)

# 10. ablation
abl = pd.read_csv(DATA / "ablation.csv").set_index("config")
rows = [("All features", "all features"), ("Without time-window context", "without context"),
        ("Without rule rarity", "without rule_rarity"), ("Only WHAT the rule is\n(no behaviour)", "semantics only")]
fig, ax = plt.subplots(figsize=(11, 4.4))
v = [abl.loc[c, "pr_auc"] for _, c in rows]
ax.barh(range(len(rows)), v, color=[RED, ORANGE, ORANGE, GRAY], height=0.65)
for k, x_ in enumerate(v):
    ax.text(x_ + 0.015, k, f"{x_:.2f}", va="center", fontsize=17, fontweight="bold", color=NAVY)
ax.set_yticks(range(len(rows)), [n for n, _ in rows])
ax.invert_yaxis()
ax.set_xlim(0, 1.1)
ax.set_xticks([])
ax.spines["bottom"].set_visible(False)
ax.set_title("Remove an ingredient, retrain, compare (PR-AUC)")
save(fig, "ablation.png")

# baseline-vs-now table for the attack alert (used as a native slide table)
b = breakdown.loc[ATTACK]
rows = []
for f, val, c in json.loads(b.contrib)[:5]:
    label, kind = feature_info(f)
    base = baseline.loc[("santos", f)]
    normal = f"in {base.nonzero:.1%} of alerts" if kind == "flag" else display_value(f, base["median"])
    rows.append([label, normal, display_value(f, val), f"{c:+.1f}"])
json.dump(rows, open(OUT / "baseline_table.json", "w"), indent=1)
print("saved baseline_table.json")
