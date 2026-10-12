"""Static PNG figures for the pitch deck."""
import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from blueteam.ingest import DATA_DIR, LABELS_CSV

OUT = DATA_DIR.parent / "figures"
NAMES = {"model": "AlertLens (ours)", "isoforest": "Isolation Forest", "rarity": "Rule rarity",
         "wazuh_level": "Wazuh severity\n(status quo)"}


def baselines():
    s = pd.read_csv(DATA_DIR / "metrics_summary.csv", index_col=0).loc[list(NAMES)]
    fig, axes = plt.subplots(1, 3, figsize=(15, 4))
    colors = ["crimson", "grey", "grey", "lightgrey"]
    for ax, (col, title, log) in zip(axes, [("pr_auc", "PR-AUC", False), ("p@20", "Precision of top-20 queue", False),
                                            ("queue_size@90recall", "Items to review for 90% attack recall", True)]):
        ax.barh([NAMES[i] for i in s.index][::-1], s[col][::-1], color=colors[::-1])
        for y, v in enumerate(s[col][::-1]):
            ax.text(v, y, f" {v:,.0f}" if log else f" {v:.2f}", va="center")
        ax.set_title(title)
        if log:
            ax.set_xscale("log")
        else:
            ax.set_xlim(0, 1.15)
    fig.suptitle("Held-out networks (leave-one-network-out, mean of 8)")
    fig.tight_layout()
    fig.savefig(OUT / "baselines.png", dpi=150)


def timeline(scenario="santos"):
    m = pd.read_parquet(DATA_DIR / "meta_explained.parquet")
    m = m[m["scenario"] == scenario]
    lab = pd.read_csv(LABELS_CSV)
    lab = lab[lab["scenario"] == scenario]
    t0 = lab["start"].min() - 1800
    t1 = lab[lab["attack"] == "privilege_escalation"]["end"].max() + 1800
    w = m[(m["start"] >= t0) & (m["start"] <= t1)]
    fig, ax = plt.subplots(figsize=(15, 5))
    for i, r in enumerate(lab[(lab["start"] >= t0) & (lab["start"] <= t1)].itertuples()):
        ax.axvspan(pd.to_datetime(r.start, unit="s"), pd.to_datetime(max(r.end, r.start + 40), unit="s"),
                   color="orange", alpha=0.25)
        ax.text(pd.to_datetime(r.start, unit="s"), 1.04 + 0.06 * (i % 2), r.attack, fontsize=8, rotation=0)
    for lbl, c in [(0, "steelblue"), (1, "crimson")]:
        d = w[w["label"] == lbl]
        ax.scatter(pd.to_datetime(d["start"], unit="s"), d["score_model"], s=np.log1p(d["n_alerts"]) * 12 + 8, c=c,
                   alpha=0.7, label="attack-related" if lbl else "benign")
    ax.axhline(0.5, ls="--", c="k", lw=0.8)
    ax.set_ylim(-0.02, 1.15)
    ax.set_ylabel("AlertLens risk (held-out)")
    ax.set_title(f"Network '{scenario}' on attack day: risk per meta-alert vs labeled attack phases (orange)")
    ax.legend(loc="center right")
    fig.tight_layout()
    fig.savefig(OUT / f"timeline_{scenario}.png", dpi=150)


def funnel():
    st = json.load(open(DATA_DIR / "stats.json"))
    vals = [st["n_alerts"], st["n_meta"], st["n_flagged_meta"], st["n_incidents"]]
    names = ["Raw alerts", "Meta-alerts", "Flagged", "Incidents"]
    fig, ax = plt.subplots(figsize=(8, 3.2))
    ax.barh(names[::-1], vals[::-1], color=["steelblue", "goldenrod", "darkorange", "crimson"])
    ax.set_xscale("log")
    for y, v in enumerate(vals[::-1]):
        ax.text(v, y, f" {v:,}", va="center")
    ax.set_xlim(1, 3e7)
    ax.set_title(f"From alert fatigue to {st['n_incidents']} incidents (8 networks x 5 days)")
    fig.tight_layout()
    fig.savefig(OUT / "funnel.png", dpi=150)


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    baselines()
    timeline("santos")
    timeline("harrison")
    funnel()
    print("figures written to", OUT)
