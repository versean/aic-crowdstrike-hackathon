"""Write the deliverables as plain files: ranked explained alerts (CSV) + incident reports (Markdown)."""
import json

import pandas as pd

from blueteam.ingest import DATA_DIR

OUT = DATA_DIR.parent / "outputs"


def main(top_per_network: int = 100):
    OUT.mkdir(exist_ok=True)
    meta = pd.read_parquet(DATA_DIR / "meta_explained.parquet")
    top = meta.sort_values("score_model", ascending=False).groupby("scenario").head(top_per_network)
    top = top.assign(
        rank=top.groupby("scenario")["score_model"].rank(ascending=False, method="first").astype(int),
        time_utc=pd.to_datetime(top["start"], unit="s").dt.strftime("%Y-%m-%d %H:%M:%S"),
        why=top["reasons"].apply(lambda r: " | ".join(x["text"] for x in json.loads(r or "[]"))),
    ).sort_values(["scenario", "rank"])
    cols = ["scenario", "rank", "score_model", "time_utc", "pred_stage", "source", "host", "src_ip", "rule_desc",
            "n_alerts", "why", "sample_log", "incident_id", "label", "phase"]
    top[cols].rename(columns={"score_model": "risk", "label": "ground_truth_attack", "phase": "ground_truth_phase"}) \
        .to_csv(OUT / "ranked_alerts.csv", index=False)

    incidents = json.load(open(DATA_DIR / "incidents.json"))
    narratives = json.load(open(DATA_DIR / "narratives.json")) if (DATA_DIR / "narratives.json").exists() else {}
    lines = ["# AlertLens incident reports", ""]
    for inc in sorted(incidents, key=lambda i: (i["scenario"], i["rank_in_scenario"])):
        start = pd.to_datetime(inc["start"], unit="s").strftime("%Y-%m-%d %H:%M")
        end = pd.to_datetime(inc["end"], unit="s").strftime("%H:%M")
        lines += [
            f"## {inc['scenario']} — incident #{inc['rank_in_scenario']} (risk {inc['risk']:.2f})",
            f"*{start} → {end} UTC · {inc['n_meta']} meta-alerts · {inc['n_alerts']:,} raw alerts · "
            f"stages: {' → '.join(inc['stages'])}*",
            "",
            narratives.get(f"{inc['scenario']}#{inc['incident_id']}", "_LLM report not generated._"),
            "",
        ]
    (OUT / "incident_reports.md").write_text("\n".join(lines))
    print(f"wrote {OUT / 'ranked_alerts.csv'} ({len(top)} rows) and {OUT / 'incident_reports.md'} ({len(incidents)} incidents)")


if __name__ == "__main__":
    main()
