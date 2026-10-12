"""Baseline, learning period and per-alert score breakdown for the analyst "Why suspicious?" view.

The breakdown uses the same leave-one-network-out seed ensembles as train.py, so it explains exactly the score the
analyst sees, produced by models that never saw that network.
"""
import json

import numpy as np
import pandas as pd

from blueteam.features import CONTEXT_BUCKET
from blueteam.ingest import DATA_DIR
from blueteam.train import fit_ensemble

LEARNING_HOURS = 24
N_CONTRIB = 10

IOC_LABELS = {
    "ioc_service_account_pivot": "Web-server account (www-data) switches user / runs commands",
    "ioc_pty_without_login": "Interactive shell with no login session",
    "ioc_web_dir_exec": "Commands run from a web or temp directory",
    "ioc_sensitive_file": "Credential file access (/etc/shadow, SSH keys)",
    "ioc_tool_user_agent": "Scripted client / attack-tool user agent",
    "ioc_encoded_payload": "Long encoded payload",
    "ioc_php_in_uploads": "PHP file requested from uploads/",
    "ioc_ssh_admin_session": "SSH key login by an administrator",
    "ioc_home_dir_exec": "Commands run from a user home directory",
}
# label, display kind: num | log (stored as log1p) | exp (stored as log ratio) | frac | flag
FEATURE_INFO = {
    "ctx_rare_rules": ("Rarely-seen detections network-wide, same 10 min", "num"),
    "ctx_rules": ("Distinct rules firing network-wide, same 10 min", "num"),
    "ctx_hosts": ("Hosts alerting, same 10 min", "num"),
    "ctx_sources": ("Sensor types corroborating, same 10 min", "num"),
    "ctx_volume_ratio": ("Alert volume vs normal (x)", "exp"),
    "host_ctx_rules": ("Distinct rules on this host, same 10 min", "num"),
    "host_ctx_sources": ("Sensor types on this host, same 10 min", "num"),
    "rule_hour_frac": ("Share of past hours this rule was active", "frac"),
    "log_rule_count": ("Earlier alerts from this rule", "log"),
    "log_rule_meta_count": ("Earlier bursts of this rule", "log"),
    "hours_since_rule_first": ("Hours since this rule was first seen", "num"),
    "rule_occurrence_rank": ("Occurrence number of this rule", "log"),
    "rule_hosts": ("Hosts this rule fired on before", "num"),
    "first_on_host": ("First time this rule fires on this host", "flag"),
    "log_ip_count": ("Earlier alerts from this source IP", "log"),
    "hours_since_ip_first": ("Hours since this source IP was first seen", "num"),
    "ip_rules": ("Distinct rules triggered by this source IP", "num"),
    "ip_hosts": ("Hosts touched by this source IP", "num"),
    "ip_hours": ("Hours this source IP was active", "num"),
    "ip_kind": ("Source IP: 0 none, 1 internal, 2 external", "num"),
    "log_n_alerts": ("Alerts in this burst", "log"),
    "duration_s": ("Burst duration (s)", "num"),
    "alert_rate": ("Alerts per second", "num"),
    "max_level": ("Wazuh severity level", "num"),
    "log_max_firedtimes": ("Times the rule fired within the burst", "log"),
    "n_urls": ("Distinct URLs", "num"),
    "n_users": ("Distinct user accounts", "num"),
    "n_dst_ports": ("Distinct destination ports", "num"),
    "n_dst_ips": ("Distinct destination IPs", "num"),
    "am_n_paths": ("Log fields flagged by AMiner", "num"),
    "ioc_attacker_score": ("Attacker indicators in raw log lines", "num"),
    "acct_has_user": ("Alert carries a user account", "flag"),
    "acct_log_seen_on_host": ("Earlier alerts with this account on this host", "log"),
    "acct_log_seen_anywhere": ("Earlier alerts with this account in the network", "log"),
    "acct_hosts_before": ("Hosts this account was seen on before", "num"),
} | {k: (v, "flag") for k, v in IOC_LABELS.items()}


def feature_info(feat: str) -> tuple[str, str]:
    if feat in FEATURE_INFO:
        return FEATURE_INFO[feat]
    prefix, rest = feat.split("_", 1) if "_" in feat else ("", feat)
    kind = {"grp": "Rule tag", "tac": "MITRE tactic", "src": "Sensor", "log": "Log source"}.get(prefix)
    return (f"{kind}: {rest.replace('_', ' ')}" if kind else feat), "flag"


def display_value(feat: str, v: float) -> str:
    if pd.isna(v):
        return "–"
    kind = feature_info(feat)[1]
    if kind == "log":
        return f"{np.expm1(v):,.0f}"
    if kind == "exp":
        return f"{np.exp(v):.1f}x"
    if kind == "frac":
        return f"{v:.1%}"
    if kind == "flag":
        return "yes" if v > 0 else "no"
    return f"{v:,.1f}" if abs(v) < 100 and v != int(v) else f"{v:,.0f}"


def learning_periods(alerts):
    g = alerts.groupby("scenario")["ts"]
    lp = pd.DataFrame({"t0": g.min(), "t_end": g.max()})
    lp["learn_end"] = lp["t0"] + LEARNING_HOURS * 3600
    in_lp = alerts["ts"] < alerts["scenario"].map(lp["learn_end"])
    lp["n_alerts_learning"] = alerts[in_lp].groupby("scenario").size()
    lp["n_rules_learning"] = alerts[in_lp].groupby("scenario")["rule_id"].nunique()
    return lp


def feature_baselines(meta, X, lp):
    in_lp = (meta["start"] < meta["scenario"].map(lp["learn_end"])).to_numpy()
    Xl = X[in_lp].assign(scenario=meta.loc[in_lp, "scenario"].to_numpy())
    g = Xl.groupby("scenario")
    out = pd.concat({"median": g.median(), "p95": g.quantile(0.95), "nonzero": g.agg(lambda s: (s > 0).mean())},
                    names=["stat"]).stack().rename("value").reset_index()
    out.columns = ["stat", "scenario", "feature", "value"]
    return out.pivot_table(index=["scenario", "feature"], columns="stat", values="value").reset_index()


def rule_hourly(alerts, meta, explained):
    keys = meta.loc[explained, ["scenario", "rule_id"]].drop_duplicates()
    a = alerts.merge(keys, on=["scenario", "rule_id"])
    a["hour"] = (a["ts"] // 3600 * 3600).astype(np.int64)
    return a.groupby(["scenario", "rule_id", "hour"]).size().rename("n").reset_index()


def network_series(alerts, meta, X):
    a = alerts.assign(bucket=(alerts["ts"] // CONTEXT_BUCKET * CONTEXT_BUCKET).astype(np.int64))
    vol = a.groupby(["scenario", "bucket"]).agg(n_alerts=("ts", "size"), n_rules=("rule_id", "nunique"))
    m = meta[["scenario", "start"]].assign(
        bucket=(meta["start"] // CONTEXT_BUCKET * CONTEXT_BUCKET).astype(np.int64),
        rare=X["ctx_rare_rules"].to_numpy())
    rare = m.groupby(["scenario", "bucket"])["rare"].max().rename("rare_rules")
    return vol.join(rare).fillna({"rare_rules": 0}).reset_index()


def score_breakdown(meta, X, explained):
    """Tree-SHAP contributions (log-odds) from the held-out-network seed ensemble that produced score_model."""
    cols = X.columns.to_numpy()
    rows = {}
    for sc in sorted(meta["scenario"].unique()):
        tr = (meta["scenario"] != sc).to_numpy()
        idx = meta.index[~tr].intersection(explained)
        if not len(idx):
            continue
        models = fit_ensemble(X[tr], meta.loc[tr, "label"])
        Xi = X.loc[idx].to_numpy()
        contrib = np.mean([m.booster_.predict(Xi, pred_contrib=True) for m in models], axis=0)
        for i, mi in enumerate(idx):
            c, bias = contrib[i, :-1], contrib[i, -1]
            top = np.argsort(-np.abs(c))[:N_CONTRIB]
            rows[mi] = {
                "bias": float(bias), "rest": float(c.sum() - c[top].sum()),
                "contrib": json.dumps([[cols[j], float(Xi[i, j]), float(c[j])] for j in top]),
            }
        print(f"breakdown {sc}: {len(idx)} alerts", flush=True)
    return pd.DataFrame.from_dict(rows, orient="index")


def main():
    meta = pd.read_parquet(DATA_DIR / "meta_explained.parquet")
    X = pd.read_parquet(DATA_DIR / "features.parquet").astype("float32")
    alerts = pd.read_parquet(DATA_DIR / "alerts.parquet", columns=["scenario", "ts", "rule_id"])
    explained = meta.index[meta["reasons"].notna()]

    lp = learning_periods(alerts)
    lp.reset_index().to_json(DATA_DIR / "learning_periods.json", orient="records", indent=1)
    feature_baselines(meta, X, lp).to_parquet(DATA_DIR / "feature_baseline.parquet", index=False)
    rule_hourly(alerts, meta, explained).to_parquet(DATA_DIR / "rule_hourly.parquet", index=False)
    network_series(alerts, meta, X).to_parquet(DATA_DIR / "network_series.parquet", index=False)

    bd = score_breakdown(meta, X, explained)
    bd.index.name = "row"
    bd.reset_index().to_parquet(DATA_DIR / "score_breakdown.parquet", index=False)

    flagged = meta["score_model"] >= 0.5
    early = flagged & (meta["start"] < meta["scenario"].map(lp["learn_end"]))
    print(lp.round(0).to_string())
    print(f"flagged during learning period: {int(early.sum())} of {int(flagged.sum())} "
          f"({int(meta.loc[early, 'label'].sum())} attack)")


if __name__ == "__main__":
    main()
