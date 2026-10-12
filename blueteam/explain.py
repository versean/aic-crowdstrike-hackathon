"""Turn scored meta-alerts into explained, ranked incidents (SHAP reasons + kill-chain stage + incident grouping)."""
import json

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score

from blueteam.ingest import DATA_DIR
from blueteam.train import LGB_PARAMS

FLAG_THRESHOLD = 0.5
INCIDENT_GAP = 3600

PHASE_TO_STAGE = {
    "network_scans": "Reconnaissance",
    "service_scans": "Reconnaissance",
    "wpscan": "Web discovery",
    "dirb": "Web discovery",
    "webshell": "Initial access (webshell upload)",
    "cracking": "Credential access",
    "reverse_shell": "Execution (reverse shell)",
    "privilege_escalation": "Privilege escalation",
    "service_stop": "Impact / exfiltration",
    "dnsteal": "Impact / exfiltration",
}
STAGE_ORDER = ["Reconnaissance", "Web discovery", "Initial access (webshell upload)", "Credential access",
               "Execution (reverse shell)", "Privilege escalation", "Impact / exfiltration"]
STAGE_MITRE = {
    "Reconnaissance": "TA0043 Reconnaissance / T1595 Active Scanning",
    "Web discovery": "T1595.003 Wordlist Scanning",
    "Initial access (webshell upload)": "T1190 Exploit Public-Facing App / T1505.003 Web Shell",
    "Credential access": "T1110.002 Password Cracking",
    "Execution (reverse shell)": "T1059 Command and Scripting Interpreter",
    "Privilege escalation": "T1548.003 Sudo and Sudo Caching",
    "Impact / exfiltration": "T1048 Exfiltration Over Alternative Protocol / T1489 Service Stop",
}


IOC_SHORT = {
    "ioc_service_account_pivot": "www-data user switch", "ioc_pty_without_login": "shell without login",
    "ioc_web_dir_exec": "exec from web/tmp dir", "ioc_sensitive_file": "credential file access",
    "ioc_tool_user_agent": "attack-tool user agent", "ioc_encoded_payload": "encoded payload",
    "ioc_php_in_uploads": "PHP in uploads",
}


def _fmt_dur(s):
    s = float(s)
    return f"{s:.0f}s" if s < 120 else (f"{s / 60:.0f} min" if s < 7200 else f"{s / 3600:.1f} h")


def reason_text(feat: str, v: float, row: pd.Series, contrib: float) -> str | None:
    with np.errstate(all="ignore"):
        return _reason_text(feat, v, row, contrib)


def _reason_text(feat: str, v: float, row: pd.Series, contrib: float) -> str | None:
    up = contrib > 0
    if pd.isna(v) and feat not in ("ip_kind",):
        return None
    t = {
        "ctx_rare_rules": f"{v:.0f} rarely-seen detections fired across the network in the same 10-min window"
        if up else "quiet period: few unusual detections network-wide",
        "rule_hour_frac": ("rule never seen before in this network" if v < 1e-3 else
                           f"rare rule here: active in only {v:.1%} of past hours") if up
        else f"routine rule: fires in {v:.0%} of past hours",
        "hours_since_rule_first": "first time this detection appears in the network" if v < 1 and up
        else f"rule first seen {v:.0f} h earlier",
        "rule_occurrence_rank": "one of the first occurrences of this rule" if up else "rule has fired many times before",
        "log_rule_count": f"rule fired only {np.expm1(v):.0f}x before" if up else f"high-volume rule ({np.expm1(v):,.0f} prior alerts)",
        "log_rule_meta_count": f"rule seen in only {np.expm1(v):.0f} earlier bursts" if up else f"rule recurs ({np.expm1(v):,.0f} earlier bursts)",
        "ctx_volume_ratio": f"alert volume {np.exp(v):.1f}x the normal level" if v > 0 else "alert volume at normal level",
        "ctx_hosts": f"{v:.0f} hosts alerting simultaneously",
        "ctx_rules": f"{v:.0f} distinct rules firing in the same window",
        "ctx_sources": f"{v:.0f} independent sensors (HIDS/NIDS/log-anomaly) corroborate",
        "host_ctx_rules": f"{v:.0f} distinct rules on this host in the same window",
        "host_ctx_sources": f"{v:.0f} sensor types on this host in the same window",
        "hours_since_ip_first": (f"source IP {row['src_ip']} first seen {v * 60:.0f} min earlier" if v < 2
                                 else f"source IP {row['src_ip']} known for {v:.0f} h"),
        "ip_rules": f"source IP triggered {v:.0f} different rules",
        "ip_hosts": f"source IP touched {v:.0f} hosts",
        "ip_hours": f"source IP active in {v:.0f} distinct hours",
        "log_ip_count": f"source IP produced {np.expm1(v):,.0f} earlier alerts",
        "ip_kind": {0: "no network actor", 1: "internal source IP", 2: "external source IP"}.get(int(v) if not pd.isna(v) else 0),
        "log_n_alerts": f"burst of {np.expm1(v):,.0f} alerts",
        "alert_rate": f"{v:.1f} alerts/sec",
        "duration_s": f"activity lasted {_fmt_dur(v)}",
        "n_urls": f"{v:.0f} distinct URLs requested",
        "n_users": f"{v:.0f} distinct user accounts",
        "max_level": f"Wazuh severity level {v:.0f}",
        "first_on_host": "first time on this host" if v == 1 else None,
        "log_max_firedtimes": f"rule already fired {np.expm1(v):,.0f}x in this burst",
        "ioc_service_account_pivot": "web-server account (www-data) used to switch user / run commands" if v else None,
        "ioc_pty_without_login": "interactive shell (pty) with no login session (typical reverse shell)" if v else None,
        "ioc_web_dir_exec": "commands executed from a web or temp directory (/var/www, /tmp)" if v else None,
        "ioc_sensitive_file": "access to credential files (/etc/shadow, /etc/passwd, SSH keys)" if v else None,
        "ioc_tool_user_agent": "scripted client / attack tool user agent (python-requests, curl, scanners)" if v else None,
        "ioc_encoded_payload": "long encoded payload in request or command" if v else None,
        "ioc_php_in_uploads": "PHP file requested from an uploads directory (webshell pattern)" if v else None,
        "ioc_ssh_admin_session": "regular SSH key login by an administrator (likely benign)" if v else None,
        "ioc_home_dir_exec": "commands run from a user home directory (normal admin work)" if v else None,
        "ioc_attacker_score": ("attacker indicators in raw logs: " + ", ".join(
            IOC_SHORT[c] for c in IOC_SHORT if c in row.index and row[c] > 0) if v else
                               "no attacker indicators in the raw log lines"),
        "acct_has_user": None,
        "acct_log_seen_on_host": ("account used on this host for the first time" if v == 0
                                  else f"account seen on this host {np.expm1(v):,.0f}x before"),
        "acct_log_seen_anywhere": ("account never seen before in the network" if v == 0
                                   else f"known account ({np.expm1(v):,.0f} earlier alerts)"),
        "acct_hosts_before": f"account previously used on {v:.0f} hosts",
    }.get(feat)
    if t is None and feat.startswith(("grp_", "tac_", "src_", "log_")):
        name = feat.split("_", 1)[1].replace("_", " ")
        t = f"signal type: {name}" if v == 1 else None
    return t


def add_explanations(meta, X, boosters, idx, k=4):
    Xi = X.loc[idx].to_numpy()
    contrib = np.mean([b.predict(Xi, pred_contrib=True)[:, :-1] for b in boosters], axis=0)
    cols = X.columns.to_numpy()
    out = {}
    for row_i, mi in enumerate(idx):
        c = contrib[row_i]
        order = np.argsort(-np.abs(c))
        reasons = []
        row = pd.concat([meta.loc[mi], X.loc[mi, list(IOC_SHORT)]])
        for j in order[:12]:
            txt = reason_text(cols[j], X.at[mi, cols[j]], row, c[j])
            if txt and txt not in [r["text"] for r in reasons]:
                reasons.append({"text": txt, "impact": round(float(c[j]), 3), "feature": cols[j]})
            if len(reasons) >= k:
                break
        out[mi] = reasons
    return out


def stage_classifier(meta, X):
    """LOSO multiclass model: which kill-chain stage does an attack meta-alert belong to?"""
    m = meta[meta["label"] == 1].copy()
    m["stage"] = m["phase"].map(PHASE_TO_STAGE)
    classes = [s for s in STAGE_ORDER if s in set(m["stage"])]
    y = m["stage"].map({s: i for i, s in enumerate(classes)})
    oof = pd.Series(index=m.index, dtype=object)
    params = {**LGB_PARAMS, "n_estimators": 200, "min_child_samples": 3}
    for sc in m["scenario"].unique():
        tr = m["scenario"] != sc
        clf = lgb.LGBMClassifier(**params).fit(X.loc[m.index[tr]], y[tr])
        oof[m.index[~tr]] = [classes[i] for i in clf.predict(X.loc[m.index[~tr]])]
    acc = accuracy_score(m["stage"], oof)
    f1 = f1_score(m["stage"], oof, average="macro")
    print(f"stage classifier (LOSO): accuracy={acc:.3f} macro-F1={f1:.3f}")
    final = lgb.LGBMClassifier(**params).fit(X.loc[m.index], y)
    return final, classes, {"stage_accuracy": acc, "stage_macro_f1": f1}


def build_incidents(meta: pd.DataFrame) -> pd.DataFrame:
    f = meta[meta["score_model"] >= FLAG_THRESHOLD].sort_values(["scenario", "start"]).copy()
    inc_ids = []
    cur, last_end, last_sc = -1, -np.inf, None
    for r in f[["scenario", "start", "end"]].itertuples():
        if r.scenario != last_sc or r.start - last_end > INCIDENT_GAP:
            cur += 1
            last_end = r.end
        last_end = max(last_end, r.end)
        last_sc = r.scenario
        inc_ids.append(cur)
    f["incident_id"] = inc_ids
    return f


def summarize_incidents(f: pd.DataFrame) -> pd.DataFrame:
    def agg(g):
        stages = [s for s in STAGE_ORDER if s in set(g["pred_stage"])]
        ext = sorted({ip for ip in g["src_ip"] if ip != "-"})
        risk = 1 - np.prod(1 - g["score_model"].clip(0, 0.999).to_numpy())
        return pd.Series({
            "scenario": g["scenario"].iloc[0],
            "start": g["start"].min(), "end": g["end"].max(),
            "n_meta": len(g), "n_alerts": int(g["n_alerts"].sum()),
            "max_score": g["score_model"].max(),
            "risk": float(risk) * (1 + 0.15 * len(stages)) * np.log1p(len(g)),
            "stages": stages, "n_stages": len(stages),
            "hosts": sorted(set(g["host"].astype(str)))[:12],
            "src_ips": ext[:12],
            "sensors": sorted(set(g["source"])),
            "true_attack_share": g["label"].mean(),
            "true_phases": sorted(set(g["phase"].dropna())),
        })
    inc = f.groupby("incident_id").apply(agg, include_groups=False).reset_index()
    inc["rank_in_scenario"] = inc.groupby("scenario")["risk"].rank(ascending=False, method="first").astype(int)
    return inc.sort_values(["scenario", "rank_in_scenario"])


def main():
    meta = pd.read_parquet(DATA_DIR / "meta_scored.parquet")
    X = pd.read_parquet(DATA_DIR / "features.parquet").astype("float32")
    boosters = [lgb.Booster(model_file=str(p)) for p in sorted(DATA_DIR.glob("model_seed*.txt"))]

    clf, classes, stage_metrics = stage_classifier(meta, X)
    flagged_idx = meta.index[meta["score_model"] >= FLAG_THRESHOLD]
    probs = clf.predict_proba(X.loc[flagged_idx])
    meta["pred_stage"] = None
    meta.loc[flagged_idx, "pred_stage"] = [classes[i] for i in probs.argmax(1)]
    meta.loc[flagged_idx, "stage_conf"] = probs.max(1)

    top_idx = meta.groupby("scenario")["score_model"].nlargest(300).index.get_level_values(1)
    explain_idx = flagged_idx.union(top_idx)
    reasons = add_explanations(meta, X, boosters, explain_idx)
    meta["reasons"] = None
    meta.loc[explain_idx, "reasons"] = [json.dumps(reasons[i]) for i in explain_idx]

    f = build_incidents(meta)
    meta["incident_id"] = np.nan
    meta.loc[f.index, "incident_id"] = f["incident_id"]
    inc = summarize_incidents(f)

    all_phases = meta[meta["label"] == 1].groupby("scenario")["phase"].agg(lambda s: set(s.dropna()))
    covered = f[f["label"] == 1].groupby("scenario")["phase"].agg(lambda s: set(s.dropna()))
    phase_recall = np.mean([len(covered.get(sc, set())) / len(p) for sc, p in all_phases.items()])
    stats = json.load(open(DATA_DIR / "stats.json"))
    stats.update(stage_metrics)
    stats.update({
        "n_flagged_meta": int(len(f)),
        "flagged_precision": float(f["label"].mean()),
        "n_incidents": int(len(inc)),
        "incident_precision": float((inc["true_attack_share"] > 0).mean()),
        "phase_recall_flagged": float(phase_recall),
        "attack_meta_recall": float(f["label"].sum() / meta["label"].sum()),
        "raw_alerts_flagged": int(f["n_alerts"].sum()),
    })
    json.dump(stats, open(DATA_DIR / "stats.json", "w"), indent=2)
    print(json.dumps(stats, indent=2))
    pd.set_option("display.width", 250)
    print(inc[["scenario", "rank_in_scenario", "n_meta", "n_alerts", "risk", "n_stages", "true_attack_share",
               "true_phases"]].to_string(index=False))

    meta.to_parquet(DATA_DIR / "meta_explained.parquet", index=False)
    inc.to_json(DATA_DIR / "incidents.json", orient="records", indent=1)


if __name__ == "__main__":
    main()
