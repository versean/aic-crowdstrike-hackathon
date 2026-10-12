"""Meta-alert construction + config-driven feature calcers (registry pattern from the Magnit hack)."""
import ipaddress
from abc import ABC, abstractmethod
from functools import lru_cache

import numpy as np
import pandas as pd

from blueteam.ingest import DATA_DIR, LABELS_CSV

GAP_SECONDS = 300
CONTEXT_BUCKET = 600
ENRICHMENT_THRESHOLD = 10.0


# --------------------------------------------------------------------------- labels

def denoise_labels(df: pd.DataFrame, labels: pd.DataFrame) -> pd.DataFrame:
    """In-window alerts count as attack only if their rule is >=10x enriched inside attack windows."""
    labels = labels.assign(dur=labels["end"] - labels["start"])
    window_dur = labels.groupby("scenario")["dur"].sum()
    span = df.groupby("scenario")["ts"].agg(lambda s: s.max() - s.min())
    c = df.groupby(["scenario", "rule_id", "in_window"]).size().unstack(fill_value=0)
    c = c.reindex(columns=[0, 1], fill_value=0)
    c.columns = ["out", "inn"]
    c = c.reset_index()
    wd = c["scenario"].map(window_dur)
    sp = c["scenario"].map(span)
    c["enrichment"] = (c["inn"] / wd) / ((c["out"] + 1) / (sp - wd))
    enr = c.set_index(["scenario", "rule_id"])["enrichment"]
    key = pd.MultiIndex.from_arrays([df["scenario"], df["rule_id"]])
    df["rule_enrichment"] = enr.reindex(key).to_numpy()
    df["is_attack"] = ((df["in_window"] == 1) & (df["rule_enrichment"] >= ENRICHMENT_THRESHOLD)).astype(np.int8)
    df.loc[df["is_attack"] == 0, "phase_attack"] = pd.NA
    df.loc[df["is_attack"] == 1, "phase_attack"] = df.loc[df["is_attack"] == 1, "phase"]
    return df


# --------------------------------------------------------------------------- meta-alerts

def build_meta_alerts(df: pd.DataFrame) -> pd.DataFrame:
    """Collapse repeated alerts (same scenario/host/rule/src_ip, gap <= 5 min) into one meta-alert."""
    df["src_key"] = df["src_ip"].fillna("-")
    df = df.sort_values(["scenario", "host", "rule_id", "src_key", "ts"], kind="stable").reset_index(drop=True)
    same = (
        (df["scenario"] == df["scenario"].shift())
        & (df["host"] == df["host"].shift())
        & (df["rule_id"] == df["rule_id"].shift())
        & (df["src_key"] == df["src_key"].shift())
        & ((df["ts"] - df["ts"].shift()) <= GAP_SECONDS)
    ).fillna(False).to_numpy(dtype=bool)
    df["meta_id"] = np.cumsum(~same) - 1

    g = df.groupby("meta_id", sort=False)
    meta = g.agg(
        scenario=("scenario", "first"),
        host=("host", "first"),
        agent_ip=("agent_ip", "first"),
        rule_id=("rule_id", "first"),
        rule_desc=("rule_desc", "first"),
        rule_groups=("rule_groups", "first"),
        source=("source", "first"),
        decoder=("decoder", "first"),
        am_type=("am_type", "first"),
        sig_cat=("sig_cat", "first"),
        mitre_ids=("mitre_ids", "first"),
        mitre_tactics=("mitre_tactics", "first"),
        location=("location", "first"),
        src_ip=("src_key", "first"),
        start=("ts", "min"),
        end=("ts", "max"),
        n_alerts=("ts", "size"),
        max_level=("rule_level", "max"),
        max_firedtimes=("firedtimes", "max"),
        sig_sev=("sig_sev", "first"),
        n_urls=("url", "nunique"),
        n_users=("user", "nunique"),
        n_dst_ports=("dst_port", "nunique"),
        n_dst_ips=("dst_ip", "nunique"),
        am_n_paths=("am_n_paths", "max"),
        sample_log=("log", "first"),
        sample_url=("url", "first"),
        attack_share=("is_attack", "mean"),
        in_window_share=("in_window", "mean"),
        phase=("phase_attack", lambda s: s.mode().iloc[0] if s.notna().any() else None),
    ).reset_index()
    meta["label"] = (meta["attack_share"] >= 0.5).astype(np.int8)
    return meta, df[["meta_id", "scenario", "ts", "host", "rule_id", "source", "src_key", "is_attack",
                     "log", "url", "user"]]


# --------------------------------------------------------------------------- calcers

class FeatureCalcer(ABC):
    name = "_base"

    def __init__(self, **params):
        self.params = params

    @abstractmethod
    def compute(self, meta: pd.DataFrame, alerts: pd.DataFrame) -> pd.DataFrame:
        """Return a frame indexed like `meta` with new feature columns."""


CALCER_REFERENCE = {}


def register_calcer(cls):
    CALCER_REFERENCE[cls.name] = cls
    return cls


def create_calcer(name: str, **kwargs) -> FeatureCalcer:
    return CALCER_REFERENCE[name](**kwargs)


@register_calcer
class BurstCalcer(FeatureCalcer):
    name = "burst"

    def compute(self, meta, alerts):
        dur = (meta["end"] - meta["start"]).clip(lower=0)
        return pd.DataFrame({
            "log_n_alerts": np.log1p(meta["n_alerts"]),
            "duration_s": dur,
            "alert_rate": meta["n_alerts"] / (dur + 1),
            "max_level": meta["max_level"],
            "log_max_firedtimes": np.log1p(meta["max_firedtimes"]),
            "sig_sev": pd.to_numeric(meta["sig_sev"], errors="coerce"),
            "n_urls": meta["n_urls"],
            "n_users": meta["n_users"],
            "n_dst_ports": meta["n_dst_ports"],
            "n_dst_ips": meta["n_dst_ips"],
            "am_n_paths": meta["am_n_paths"],
        }, index=meta.index)


@register_calcer
class RuleRarityCalcer(FeatureCalcer):
    """How routine is this rule in this network? (label-free, computed per scenario)."""
    name = "rule_rarity"

    def compute(self, meta, alerts):
        a = alerts.assign(hour=(alerts["ts"] // 3600).astype(np.int64))
        hours = a.groupby("scenario")["hour"].nunique()
        rs = a.groupby(["scenario", "rule_id"]).agg(
            rule_count=("ts", "size"), rule_hours=("hour", "nunique"), rule_hosts=("host", "nunique"),
            rule_first=("ts", "min"),
        ).reset_index()
        rs["rule_hour_frac"] = rs["rule_hours"] / rs["scenario"].map(hours)
        rm = meta.groupby(["scenario", "rule_id"]).size().rename("rule_meta_count").reset_index()
        m = meta[["scenario", "rule_id", "host", "start"]].merge(rs, on=["scenario", "rule_id"], how="left")
        m = m.merge(rm, on=["scenario", "rule_id"], how="left")
        order_rule = meta.groupby(["scenario", "rule_id"])["start"].rank(method="first")
        order_rule_host = meta.groupby(["scenario", "rule_id", "host"])["start"].rank(method="first")
        return pd.DataFrame({
            "log_rule_count": np.log1p(m["rule_count"].to_numpy()),
            "rule_hour_frac": m["rule_hour_frac"].to_numpy(),
            "rule_hosts": m["rule_hosts"].to_numpy(),
            "log_rule_meta_count": np.log1p(m["rule_meta_count"].to_numpy()),
            "hours_since_rule_first": ((m["start"] - m["rule_first"]) / 3600).to_numpy(),
            "rule_occurrence_rank": np.log1p(order_rule.to_numpy()),
            "first_on_host": (order_rule_host.to_numpy() == 1).astype(np.int8),
        }, index=meta.index)


def prior_counts(events: pd.DataFrame, queries: pd.DataFrame, keys: list[str]) -> np.ndarray:
    """For each query row, number of event rows with the same keys and ts strictly before the query ts."""
    ev = events[keys + ["ts"]].assign(_w=1, _q=-1)
    q = queries[keys + ["ts"]].assign(_w=0, _q=np.arange(len(queries)))
    allx = pd.concat([ev, q], ignore_index=True).sort_values(keys + ["ts", "_w"], kind="stable")
    allx["_c"] = allx.groupby(keys, sort=False)["_w"].cumsum()
    res = allx.loc[allx["_w"] == 0, ["_q", "_c"]].sort_values("_q")
    return res["_c"].to_numpy()


def first_occurrences(alerts: pd.DataFrame, keys: list[str]) -> pd.DataFrame:
    return alerts.groupby(keys, sort=False)["ts"].min().reset_index()


@register_calcer
class RuleRarityCausalCalcer(FeatureCalcer):
    """Streaming-safe rule rarity: only alerts strictly before the meta-alert are used."""
    name = "rule_rarity_causal"

    def compute(self, meta, alerts):
        a = alerts.assign(hour=(alerts["ts"] // 3600).astype(np.int64))
        q = meta[["scenario", "rule_id", "host", "start"]].rename(columns={"start": "ts"})
        n_prior = prior_counts(a, q, ["scenario", "rule_id"])
        hours_prior = prior_counts(first_occurrences(a, ["scenario", "rule_id", "hour"]), q, ["scenario", "rule_id"])
        hosts_prior = prior_counts(first_occurrences(a, ["scenario", "rule_id", "host"]), q, ["scenario", "rule_id"])
        t0 = q["scenario"].map(a.groupby("scenario")["ts"].min())
        elapsed_h = np.maximum((q["ts"] - t0).to_numpy() / 3600, 1.0)
        rule_first = q.merge(first_occurrences(a, ["scenario", "rule_id"]).rename(columns={"ts": "first"}),
                             on=["scenario", "rule_id"], how="left")["first"].to_numpy()
        order_rule = meta.groupby(["scenario", "rule_id"])["start"].rank(method="first")
        order_rule_host = meta.groupby(["scenario", "rule_id", "host"])["start"].rank(method="first")
        return pd.DataFrame({
            "log_rule_count": np.log1p(n_prior),
            "rule_hour_frac": np.minimum(hours_prior / elapsed_h, 1.0),
            "rule_hosts": hosts_prior,
            "log_rule_meta_count": np.log1p(order_rule.to_numpy() - 1),
            "hours_since_rule_first": (q["ts"].to_numpy() - rule_first) / 3600,
            "rule_occurrence_rank": np.log1p(order_rule.to_numpy()),
            "first_on_host": (order_rule_host.to_numpy() == 1).astype(np.int8),
        }, index=meta.index)


@register_calcer
class SourceIpCausalCalcer(FeatureCalcer):
    """Streaming-safe actor history: only alerts strictly before the meta-alert are used."""
    name = "src_ip_causal"

    def compute(self, meta, alerts):
        a = alerts[alerts["src_key"] != "-"].rename(columns={"src_key": "src_ip"})
        a = a.assign(hour=(a["ts"] // 3600).astype(np.int64))
        q = meta[["scenario", "src_ip", "start"]].rename(columns={"start": "ts"})
        k = ["scenario", "src_ip"]
        n_prior = prior_counts(a, q, k)
        rules_prior = prior_counts(first_occurrences(a, k + ["rule_id"]), q, k)
        hosts_prior = prior_counts(first_occurrences(a, k + ["host"]), q, k)
        hours_prior = prior_counts(first_occurrences(a, k + ["hour"]), q, k)
        ip_first = q.merge(first_occurrences(a, k).rename(columns={"ts": "first"}), on=k, how="left")["first"]
        has_ip = (meta["src_ip"] != "-").to_numpy()
        return pd.DataFrame({
            "ip_kind": meta["src_ip"].map(_ip_kind).to_numpy(),
            "log_ip_count": np.where(has_ip, np.log1p(n_prior), np.nan),
            "ip_rules": np.where(has_ip, rules_prior, np.nan),
            "ip_hosts": np.where(has_ip, hosts_prior, np.nan),
            "ip_hours": np.where(has_ip, hours_prior, np.nan),
            "hours_since_ip_first": np.where(has_ip, (q["ts"] - ip_first).to_numpy() / 3600, np.nan),
        }, index=meta.index)


@lru_cache(maxsize=100_000)
def _ip_kind(ip: str) -> int:
    """0 = none, 1 = private, 2 = public."""
    if ip in ("-", "", None):
        return 0
    try:
        return 1 if ipaddress.ip_address(ip).is_private else 2
    except ValueError:
        return 0


@register_calcer
class SourceIpCalcer(FeatureCalcer):
    """Is the actor behind this alert new / noisy / touching many rules?"""
    name = "src_ip"

    def compute(self, meta, alerts):
        a = alerts[alerts["src_key"] != "-"]
        s = a.groupby(["scenario", "src_key"]).agg(
            ip_count=("ts", "size"), ip_rules=("rule_id", "nunique"), ip_hosts=("host", "nunique"),
            ip_first=("ts", "min"),
        ).reset_index().rename(columns={"src_key": "src_ip"})
        hours = alerts.assign(h=alerts["ts"] // 3600).groupby(["scenario", "src_key"])["h"].nunique()
        hours = hours.rename("ip_hours").reset_index().rename(columns={"src_key": "src_ip"})
        m = meta[["scenario", "src_ip", "start"]].merge(s, on=["scenario", "src_ip"], how="left")
        m = m.merge(hours, on=["scenario", "src_ip"], how="left")
        has_ip = (meta["src_ip"] != "-").to_numpy()
        out = pd.DataFrame({
            "ip_kind": meta["src_ip"].map(_ip_kind).to_numpy(),
            "log_ip_count": np.where(has_ip, np.log1p(m["ip_count"].to_numpy()), np.nan),
            "ip_rules": np.where(has_ip, m["ip_rules"].to_numpy(), np.nan),
            "ip_hosts": np.where(has_ip, m["ip_hosts"].to_numpy(), np.nan),
            "ip_hours": np.where(has_ip, m["ip_hours"].to_numpy(), np.nan),
            "hours_since_ip_first": np.where(has_ip, ((m["start"] - m["ip_first"]) / 3600).to_numpy(), np.nan),
        }, index=meta.index)
        return out


@register_calcer
class ContextCalcer(FeatureCalcer):
    """What else is happening around this meta-alert? (multi-sensor corroboration, volume spikes)."""
    name = "context"

    def compute(self, meta, alerts):
        bucket = self.params.get("bucket", CONTEXT_BUCKET)
        causal = self.params.get("causal", False)
        a = alerts.assign(b=(alerts["ts"] // bucket).astype(np.int64))
        if causal:
            rb = a[["scenario", "rule_id", "b"]].drop_duplicates()
            rb["ts"] = rb["b"] * bucket
            first_hours = first_occurrences(a.assign(hour=(a["ts"] // 3600).astype(np.int64)),
                                            ["scenario", "rule_id", "hour"])
            t0 = rb["scenario"].map(a.groupby("scenario")["ts"].min())
            elapsed_h = np.maximum((rb["ts"] - t0).to_numpy() / 3600, 1.0)
            rb["is_rare"] = prior_counts(first_hours, rb, ["scenario", "rule_id"]) / elapsed_h < 0.05
            a = a.merge(rb[["scenario", "rule_id", "b", "is_rare"]], on=["scenario", "rule_id", "b"], how="left")
        else:
            hours = a.assign(h=a["ts"] // 3600).groupby(["scenario", "rule_id"])["h"].nunique()
            n_hours = a.assign(h=a["ts"] // 3600).groupby("scenario")["h"].nunique()
            rare = (hours / hours.index.get_level_values(0).map(n_hours).to_numpy()) < 0.05
            rare_rules = set(rare[rare].index)
            a["is_rare"] = [k in rare_rules for k in zip(a["scenario"], a["rule_id"])]

        net = a.groupby(["scenario", "b"]).agg(
            ctx_rules=("rule_id", "nunique"), ctx_hosts=("host", "nunique"), ctx_sources=("source", "nunique"),
            ctx_volume=("ts", "size"),
        )
        rare_ctx = a[a["is_rare"]].groupby(["scenario", "b"])["rule_id"].nunique().rename("ctx_rare_rules")
        net = net.join(rare_ctx, how="left").fillna({"ctx_rare_rules": 0}).reset_index()
        if causal:
            net = net.sort_values(["scenario", "b"])
            med = net.groupby("scenario")["ctx_volume"].transform(lambda s: s.expanding().median().shift(1))
            med = med.fillna(net["ctx_volume"])
        else:
            med = net.groupby("scenario")["ctx_volume"].transform("median")
        net["ctx_volume_ratio"] = np.log1p(net["ctx_volume"]) - np.log1p(med)

        hostctx = a.groupby(["scenario", "host", "b"]).agg(
            host_ctx_rules=("rule_id", "nunique"), host_ctx_sources=("source", "nunique"),
        ).reset_index()

        mb = meta[["scenario", "host"]].assign(b=(meta["start"] // bucket).astype(np.int64))
        feats = []
        for shift in (0,):
            m = mb.assign(b=mb["b"] + shift)
            m = m.merge(net, on=["scenario", "b"], how="left").merge(hostctx, on=["scenario", "host", "b"], how="left")
            feats.append(m)
        m = feats[0]
        cols = ["ctx_rules", "ctx_hosts", "ctx_sources", "ctx_rare_rules", "ctx_volume_ratio",
                "host_ctx_rules", "host_ctx_sources"]
        out = m[cols].copy()
        out.index = meta.index
        return out


IOC_PATTERNS = {
    # attacker tradecraft
    "ioc_service_account_pivot": r"(?:by|for) (?:www-data|apache|nginx|nobody|daemon)\b|www-data:|\(uid=33\)|\buid=33\b",
    "ioc_pty_without_login": r"auid=4294967295.*terminal=/dev/pts",
    "ioc_web_dir_exec": r"(?:PWD|cwd)=\"?/(?:var/www|tmp|dev/shm)",
    "ioc_sensitive_file": r"/etc/shadow|/etc/passwd|id_rsa|/\.ssh/",
    "ioc_tool_user_agent": r"python-requests|curl/|wget/|nmap|sqlmap|nikto|wpscan|gobuster|hydra",
    "ioc_encoded_payload": r"=[A-Za-z0-9+/%]{60,}",
    "ioc_php_in_uploads": r"/uploads/[^ ?]*\.php",
    # benign administration
    "ioc_ssh_admin_session": r"Accepted publickey|exe=\"/usr/sbin/sshd\"|terminal=ssh",
    "ioc_home_dir_exec": r"(?:PWD|cwd)=\"?/home/",
}


def _decode_audit_hex(text: pd.Series) -> pd.Series:
    """auditd logs commands as hex (cmd=636174...); decode so content IOCs can match them."""
    hexes = text.str.extract(r"cmd=([0-9A-F]{6,})", expand=False)
    uniq = {h: bytes.fromhex(h).decode("latin-1") for h in hexes.dropna().unique() if len(h) % 2 == 0}
    decoded = hexes.map(uniq)
    return text.where(decoded.isna(), text + " decoded_cmd=" + decoded.fillna(""))


@register_calcer
class LogContentCalcer(FeatureCalcer):
    """Detection-engineering indicators from raw log text, max-aggregated over every alert in the meta-alert."""
    name = "log_content"

    def compute(self, meta, alerts):
        text = (alerts["log"].fillna("") + " " + alerts["url"].fillna("")).astype(object)
        text = _decode_audit_hex(pd.Series(text, index=alerts.index))
        flags = pd.DataFrame({k: text.str.contains(p, regex=True, case=False).astype(np.int8)
                              for k, p in IOC_PATTERNS.items()}, index=alerts.index)
        flags["meta_id"] = alerts["meta_id"].to_numpy()
        agg = flags.groupby("meta_id").max()
        out = agg.reindex(meta["meta_id"]).fillna(0).astype(np.int8)
        out.index = meta.index
        out["ioc_attacker_score"] = out[[c for c in IOC_PATTERNS if c not in
                                         ("ioc_ssh_admin_session", "ioc_home_dir_exec")]].sum(axis=1)
        return out


@register_calcer
class AccountNoveltyCalcer(FeatureCalcer):
    """Streaming-safe: has this account been seen on this host / anywhere before?"""
    name = "account"

    def compute(self, meta, alerts):
        a = alerts[alerts["user"].notna()].copy()
        a["user"] = a["user"].astype(str)
        first_user = a.groupby("meta_id")["user"].first()
        q = meta[["scenario", "host", "start", "meta_id"]].rename(columns={"start": "ts"}).copy()
        q["user"] = q["meta_id"].map(first_user)
        has_user = q["user"].notna().to_numpy()
        q["user"] = q["user"].fillna("-")
        on_host = prior_counts(a, q, ["scenario", "host", "user"])
        anywhere = prior_counts(a, q, ["scenario", "user"])
        hosts = prior_counts(first_occurrences(a, ["scenario", "user", "host"]), q, ["scenario", "user"])
        return pd.DataFrame({
            "acct_has_user": has_user.astype(np.int8),
            "acct_log_seen_on_host": np.where(has_user, np.log1p(on_host), np.nan),
            "acct_log_seen_anywhere": np.where(has_user, np.log1p(anywhere), np.nan),
            "acct_hosts_before": np.where(has_user, hosts, np.nan),
        }, index=meta.index)


TOKEN_VOCAB = [
    "attack", "web", "appsec", "accesslog", "ids", "suricata", "authentication_failed", "authentication_success",
    "invalid_login", "sshd", "pam", "syslog", "sudo", "su", "dovecot", "audit", "audit_selinux", "recon",
    "web_scan", "freshclam", "virus", "local", "low_diskspace", "service_availability",
    "NewMatchPathDetector", "NewMatchPathValueDetector", "NewMatchPathValueComboDetector", "CharsetDetector",
    "EntropyDetector", "EventCountClusterDetector", "EventFrequencyDetector", "ValueRangeDetector",
    "MatchValueAverageChangeDetector",
]
TACTICS = ["Credential Access", "Initial Access", "Privilege Escalation", "Persistence", "Defense Evasion",
           "Lateral Movement", "Discovery", "Impact", "Execution"]


@register_calcer
class SemanticsCalcer(FeatureCalcer):
    """What kind of signal is it? (rule groups, sensor, AMiner detector type, MITRE tactic)."""
    name = "semantics"

    def compute(self, meta, alerts):
        groups = meta["rule_groups"].fillna("")
        tactics = meta["mitre_tactics"].fillna("")
        loc = meta["location"].fillna("")
        out = {f"grp_{t}": groups.str.split("|").apply(lambda xs, t=t: t in xs).astype(np.int8) for t in TOKEN_VOCAB}
        out.update({f"tac_{t.replace(' ', '_')}": tactics.str.contains(t, regex=False).astype(np.int8) for t in TACTICS})
        out["src_wazuh"] = (meta["source"] == "wazuh").astype(np.int8)
        out["src_suricata"] = (meta["source"] == "suricata").astype(np.int8)
        out["src_aminer"] = (meta["source"] == "aminer").astype(np.int8)
        for k in ["audit", "apache", "auth", "dns", "suricata", "monitor", "syslog", "mail"]:
            out[f"log_{k}"] = loc.str.contains(k, regex=False).astype(np.int8)
        return pd.DataFrame(out, index=meta.index)


DEFAULT_CONFIG = [
    {"name": "burst", "args": {}},
    {"name": "rule_rarity", "args": {}},
    {"name": "src_ip", "args": {}},
    {"name": "context", "args": {"bucket": CONTEXT_BUCKET}},
    {"name": "semantics", "args": {}},
    {"name": "log_content", "args": {}},
    {"name": "account", "args": {}},
]


CAUSAL_CONFIG = [
    {"name": "burst", "args": {}},
    {"name": "rule_rarity_causal", "args": {}},
    {"name": "src_ip_causal", "args": {}},
    {"name": "context", "args": {"bucket": CONTEXT_BUCKET, "causal": True}},
    {"name": "semantics", "args": {}},
    {"name": "log_content", "args": {}},
    {"name": "account", "args": {}},
]


def compute_features(meta: pd.DataFrame, alerts: pd.DataFrame, config=DEFAULT_CONFIG) -> pd.DataFrame:
    parts = []
    for cfg in config:
        calcer = create_calcer(cfg["name"], **cfg["args"])
        parts.append(calcer.compute(meta, alerts))
        print(f"  calcer {cfg['name']}: {parts[-1].shape[1]} features", flush=True)
    return pd.concat(parts, axis=1)


def main(causal: bool = True):
    df = pd.read_parquet(DATA_DIR / "alerts.parquet")
    df = denoise_labels(df, pd.read_csv(LABELS_CSV))
    print("attack alerts after denoising:", int(df["is_attack"].sum()), "of", int(df["in_window"].sum()), "in-window")
    meta, alerts = build_meta_alerts(df)
    print(f"meta-alerts: {len(meta):,} from {len(df):,} alerts; attack meta-alerts: {int(meta['label'].sum()):,}")
    X = compute_features(meta, alerts, CAUSAL_CONFIG if causal else DEFAULT_CONFIG)
    meta.to_parquet(DATA_DIR / "meta.parquet", index=False)
    X.to_parquet(DATA_DIR / ("features.parquet" if causal else "features_batch.parquet"), index=False)
    alerts[["meta_id", "ts"]].to_parquet(DATA_DIR / "alert_meta_map.parquet", index=False)
    print(meta.groupby("scenario")["label"].agg(["size", "sum"]))


if __name__ == "__main__":
    import sys

    main(causal="--batch" not in sys.argv)
