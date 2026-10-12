"""Flatten the AIT-ADS JSON alerts (Wazuh, Suricata, AMiner) into one normalized parquet table."""
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np
import orjson
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "ait_ads"
LABELS_CSV = ROOT / "labels.csv"
DATA_DIR = ROOT / "data"

COLUMNS = [
    "scenario", "source", "ts", "agent_ip", "host", "rule_id", "rule_level", "rule_desc",
    "rule_groups", "firedtimes", "mitre_ids", "mitre_tactics", "decoder", "location",
    "src_ip", "src_port", "dst_ip", "dst_port", "user", "url", "status", "sig_id", "sig_cat",
    "sig_sev", "dns_query", "am_type", "am_n_paths", "am_values", "log",
]


def _s(v, n=400):
    if v is None:
        return None
    if isinstance(v, list):
        v = "|".join(map(str, v))
    return str(v)[:n]


def _wazuh(d, scenario):
    rule = d.get("rule", {})
    data = d.get("data", {}) or {}
    alert = data.get("alert", {}) or {}
    http = data.get("http", {}) or {}
    dns = data.get("dns", {}) or {}
    mitre = rule.get("mitre", {}) or {}
    location = d.get("location", "")
    is_suricata = location.endswith("eve.json")
    return {
        "scenario": scenario,
        "source": "suricata" if is_suricata else "wazuh",
        "ts": d.get("@timestamp"),
        "agent_ip": d.get("agent", {}).get("ip"),
        "host": (d.get("predecoder") or {}).get("hostname") or d.get("agent", {}).get("ip"),
        "rule_id": "S" + str(alert.get("signature_id")) if is_suricata and alert else "W" + str(rule.get("id")),
        "rule_level": rule.get("level"),
        "rule_desc": _s(rule.get("description"), 200),
        "rule_groups": _s(rule.get("groups")),
        "firedtimes": rule.get("firedtimes"),
        "mitre_ids": _s(mitre.get("id")),
        "mitre_tactics": _s(mitre.get("tactic")),
        "decoder": (d.get("decoder") or {}).get("name"),
        "location": location,
        "src_ip": data.get("srcip") or data.get("src_ip"),
        "src_port": data.get("srcport") or data.get("src_port"),
        "dst_ip": data.get("dstip") or data.get("dest_ip"),
        "dst_port": data.get("dstport") or data.get("dest_port"),
        "user": data.get("dstuser") or data.get("srcuser"),
        "url": _s(data.get("url") or http.get("url"), 300),
        "status": data.get("id") if not is_suricata else http.get("status"),
        "sig_id": alert.get("signature_id"),
        "sig_cat": alert.get("category"),
        "sig_sev": alert.get("severity"),
        "dns_query": dns.get("rrname"),
        "am_type": None,
        "am_n_paths": None,
        "am_values": None,
        "log": _s(d.get("full_log") or alert.get("signature")),
    }


def _aminer(d, scenario):
    ac = d.get("AnalysisComponent", {})
    ld = d.get("LogData", {})
    ts = (ld.get("Timestamps") or ld.get("DetectionTimestamp") or [None])[0]
    name = ac.get("AnalysisComponentName", "")
    raw = ld.get("RawLogData") or [""]
    return {
        "scenario": scenario,
        "source": "aminer",
        "ts": ts,
        "agent_ip": (d.get("AMiner") or {}).get("ID"),
        "host": (d.get("AMiner") or {}).get("ID"),
        "rule_id": "A" + name.replace("AMiner: ", "")[:60],
        "rule_level": None,
        "rule_desc": name,
        "rule_groups": _s(ac.get("AnalysisComponentType")),
        "firedtimes": None,
        "mitre_ids": None,
        "mitre_tactics": None,
        "decoder": ac.get("AnalysisComponentType"),
        "location": _s((ld.get("LogResources") or [None])[0]),
        "src_ip": None, "src_port": None, "dst_ip": None, "dst_port": None,
        "user": None, "url": None, "status": None,
        "sig_id": None, "sig_cat": None, "sig_sev": None, "dns_query": None,
        "am_type": ac.get("AnalysisComponentType"),
        "am_n_paths": len(ac.get("AffectedLogAtomPaths") or []),
        "am_values": _s(ac.get("AffectedLogAtomValues"), 300),
        "log": _s(raw[0]),
    }


def parse_file(path: Path) -> pd.DataFrame:
    scenario, kind = path.stem.rsplit("_", 1)
    fn = _aminer if kind == "aminer" else _wazuh
    rows = []
    with open(path, "rb") as f:
        for line in f:
            if line.strip():
                rows.append(fn(orjson.loads(line), scenario))
    df = pd.DataFrame(rows, columns=COLUMNS)
    if kind == "aminer":
        df["ts"] = df["ts"].astype(float)
    else:
        dt = pd.to_datetime(df["ts"], utc=True, format="ISO8601")
        df["ts"] = (dt - pd.Timestamp("1970-01-01", tz="UTC")) / pd.Timedelta(seconds=1)
    for c in ["rule_level", "firedtimes", "am_n_paths"]:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    for c in COLUMNS:
        if df[c].dtype == object:
            df[c] = df[c].astype("string")
    print(f"parsed {path.name}: {len(df):,}", flush=True)
    return df


def attach_labels(df: pd.DataFrame, labels: pd.DataFrame) -> pd.DataFrame:
    df["phase"] = pd.Series(pd.NA, index=df.index, dtype="string")
    for r in labels.itertuples():
        m = (df["scenario"] == r.scenario) & (df["ts"] >= r.start) & (df["ts"] <= r.end)
        df.loc[m, "phase"] = r.attack
    df["in_window"] = df["phase"].notna().astype(np.int8)
    return df


def main():
    DATA_DIR.mkdir(exist_ok=True)
    files = sorted(RAW_DIR.glob("*.json"), key=lambda p: -p.stat().st_size)
    with Pool(min(8, len(files))) as pool:
        parts = pool.map(parse_file, files)
    df = pd.concat(parts, ignore_index=True)
    df = df.sort_values(["scenario", "ts"], kind="stable").reset_index(drop=True)
    labels = pd.read_csv(LABELS_CSV)
    df = attach_labels(df, labels)
    df.to_parquet(DATA_DIR / "alerts.parquet", index=False)
    print(df.groupby(["scenario", "source"]).size().unstack(fill_value=0))
    print("alerts in attack windows:", int(df["in_window"].sum()), "of", len(df))


if __name__ == "__main__":
    sys.exit(main())
