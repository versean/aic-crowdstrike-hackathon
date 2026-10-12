"""Leave-one-scenario-out training of the meta-alert ranker + comparison with SOC baselines."""
import json

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score

from blueteam.ingest import DATA_DIR

LGB_PARAMS = dict(
    n_estimators=400, learning_rate=0.03, num_leaves=31, min_child_samples=10, subsample=0.8,
    subsample_freq=1, colsample_bytree=0.8, reg_lambda=1.0, verbose=-1, random_state=165,
)
POS_WEIGHT_CAP = 50.0
SEEDS = (165, 7, 42, 2024, 31337)
TOP_K = (10, 20, 50)
BEST_PARAMS = DATA_DIR / "best_params.json"


def load():
    meta = pd.read_parquet(DATA_DIR / "meta.parquet")
    X = pd.read_parquet(DATA_DIR / "features.parquet").astype("float32")
    return meta, X


def model_params() -> dict:
    p = LGB_PARAMS | {"pos_weight_cap": POS_WEIGHT_CAP}
    if BEST_PARAMS.exists():
        p |= json.load(open(BEST_PARAMS))
    return p


def fit_model(X, y, params=None, seed=None):
    p = dict(params or model_params())
    cap = p.pop("pos_weight_cap", POS_WEIGHT_CAP)
    if seed is not None:
        p["random_state"] = seed
    pos = max(int(y.sum()), 1)
    model = lgb.LGBMClassifier(**p, scale_pos_weight=min(cap, (len(y) - pos) / pos))
    model.fit(X, y)
    return model


def fit_ensemble(X, y, params=None, seeds=SEEDS):
    return [fit_model(X, y, params, s) for s in seeds]


def predict_ensemble(models, X):
    """Average log-odds across seeds, so tree-SHAP contributions average consistently."""
    margin = np.mean([m.predict(X, raw_score=True) for m in models], axis=0)
    return 1 / (1 + np.exp(-margin))


def isolation_scores(X, meta):
    out = pd.Series(np.nan, index=meta.index)
    for sc, idx in meta.groupby("scenario").groups.items():
        iso = IsolationForest(n_estimators=200, random_state=0, n_jobs=-1)
        Xi = X.loc[idx].fillna(-1)
        iso.fit(Xi)
        out.loc[idx] = -iso.score_samples(Xi)
    return out


def scenario_metrics(m: pd.DataFrame, score_col: str) -> dict:
    y = m["label"].to_numpy()
    s = m[score_col].to_numpy()
    r = {"roc_auc": roc_auc_score(y, s), "pr_auc": average_precision_score(y, s)}
    order = m.sort_values(score_col, ascending=False)
    phases_all = set(m.loc[m["label"] == 1, "phase"].dropna())
    for k in TOP_K:
        top = order.head(k)
        r[f"p@{k}"] = top["label"].mean()
        r[f"phases@{k}"] = len(set(top.loc[top["label"] == 1, "phase"].dropna()) & phases_all) / max(len(phases_all), 1)
    # benign meta-alerts an analyst can skip while still catching 90% of attack meta-alerts
    cum_tp = order["label"].cumsum().to_numpy()
    need = int(np.ceil(0.9 * y.sum()))
    cut = int(np.searchsorted(cum_tp, need)) + 1
    n_benign = (y == 0).sum()
    r["fp_suppressed@90recall"] = 1 - (order.head(cut)["label"] == 0).sum() / n_benign
    r["queue_size@90recall"] = cut
    return r


FEATURE_GROUPS = {
    "context": lambda c: c.startswith(("ctx_", "host_ctx_")),
    "src_ip": lambda c: c.startswith("ip_") or c in ("log_ip_count", "hours_since_ip_first"),
    "rule_rarity": lambda c: c in ("log_rule_count", "rule_hour_frac", "rule_hosts", "log_rule_meta_count",
                                   "hours_since_rule_first", "rule_occurrence_rank", "first_on_host"),
    "semantics": lambda c: c.startswith(("grp_", "tac_", "src_")) or c in (
        "log_audit", "log_apache", "log_auth", "log_dns", "log_suricata", "log_monitor", "log_syslog", "log_mail"),
    "log_content": lambda c: c.startswith("ioc_"),
    "account": lambda c: c.startswith("acct_"),
}


def loso_scores(meta, X, params=None, seeds=(None,)):
    s = pd.Series(np.nan, index=meta.index)
    for sc in meta["scenario"].unique():
        tr = meta["scenario"] != sc
        models = [fit_model(X[tr], meta.loc[tr, "label"], params, seed) for seed in seeds]
        s[~tr] = predict_ensemble(models, X[~tr])
    return s


def per_scenario(meta, col):
    return pd.DataFrame({sc: scenario_metrics(meta[meta.scenario == sc], col)
                         for sc in sorted(meta.scenario.unique())}).T


def tune(n_trials=16):
    """Random search under LOSO. Also reports a nested estimate: for each held-out network the config is
    chosen by mean PR-AUC on the other networks only, then scored on the held-out one."""
    meta, X = load()
    rng = np.random.default_rng(0)
    space = {
        "num_leaves": [7, 15, 31, 63], "min_child_samples": [5, 10, 20, 40], "colsample_bytree": [0.3, 0.5, 0.8],
        "reg_lambda": [0.0, 1.0, 5.0, 20.0], "pos_weight_cap": [5.0, 20.0, 50.0],
        "lr_trees": [(0.03, 400), (0.05, 300), (0.02, 800), (0.1, 150)],
    }
    trials = [{}]
    while len(trials) < n_trials:
        trials.append({k: v[rng.integers(len(v))] for k, v in space.items()})
    rows, per = [], {}
    for i, t in enumerate(trials):
        t = dict(t)
        if "lr_trees" in t:
            t["learning_rate"], t["n_estimators"] = t.pop("lr_trees")
        params = LGB_PARAMS | {"pos_weight_cap": POS_WEIGHT_CAP} | t
        meta["s"] = loso_scores(meta, X, params)
        per[i] = per_scenario(meta, "s")
        r = per[i].mean()
        rows.append({"trial": i, **t, **r[["pr_auc", "p@20", "queue_size@90recall"]].to_dict()})
        print(rows[-1], flush=True)
    res = pd.DataFrame(rows)
    pr = pd.DataFrame({i: p["pr_auc"] for i, p in per.items()})  # scenario x trial
    nested = {sc: pr.loc[sc, pr.drop(index=sc).mean().idxmax()] for sc in pr.index}
    best = int(res["pr_auc"].idxmax())
    print(res.sort_values("pr_auc", ascending=False).round(3).to_string(index=False))
    print(f"\ndefault PR-AUC {res.loc[0, 'pr_auc']:.3f} | best {res.loc[best, 'pr_auc']:.3f} (trial {best}) | "
          f"nested-selection estimate {np.mean(list(nested.values())):.3f}")
    res.to_csv(DATA_DIR / "tuning.csv", index=False)
    chosen = {k: (v.item() if hasattr(v, "item") else v) for k, v in res.loc[best].items()
              if k not in ("trial", "pr_auc", "p@20", "queue_size@90recall") and pd.notna(v)}
    for k in ("num_leaves", "min_child_samples", "n_estimators"):
        if k in chosen:
            chosen[k] = int(chosen[k])
    json.dump(chosen, open(BEST_PARAMS, "w"), indent=1)
    json.dump({"default_pr_auc": res.loc[0, "pr_auc"], "best_pr_auc": res.loc[best, "pr_auc"],
               "nested_pr_auc": float(np.mean(list(nested.values()))), "n_trials": len(trials)},
              open(DATA_DIR / "tuning_summary.json", "w"), indent=1)


def ablation():
    meta, X = load()
    rows = []
    configs = {"all features": []} | {f"without {g}": [g] for g in FEATURE_GROUPS}
    configs["semantics only"] = [g for g in FEATURE_GROUPS if g != "semantics"] + ["burst"]
    for name, drop in configs.items():
        keep = [c for c in X.columns if not any(
            (FEATURE_GROUPS[g](c) if g in FEATURE_GROUPS else not any(f(c) for f in FEATURE_GROUPS.values()))
            for g in drop)]
        meta["s"] = loso_scores(meta, X[keep])
        r = pd.DataFrame([scenario_metrics(meta[meta.scenario == sc], "s") for sc in meta.scenario.unique()]).mean()
        rows.append({"config": name, "n_features": len(keep), **r.to_dict()})
        print(rows[-1], flush=True)
    res = pd.DataFrame(rows)
    res.to_csv(DATA_DIR / "ablation.csv", index=False)
    print(res.round(3).to_string(index=False))


def main():
    meta, X = load()
    scenarios = sorted(meta["scenario"].unique())
    meta["score_model"] = np.nan
    importances = []
    for sc in scenarios:
        tr = meta["scenario"] != sc
        models = fit_ensemble(X[tr], meta.loc[tr, "label"])
        meta.loc[~tr, "score_model"] = predict_ensemble(models, X[~tr])
        importances += [pd.Series(m.booster_.feature_importance("gain"), index=X.columns) for m in models]
        print(f"fold {sc}: done", flush=True)

    meta["score_wazuh_level"] = meta["max_level"].fillna(0) + 1e-3 * np.log1p(meta["n_alerts"])
    meta["score_rarity"] = -X["log_rule_count"].to_numpy()
    meta["score_isoforest"] = isolation_scores(X, meta)

    rows = []
    for sc in scenarios:
        m = meta[meta["scenario"] == sc]
        for col in ["score_model", "score_wazuh_level", "score_rarity", "score_isoforest"]:
            rows.append({"scenario": sc, "method": col.replace("score_", ""), **scenario_metrics(m, col)})
    res = pd.DataFrame(rows)
    summary = res.groupby("method").mean(numeric_only=True).sort_values("pr_auc", ascending=False)
    pd.set_option("display.width", 250)
    print(res[res.method == "model"].round(3).to_string(index=False))
    print("\nmean over held-out scenarios:\n", summary.round(3).to_string())

    for old in DATA_DIR.glob("model_seed*.txt"):
        old.unlink()
    for seed, m in zip(SEEDS, fit_ensemble(X, meta["label"])):
        m.booster_.save_model(str(DATA_DIR / f"model_seed{seed}.txt"))
    meta.to_parquet(DATA_DIR / "meta_scored.parquet", index=False)
    res.to_csv(DATA_DIR / "metrics_by_scenario.csv", index=False)
    summary.to_csv(DATA_DIR / "metrics_summary.csv")
    imp = pd.concat(importances, axis=1).mean(axis=1).sort_values(ascending=False)
    imp.to_csv(DATA_DIR / "feature_importance.csv", header=["gain"])
    print("\ntop features:\n", imp.head(15).round(0).to_string())
    json.dump({"n_alerts": int(meta["n_alerts"].sum()), "n_meta": len(meta), "n_attack_meta": int(meta["label"].sum())},
              open(DATA_DIR / "stats.json", "w"))


if __name__ == "__main__":
    import sys

    ablation() if "--ablation" in sys.argv else tune() if "--tune" in sys.argv else main()
