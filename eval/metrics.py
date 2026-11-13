"""Metric code shared by every model. Model owners never compute metrics themselves.

All functions take `labels` (0 = benign, 1 = tunnel) and `scores` (higher = more
suspicious), exactly as written to results/<model>/<exp>.json.
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import confusion_matrix, roc_auc_score, roc_curve

# Selection rule from the board: best F1 at under 1% FPR and under 10 ms per query.
MAX_FPR = 0.01
MAX_LATENCY_MS = 10.0


def threshold_at_fpr(labels, scores, max_fpr: float = MAX_FPR) -> float:
    """Lowest threshold whose false-positive rate on benign rows is <= max_fpr.

    Use this on a VALIDATION split and store the result in the results JSON.
    Only falls back to the test set when a run did not provide a threshold.
    """
    labels = np.asarray(labels)
    benign = np.sort(np.asarray(scores, dtype=float)[labels == 0])
    if benign.size == 0:
        return 0.5
    # Allow at most floor(max_fpr * n) benign scores to be >= threshold.
    k = int(np.floor(max_fpr * benign.size))
    idx = benign.size - k - 1  # largest benign score that must stay below the threshold
    return float(np.nextafter(benign[idx], np.inf))


def recall_at_fpr(labels, scores, max_fpr: float = MAX_FPR) -> float:
    """Recall at the best operating point with FPR <= max_fpr (threshold-free view)."""
    labels = np.asarray(labels)
    if labels.min() == labels.max():
        return float("nan")
    fpr, tpr, _ = roc_curve(labels, scores)
    ok = fpr <= max_fpr
    return float(tpr[ok].max()) if ok.any() else 0.0


def binary_metrics(labels, scores, threshold: float) -> dict:
    """Threshold-based metrics plus ROC-AUC. Safe when only one class is present."""
    labels = np.asarray(labels).astype(int)
    scores = np.asarray(scores, dtype=float)
    preds = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(labels, preds, labels=[0, 1]).ravel()

    def div(a, b):
        return float(a) / b if b else float("nan")

    precision = div(tp, tp + fp)
    recall = div(tp, tp + fn)
    if np.isnan(precision) or np.isnan(recall) or precision + recall == 0:
        f1 = 0.0 if (tp + fn) else float("nan")
    else:
        f1 = 2 * precision * recall / (precision + recall)

    one_class = labels.min() == labels.max()
    return {
        "n": int(labels.size),
        "n_tunnel": int(labels.sum()),
        "threshold": float(threshold),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "accuracy": div(tp + tn, labels.size),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": div(fp, fp + tn),
        "roc_auc": float("nan") if one_class else float(roc_auc_score(labels, scores)),
        "recall_at_1pct_fpr": recall_at_fpr(labels, scores),
    }


def evaluate_run(run: dict) -> dict:
    """Metrics for one results JSON (already loaded into a dict)."""
    labels, scores = run["labels"], run["scores"]
    if run.get("threshold") is not None:
        thr, source = float(run["threshold"]), "validation"
    else:
        thr, source = threshold_at_fpr(labels, scores), "test_fallback"
    out = binary_metrics(labels, scores, thr)
    out["threshold_source"] = source
    out["train_time_s"] = run.get("train_time_s", float("nan"))
    out["latency_ms"] = run.get("latency_ms", float("nan"))
    return out


def per_tool_recall(labels, scores, tools, threshold: float) -> dict:
    """Detection rate per tunnelling tool (for E3 charts and error analysis)."""
    labels = np.asarray(labels)
    scores = np.asarray(scores, dtype=float)
    tools = np.asarray(tools)
    out = {}
    for tool in np.unique(tools[labels == 1]):
        m = (tools == tool) & (labels == 1)
        out[str(tool)] = float((scores[m] >= threshold).mean())
    return out


def select_model(summary_rows: list[dict], max_fpr: float = MAX_FPR,
                 max_latency_ms: float = MAX_LATENCY_MS) -> dict | None:
    """Apply the selection rule to rows of ONE experiment. Returns the winning row."""
    ok = [r for r in summary_rows
          if r["fpr"] <= max_fpr and r["latency_ms"] <= max_latency_ms
          and not np.isnan(r["f1"])]
    return max(ok, key=lambda r: r["f1"]) if ok else None
