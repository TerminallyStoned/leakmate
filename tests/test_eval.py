"""Run with:  python -m pytest -q"""
import math

import numpy as np
import pytest

from eval.metrics import (binary_metrics, evaluate_run, per_tool_recall,
                          select_model, threshold_at_fpr)


def test_perfect_model():
    m = binary_metrics([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9], threshold=0.5)
    assert m["precision"] == m["recall"] == m["f1"] == m["accuracy"] == 1.0
    assert m["fpr"] == 0.0 and m["roc_auc"] == 1.0


def test_confusion_counts():
    m = binary_metrics([0, 0, 1, 1], [0.9, 0.1, 0.8, 0.2], threshold=0.5)
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (1, 1, 1, 1)
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["fpr"] == 0.5


def test_one_class_does_not_crash():
    m = binary_metrics([0, 0, 0], [0.1, 0.2, 0.9], threshold=0.5)
    assert math.isnan(m["roc_auc"]) and m["fpr"] == pytest.approx(1 / 3)


def test_threshold_respects_fpr():
    rng = np.random.default_rng(0)
    labels = np.r_[np.zeros(10_000), np.ones(1000)]
    scores = np.r_[rng.normal(0, 1, 10_000), rng.normal(3, 1, 1000)]
    thr = threshold_at_fpr(labels, scores, 0.01)
    assert binary_metrics(labels, scores, thr)["fpr"] <= 0.01


def test_validation_threshold_is_used():
    run = {"scores": [0.1, 0.9], "labels": [0, 1], "threshold": 0.95,
           "train_time_s": 1, "latency_ms": 1, "config": {}}
    m = evaluate_run(run)
    assert m["threshold_source"] == "validation" and m["recall"] == 0.0


def test_per_tool_recall():
    r = per_tool_recall([1, 1, 1, 0], [0.9, 0.2, 0.8, 0.1],
                        ["iodine", "iodine", "dnscat2", "benign"], 0.5)
    assert r == {"dnscat2": 1.0, "iodine": 0.5}


def test_selection_rule():
    rows = [
        {"model": "fast_good", "f1": 0.95, "fpr": 0.005, "latency_ms": 1.0},
        {"model": "too_slow", "f1": 0.99, "fpr": 0.001, "latency_ms": 20.0},
        {"model": "too_noisy", "f1": 0.98, "fpr": 0.05, "latency_ms": 1.0},
    ]
    assert select_model(rows)["model"] == "fast_good"
    assert select_model(rows[1:]) is None


def test_latency_table():
    import pandas as pd
    from eval.summarise import latency_table
    summary = pd.DataFrame({
        "model": ["fast", "fast", "slow"],
        "latency_ms": [1.0, 3.0, 14.0],
        "train_time_s": [10, 20, 30],
    })
    t = latency_table(summary).set_index("model")
    assert t.loc["fast", "latency_ms_median"] == 2.0 and t.loc["fast", "n_runs"] == 2
    assert bool(t.loc["fast", "under_limit"]) and not bool(t.loc["slow", "under_limit"])
