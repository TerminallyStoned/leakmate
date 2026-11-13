"""ROC curves and confusion matrices, saved as PNG under results/figures/."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # no display needed (Colab, servers)
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import roc_curve


def plot_roc(runs: dict[str, dict], experiment: str, out_dir: Path) -> Path | None:
    """Overlay ROC curves of every model for one experiment. `runs`: model -> run."""
    fig, ax = plt.subplots(figsize=(5, 4.5), dpi=150)
    drawn = 0
    for model, run in sorted(runs.items()):
        labels = np.asarray(run["labels"])
        if labels.min() == labels.max():
            continue  # ROC undefined with one class
        fpr, tpr, _ = roc_curve(labels, run["scores"])
        ax.plot(fpr, tpr, lw=1.5, label=model)
        drawn += 1
    if not drawn:
        plt.close(fig)
        return None
    ax.plot([0, 1], [0, 1], ls="--", lw=0.8, color="grey")
    ax.axvline(0.01, ls=":", lw=0.8, color="red", label="1% FPR")
    ax.set_xscale("symlog", linthresh=0.01)  # makes the low-FPR region readable
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.01)
    ax.set_xlabel("False-positive rate (symlog)")
    ax.set_ylabel("True-positive rate")
    ax.set_title(f"ROC: {experiment}")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    out = out_dir / f"roc_{experiment}.png"
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_latency(latency, out_dir: Path, limit_ms: float = 10.0) -> Path | None:
    """Horizontal bar chart of median per-query latency per model, with the limit marked.
    `latency` is the DataFrame written to results/latency.csv."""
    if latency.empty:
        return None
    df = latency.sort_values("latency_ms_median")
    fig, ax = plt.subplots(figsize=(6, 0.45 * len(df) + 1.2), dpi=150)
    colors = ["#2e7d32" if ok else "#c62828" for ok in df["under_limit"]]
    ax.barh(df["model"], df["latency_ms_median"], color=colors)
    for y, v in enumerate(df["latency_ms_median"]):
        ax.text(v * 1.08, y, f"{v:.2f} ms", va="center", fontsize=8)
    ax.axvline(limit_ms, ls="--", lw=1, color="black", label=f"{limit_ms:g} ms limit")
    ax.set_xscale("log")
    ax.set_xlim(right=max(limit_ms, df["latency_ms_median"].max()) * 4)
    ax.set_xlabel("Per-query latency, median over experiments (ms, log scale)")
    ax.set_title("Per-query latency by model")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    out = out_dir / "latency.png"
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_confusion(m: dict, model: str, experiment: str, out_dir: Path) -> Path:
    """2x2 confusion matrix from a metrics row (tp/fp/tn/fn)."""
    cm = np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]])
    fig, ax = plt.subplots(figsize=(3.6, 3.2), dpi=150)
    ax.imshow(cm, cmap="Blues")
    for (i, j), v in np.ndenumerate(cm):
        ax.text(j, i, f"{v:,}", ha="center", va="center",
                color="white" if v > cm.max() / 2 else "black")
    ax.set_xticks([0, 1], ["benign", "tunnel"])
    ax.set_yticks([0, 1], ["benign", "tunnel"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(f"{model} · {experiment}", fontsize=9)
    fig.tight_layout()
    out = out_dir / f"cm_{model}_{experiment}.png"
    fig.savefig(out)
    plt.close(fig)
    return out
