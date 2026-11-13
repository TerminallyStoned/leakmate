"""Shared code for M3 (character-level models): encoding, training loop, save/load.

m3_cnn.py and m3_bilstm.py only define the network; everything else lives here so
both variants are trained and scored in exactly the same way.
"""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch import nn

from eval.metrics import threshold_at_fpr

# ---- character vocabulary (~40 symbols) ------------------------------------------
# DNS names are case-insensitive, so we lower-case. 0 = padding, 1 = unknown.
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-_."
PAD, UNK = 0, 1
CHAR_TO_ID = {c: i + 2 for i, c in enumerate(ALPHABET)}
VOCAB_SIZE = len(ALPHABET) + 2  # 41

DEFAULTS = {
    "max_len": 256,       # a full DNS name is at most 253 characters
    "epochs": 5,
    "batch_size": 512,
    "lr": 1e-3,
    "weight_decay": 1e-4,
    "val_frac": 0.1,      # last 10% of training sessions (by time) for early stopping + threshold
    "patience": 2,
    "target_fpr": 0.01,   # threshold chosen on validation benign traffic
    "seed": 0,
}


def encode(qnames, max_len: int) -> np.ndarray:
    """Map each query name to a fixed-length array of character ids.
    Long names keep their LAST max_len characters (the registered domain is at the end)."""
    out = np.zeros((len(qnames), max_len), dtype=np.int64)
    for row, name in enumerate(qnames):
        name = str(name).lower().rstrip(".")[-max_len:]
        ids = [CHAR_TO_ID.get(c, UNK) for c in name]
        out[row, :len(ids)] = ids
    return out


def device() -> torch.device:
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


@dataclass
class M3Model:
    """What train() returns: the network plus everything needed to score again."""
    net: nn.Module
    arch: str
    cfg: dict
    threshold: float | None = None
    history: list = field(default_factory=list)


def _val_split(df: pd.DataFrame, frac: float):
    """Hold out the latest sessions of the TRAINING data (never the test data)."""
    starts = df.groupby("session_id")["ts"].min().sort_values()
    cut = int(len(starts) * (1 - frac))
    val_ids = set(starts.index[cut:])
    is_val = df["session_id"].isin(val_ids)
    tr, va = df[~is_val], df[is_val]
    if va["label"].nunique() < 2 or tr["label"].nunique() < 2:
        # Too few sessions per class: fall back to the last rows by time.
        df = df.sort_values("ts")
        cut = int(len(df) * (1 - frac))
        tr, va = df.iloc[:cut], df.iloc[cut:]
    return tr, va


def _batches(x: np.ndarray, y: np.ndarray | None, bs: int, shuffle: bool, rng=None):
    idx = np.arange(len(x))
    if shuffle:
        rng.shuffle(idx)
    for i in range(0, len(idx), bs):
        j = idx[i:i + bs]
        yield (torch.from_numpy(x[j]),
               None if y is None else torch.from_numpy(y[j]).float())


@torch.no_grad()
def _predict(net: nn.Module, x: np.ndarray, bs: int = 2048) -> np.ndarray:
    net.eval()
    dev = next(net.parameters()).device
    out = [torch.sigmoid(net(xb.to(dev))).cpu().numpy()
           for xb, _ in _batches(x, None, bs, shuffle=False)]
    return np.concatenate(out) if out else np.zeros(0)


def train_model(build_net, arch: str, train_df: pd.DataFrame, cfg: dict) -> M3Model:
    """Supervised training with class weighting, early stopping on validation loss,
    and a decision threshold set on validation benign traffic."""
    cfg = {**DEFAULTS, **(cfg or {})}
    torch.manual_seed(cfg["seed"])
    rng = np.random.default_rng(cfg["seed"])
    dev = device()

    tr, va = _val_split(train_df, cfg["val_frac"])
    xtr, ytr = encode(tr["qname"].tolist(), cfg["max_len"]), tr["label"].to_numpy()
    xva, yva = encode(va["qname"].tolist(), cfg["max_len"]), va["label"].to_numpy()

    net = build_net(cfg).to(dev)
    cfg["n_params"] = sum(p.numel() for p in net.parameters())
    # Tunnels and benign are imbalanced; weight positives so both count equally.
    pos_weight = torch.tensor([(ytr == 0).sum() / max(1, (ytr == 1).sum())], device=dev)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    opt = torch.optim.AdamW(net.parameters(), lr=cfg["lr"], weight_decay=cfg["weight_decay"])

    best_loss, best_state, bad, history = float("inf"), None, 0, []
    for epoch in range(cfg["epochs"]):
        net.train()
        t0, total = time.perf_counter(), 0.0
        for xb, yb in _batches(xtr, ytr, cfg["batch_size"], shuffle=True, rng=rng):
            xb, yb = xb.to(dev), yb.to(dev)
            opt.zero_grad()
            loss = loss_fn(net(xb), yb)
            loss.backward()
            nn.utils.clip_grad_norm_(net.parameters(), 1.0)
            opt.step()
            total += loss.item() * len(xb)

        val_loss = _val_loss(net, xva, yva, loss_fn)
        history.append({"epoch": epoch + 1, "train_loss": total / len(xtr),
                        "val_loss": val_loss, "secs": time.perf_counter() - t0})
        print(f"  [{arch}] epoch {epoch + 1}: train {total / len(xtr):.4f} "
              f"val {val_loss:.4f} ({history[-1]['secs']:.0f}s)")
        if val_loss < best_loss - 1e-4:
            best_loss, best_state, bad = val_loss, copy.deepcopy(net.state_dict()), 0
        else:
            bad += 1
            if bad >= cfg["patience"]:
                break
    if best_state is not None:
        net.load_state_dict(best_state)

    threshold = threshold_at_fpr(yva, _predict(net, xva), cfg["target_fpr"])
    return M3Model(net=net, arch=arch, cfg=cfg, threshold=threshold, history=history)


@torch.no_grad()
def _val_loss(net, x, y, loss_fn, bs: int = 2048) -> float:
    net.eval()
    dev = next(net.parameters()).device
    total = 0.0
    for xb, yb in _batches(x, y, bs, shuffle=False):
        total += loss_fn(net(xb.to(dev)), yb.to(dev)).item() * len(xb)
    return total / max(1, len(x))


def score_model(model: M3Model, df: pd.DataFrame) -> np.ndarray:
    """Probability that each query is a tunnel (higher = more suspicious)."""
    return _predict(model.net, encode(df["qname"].tolist(), model.cfg["max_len"]))


def save_model(model: M3Model, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save({"state_dict": model.net.state_dict(), "arch": model.arch,
                "cfg": model.cfg, "threshold": model.threshold,
                "history": model.history}, path)


def load_model(build_net, path: str | Path) -> M3Model:
    ckpt = torch.load(path, map_location=device(), weights_only=False)
    net = build_net(ckpt["cfg"]).to(device())
    net.load_state_dict(ckpt["state_dict"])
    net.eval()
    return M3Model(net=net, arch=ckpt["arch"], cfg=ckpt["cfg"],
                   threshold=ckpt["threshold"], history=ckpt["history"])
