"""M3: character-level CNN over the raw query name (supervised).

Character embedding -> parallel Conv1D blocks (kernel 3/5/7) -> global max-pool
-> dense -> one logit. About 0.2M parameters with the defaults (limit: 1M).
"""
from __future__ import annotations

import torch
from torch import nn

from models.m3_common import (PAD, VOCAB_SIZE, M3Model, load_model, save_model,
                              score_model, train_model)

ARCH_DEFAULTS = {"emb_dim": 32, "filters": 128, "kernels": [3, 5, 7],
                 "hidden": 128, "dropout": 0.3}


class CharCNN(nn.Module):
    def __init__(self, cfg: dict):
        super().__init__()
        c = {**ARCH_DEFAULTS, **cfg}
        self.emb = nn.Embedding(VOCAB_SIZE, c["emb_dim"], padding_idx=PAD)
        self.convs = nn.ModuleList([
            nn.Sequential(
                nn.Conv1d(c["emb_dim"], c["filters"], k, padding=k // 2),
                nn.BatchNorm1d(c["filters"]),
                nn.ReLU(),
                nn.Conv1d(c["filters"], c["filters"], k, padding=k // 2),
                nn.ReLU(),
            )
            for k in c["kernels"]
        ])
        self.head = nn.Sequential(
            nn.Dropout(c["dropout"]),
            nn.Linear(c["filters"] * len(c["kernels"]), c["hidden"]),
            nn.ReLU(),
            nn.Dropout(c["dropout"]),
            nn.Linear(c["hidden"], 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        mask = (x != PAD).unsqueeze(1)                 # (B, 1, L)
        h = self.emb(x).transpose(1, 2)                # (B, E, L)
        pooled = []
        for conv in self.convs:
            z = conv(h).masked_fill(~mask, float("-inf"))  # ignore padding in the max-pool
            pooled.append(z.max(dim=2).values)
        out = torch.cat(pooled, dim=1)
        out = torch.nan_to_num(out, neginf=0.0)        # empty names
        return self.head(out).squeeze(1)


def _build(cfg: dict) -> nn.Module:
    return CharCNN(cfg)


def train(train_df, cfg=None) -> M3Model:
    return train_model(_build, "cnn", train_df, {**ARCH_DEFAULTS, **(cfg or {})})


def score(model: M3Model, df):
    return score_model(model, df)


def save(model: M3Model, path):
    save_model(model, path)


def load(path) -> M3Model:
    return load_model(_build, path)
