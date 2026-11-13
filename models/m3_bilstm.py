"""M3 variant: character-level BiLSTM over the raw query name (supervised).

Character embedding -> 1-2 bidirectional LSTM layers (128 units) -> masked
mean + max pooling -> dense -> one logit. Same training/scoring code as the CNN.
"""
from __future__ import annotations

import torch
from torch import nn
from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence

from models.m3_common import (PAD, VOCAB_SIZE, M3Model, load_model, save_model,
                              score_model, train_model)

ARCH_DEFAULTS = {"emb_dim": 32, "lstm_units": 128, "lstm_layers": 1,
                 "hidden": 128, "dropout": 0.3}


class CharBiLSTM(nn.Module):
    def __init__(self, cfg: dict):
        super().__init__()
        c = {**ARCH_DEFAULTS, **cfg}
        self.emb = nn.Embedding(VOCAB_SIZE, c["emb_dim"], padding_idx=PAD)
        self.lstm = nn.LSTM(c["emb_dim"], c["lstm_units"], num_layers=c["lstm_layers"],
                            batch_first=True, bidirectional=True,
                            dropout=c["dropout"] if c["lstm_layers"] > 1 else 0.0)
        self.head = nn.Sequential(
            nn.Dropout(c["dropout"]),
            nn.Linear(4 * c["lstm_units"], c["hidden"]),  # mean + max of 2 directions
            nn.ReLU(),
            nn.Dropout(c["dropout"]),
            nn.Linear(c["hidden"], 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        lengths = (x != PAD).sum(1).clamp(min=1)
        packed = pack_padded_sequence(self.emb(x), lengths.cpu(), batch_first=True,
                                      enforce_sorted=False)
        out, _ = self.lstm(packed)
        out, _ = pad_packed_sequence(out, batch_first=True)    # (B, L', 2H)
        mask = (torch.arange(out.size(1), device=x.device)[None, :]
                < lengths[:, None]).unsqueeze(2)
        mean = (out * mask).sum(1) / lengths[:, None]
        mx = out.masked_fill(~mask, float("-inf")).max(1).values
        return self.head(torch.cat([mean, mx], dim=1)).squeeze(1)


def _build(cfg: dict) -> nn.Module:
    return CharBiLSTM(cfg)


def train(train_df, cfg=None) -> M3Model:
    return train_model(_build, "bilstm", train_df, {**ARCH_DEFAULTS, **(cfg or {})})


def score(model: M3Model, df):
    return score_model(model, df)


def save(model: M3Model, path):
    save_model(model, path)


def load(path) -> M3Model:
    return load_model(_build, path)
