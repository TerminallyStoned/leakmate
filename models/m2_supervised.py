"""M2 ablation 2: supervised fine-tuning of the pre-trained DNS-BERT.

Same pre-trained model as M2 (cfg["init_from"], a saved M2 model, e.g. the Phase 1
checkpoint), same tokenizer, plus a 2-class head trained on labelled benign and tunnel
names. M2 itself scores pseudo-perplexity and never sees a tunnel; this variant does, so
it shows what labels buy on known tools (Experiment 1) and what they cost on an unseen
tool (Experiment 3).

Run it on the masked testbed table only (data/processed_nozone, docs/suffix-ablation.md):
on the original table every tunnel name ends in tunnel.test and a supervised model can
learn that suffix instead of the tunnel.

Score = logit margin (tunnel - benign): higher = more suspicious, finite, and unlike
P(tunnel) it does not saturate at 1.0, so the validation threshold has no ties to fall on.

Contract interface: train(train_df, cfg) -> model, score(model, df), save, load.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from transformers import BertForSequenceClassification, DataCollatorWithPadding, PreTrainedTokenizerFast

from models import m2_dnsbert
from models.m2_dnsbert import _norm_qname

DEFAULT_CFG = {
    "init_from": None,  # required: saved M2 model whose encoder and tokenizer are reused
    "epochs": 2,
    "max_steps": None,  # overrides epochs when set
    "batch_size": 256,
    "lr": 5e-5,
    "warmup_ratio": 0.05,
    "weight_decay": 0.01,
    "seed": 42,
    "score_batch_rows": 2048,
    "device": None,
    "log_every": 100,
}


@dataclass
class SupModel:
    tokenizer: PreTrainedTokenizerFast
    model: BertForSequenceClassification
    cfg: dict


def train(train_df: pd.DataFrame, cfg: dict | None = None) -> SupModel:
    cfg = {**DEFAULT_CFG, **(cfg or {})}
    if not cfg.get("init_from"):
        raise ValueError("ablation 2 needs cfg['init_from']: a saved M2 model to fine-tune")
    m2_dnsbert._seed(cfg["seed"])
    dev = m2_dnsbert._device(cfg)
    base = m2_dnsbert.load(cfg["init_from"], device="cpu")
    tok, max_len = base.tokenizer, base.cfg["max_len"]
    model = BertForSequenceClassification.from_pretrained(cfg["init_from"], num_labels=2).to(dev)
    for k in ["tokenizer", "vocab_size", "max_len", "num_layers", "hidden", "heads"]:
        cfg[k] = base.cfg[k]

    pairs = pd.DataFrame({"q": [_norm_qname(q) for q in train_df["qname"]], "y": train_df["label"].astype(int)})
    pairs = pairs[pairs["q"] != ""].drop_duplicates()
    counts = np.bincount(pairs["y"], minlength=2)
    if counts.min() == 0:
        raise ValueError(f"supervised training needs both classes, got benign={counts[0]} tunnel={counts[1]}")
    weight = torch.tensor(len(pairs) / (2.0 * counts), dtype=torch.float32, device=dev)
    enc = tok(pairs["q"].tolist(), truncation=True, max_length=max_len)["input_ids"]
    items = [{"input_ids": e, "labels": int(y)} for e, y in zip(enc, pairs["y"])]
    loader = torch.utils.data.DataLoader(
        items, batch_size=cfg["batch_size"], shuffle=True, collate_fn=DataCollatorWithPadding(tok)
    )
    total = cfg["max_steps"] or cfg["epochs"] * len(loader)
    warm = max(1, int(total * cfg["warmup_ratio"]))
    opt = torch.optim.AdamW(model.parameters(), lr=cfg["lr"], weight_decay=cfg["weight_decay"])
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt, lambda s: min((s + 1) / warm, max(0.0, (total - s) / max(1, total - warm)))
    )
    use_amp = dev.type == "cuda"
    scaler = torch.amp.GradScaler("cuda", enabled=use_amp)
    loss_fn = torch.nn.CrossEntropyLoss(weight=weight)
    model.train()
    step, t0 = 0, time.time()
    while step < total:
        for batch in loader:
            if step >= total:
                break
            batch = {k: v.to(dev) for k, v in batch.items()}
            y = batch.pop("labels")
            with torch.autocast(dev.type, dtype=torch.float16, enabled=use_amp):
                loss = loss_fn(model(**batch).logits.float(), y)
            opt.zero_grad(set_to_none=True)
            scaler.scale(loss).backward()
            scaler.unscale_(opt)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(opt)
            scaler.update()
            sched.step()
            step += 1
            if step % cfg["log_every"] == 0 or step == total:
                print(f"[m2sup] step {step}/{total} loss {loss.item():.4f} ({time.time() - t0:.0f}s)")
    model.eval()
    cfg["n_train_pairs"] = int(len(pairs))
    cfg["n_train_tunnel_pairs"] = int(counts[1])
    return SupModel(tok, model, cfg)


@torch.inference_mode()
def score(m: SupModel, df: pd.DataFrame) -> np.ndarray:
    """Logit margin (tunnel - benign) per query. Higher = more suspicious. Reads only qname."""
    m.model.eval()
    names = [_norm_qname(q) for q in df["qname"].tolist()]
    uniq, inv = np.unique(np.array(names, dtype=object), return_inverse=True)
    dev = next(m.model.parameters()).device
    collate = DataCollatorWithPadding(m.tokenizer)
    out = np.empty(len(uniq), dtype=np.float32)
    step = m.cfg.get("score_batch_rows", DEFAULT_CFG["score_batch_rows"])
    for i in range(0, len(uniq), step):
        ids = m.tokenizer(list(uniq[i : i + step]), truncation=True, max_length=m.cfg["max_len"])["input_ids"]
        batch = {k: v.to(dev) for k, v in collate([{"input_ids": e} for e in ids]).items()}
        logits = m.model(**batch).logits.float()
        out[i : i + step] = (logits[:, 1] - logits[:, 0]).cpu().numpy()
    return out[inv]


def save(m: SupModel, path) -> None:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    m.model.save_pretrained(path)
    m.tokenizer.save_pretrained(path)
    (path / "m2sup_config.json").write_text(json.dumps({"cfg": m.cfg}, indent=2, default=str))


def load(path, device: str | None = None) -> SupModel:
    path = Path(path)
    cfg = {**DEFAULT_CFG, **json.loads((path / "m2sup_config.json").read_text())["cfg"]}
    dev = torch.device(device) if device else m2_dnsbert._device(cfg)
    tok = PreTrainedTokenizerFast.from_pretrained(path)
    model = BertForSequenceClassification.from_pretrained(path).to(dev).eval()
    return SupModel(tok, model, cfg)
