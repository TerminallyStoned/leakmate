"""M2: DNS-BERT — a small BERT trained only on benign domain names.

A query is suspicious when the model finds its qname surprising (high
pseudo-perplexity). Training uses benign names only, so the model needs no
attack labels.

Contract interface (see the CONTRACTS card):
    train(train_df, cfg) -> model
    score(model, df)     -> np.ndarray   (higher = more suspicious)
    save(model, path) / load(path)

`train_df` follows the query-table schema; only rows with label == 0 are used.
Extra benign names (e.g. Tranco) can be passed via cfg["extra_benign"].
"""
from __future__ import annotations

import json
import math
import random
import string
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from tokenizers import Regex, Tokenizer, decoders, models, pre_tokenizers, processors, trainers
from transformers import BertConfig, BertForMaskedLM, DataCollatorForLanguageModeling, PreTrainedTokenizerFast

SPECIALS = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"]
# Characters that appear in qnames. Case is kept on purpose: DNS is
# case-insensitive, benign names are almost all lowercase, and several tunnel
# encodings (base64/base128) are mixed-case.
DNS_ALPHABET = list(string.ascii_lowercase + string.ascii_uppercase + string.digits + "-_.")

DEFAULT_CFG = {
    "tokenizer": "bpe",        # "bpe" (main) or "char" (ablation 1)
    "vocab_size": 8000,        # BPE only; card says 8k-16k
    "max_len": 64,             # tokens incl. [CLS]/[SEP]
    "num_layers": 4,
    "hidden": 256,
    "heads": 4,
    "intermediate": 1024,
    "mlm_probability": 0.15,
    "dedup": True,             # train on unique names (CIC benign repeats heavily)
    "epochs": 3,
    "max_steps": None,         # overrides epochs when set
    "batch_size": 256,
    "lr": 5e-4,
    "warmup_ratio": 0.05,
    "weight_decay": 0.01,
    "seed": 42,
    "ckpt_dir": None,          # e.g. /content/drive/MyDrive/leakmate/m2_ckpt (Colab)
    "ckpt_every": 1000,        # steps
    "score_batch_rows": 4096,  # masked copies per forward pass when scoring
    "device": None,            # auto
    "log_every": 100,
}


def _norm_qname(q: str) -> str:
    q = "" if q is None or (isinstance(q, float) and math.isnan(q)) else str(q)
    return q.strip().rstrip(".")


# --------------------------------------------------------------------------- tokenizers
def build_tokenizer(names: list[str], kind: str, vocab_size: int, max_len: int) -> PreTrainedTokenizerFast:
    """Train a BPE or character tokenizer on benign names only."""
    if kind == "bpe":
        tk = Tokenizer(models.BPE(unk_token="[UNK]"))
        # dots are kept as their own token; BPE learns pieces like "cdn", "api", "com"
        tk.pre_tokenizer = pre_tokenizers.Split(".", behavior="isolated")
        trainer = trainers.BpeTrainer(vocab_size=vocab_size, special_tokens=SPECIALS,
                                      initial_alphabet=DNS_ALPHABET, show_progress=False)
        tk.train_from_iterator(names, trainer=trainer)
        tk.decoder = decoders.BPEDecoder()
    elif kind == "char":
        chars = sorted(set("".join(names)))
        vocab = {t: i for i, t in enumerate(SPECIALS + [c for c in chars if c not in SPECIALS])}
        tk = Tokenizer(models.WordLevel(vocab=vocab, unk_token="[UNK]"))
        tk.pre_tokenizer = pre_tokenizers.Split(Regex("."), behavior="isolated")
    else:
        raise ValueError(f"unknown tokenizer kind: {kind}")
    tk.post_processor = processors.TemplateProcessing(
        single="[CLS] $A [SEP]", special_tokens=[("[CLS]", tk.token_to_id("[CLS]")), ("[SEP]", tk.token_to_id("[SEP]"))])
    tk.enable_truncation(max_length=max_len)
    return PreTrainedTokenizerFast(tokenizer_object=tk, unk_token="[UNK]", pad_token="[PAD]", cls_token="[CLS]",
                                   sep_token="[SEP]", mask_token="[MASK]", model_max_length=max_len)


# --------------------------------------------------------------------------- model wrapper
@dataclass
class M2Model:
    tokenizer: PreTrainedTokenizerFast
    model: BertForMaskedLM
    cfg: dict
    history: list = field(default_factory=list)

    @property
    def device(self):
        return next(self.model.parameters()).device


def _device(cfg) -> torch.device:
    if cfg.get("device"):
        return torch.device(cfg["device"])
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def _seed(s: int):
    random.seed(s); np.random.seed(s); torch.manual_seed(s)


def _benign_names(train_df: pd.DataFrame, cfg: dict) -> list[str]:
    df = train_df
    if "label" in df.columns:
        df = df[df["label"] == 0]
    names = [_norm_qname(q) for q in df["qname"].tolist()]
    names += [_norm_qname(q) for q in cfg.get("extra_benign") or []]
    names = [n for n in names if n]
    if cfg["dedup"]:
        names = list(dict.fromkeys(names))
    if not names:
        raise ValueError("no benign names to train on")
    return names


def train(train_df: pd.DataFrame, cfg: dict | None = None) -> M2Model:
    cfg = {**DEFAULT_CFG, **(cfg or {})}
    _seed(cfg["seed"])
    dev = _device(cfg)
    names = _benign_names(train_df, cfg)
    ckpt = Path(cfg["ckpt_dir"]) if cfg.get("ckpt_dir") else None

    # resume from a checkpoint if one exists (Colab disconnects)
    state = None
    if ckpt and (ckpt / "last" / "trainer_state.pt").exists():
        m = load(ckpt / "last", device=str(dev))
        tok, model = m.tokenizer, m.model
        state = torch.load(ckpt / "last" / "trainer_state.pt", map_location=dev, weights_only=False)
        print(f"[m2] resuming from {ckpt/'last'} at step {state['step']}")
    else:
        tok = build_tokenizer(names, cfg["tokenizer"], cfg["vocab_size"], cfg["max_len"])
        bcfg = BertConfig(vocab_size=len(tok), hidden_size=cfg["hidden"], num_hidden_layers=cfg["num_layers"],
                          num_attention_heads=cfg["heads"], intermediate_size=cfg["intermediate"],
                          max_position_embeddings=cfg["max_len"] + 2, pad_token_id=tok.pad_token_id,
                          type_vocab_size=1)
        model = BertForMaskedLM(bcfg).to(dev)

    enc = tok(names, truncation=True, max_length=cfg["max_len"])["input_ids"]
    collator = DataCollatorForLanguageModeling(tok, mlm_probability=cfg["mlm_probability"])
    loader = torch.utils.data.DataLoader([{"input_ids": e} for e in enc], batch_size=cfg["batch_size"],
                                         shuffle=True, collate_fn=collator, drop_last=False)
    total = cfg["max_steps"] or cfg["epochs"] * len(loader)
    warm = max(1, int(total * cfg["warmup_ratio"]))
    opt = torch.optim.AdamW(model.parameters(), lr=cfg["lr"], weight_decay=cfg["weight_decay"])
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt, lambda s: min((s + 1) / warm, max(0.0, (total - s) / max(1, total - warm))))
    use_amp = dev.type == "cuda"
    scaler = torch.amp.GradScaler("cuda", enabled=use_amp)
    step, history = 0, []
    if state:
        opt.load_state_dict(state["opt"]); sched.load_state_dict(state["sched"]); step = state["step"]
        history = state.get("history", [])

    m2 = M2Model(tok, model, {k: v for k, v in cfg.items() if k != "extra_benign"}, history)
    m2.cfg["n_train_names"] = len(names)
    model.train()
    t0, run_loss = time.time(), 0.0
    while step < total:
        for batch in loader:
            if step >= total:
                break
            batch = {k: v.to(dev) for k, v in batch.items()}
            with torch.autocast(dev.type, dtype=torch.float16, enabled=use_amp):
                loss = model(**batch).loss
            opt.zero_grad(set_to_none=True)
            scaler.scale(loss).backward()
            scaler.unscale_(opt)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(opt); scaler.update(); sched.step()
            step += 1
            run_loss += loss.item()
            if step % cfg["log_every"] == 0 or step == total:
                n = cfg["log_every"] if step % cfg["log_every"] == 0 else step % cfg["log_every"]
                history.append({"step": step, "loss": run_loss / n, "elapsed_s": time.time() - t0})
                print(f"[m2] step {step}/{total} loss {run_loss / n:.4f} ({time.time() - t0:.0f}s)")
                run_loss = 0.0
            if ckpt and (step % cfg["ckpt_every"] == 0 or step == total):
                save(m2, ckpt / "last")
                torch.save({"opt": opt.state_dict(), "sched": sched.state_dict(), "step": step, "history": history},
                           ckpt / "last" / "trainer_state.pt")
    model.eval()
    return m2


# --------------------------------------------------------------------------- scoring
@torch.inference_mode()
def _pseudo_nll(m2: M2Model, ids_list: list[list[int]], max_rows: int) -> tuple[np.ndarray, np.ndarray]:
    """Per query: (mean NLL in nats, total NLL in nats), masking one token at a time.

    All masked copies of a query go through the model in the same forward pass,
    and copies from many queries are packed together up to `max_rows` rows.
    Only the masked position is sent through the MLM head (saves V x T logits).
    """
    model, dev = m2.model, m2.device
    mask_id, pad_id = m2.tokenizer.mask_token_id, m2.tokenizer.pad_token_id
    out = np.zeros(len(ids_list), dtype=np.float64)
    tot = np.zeros(len(ids_list), dtype=np.float64)
    use_amp = dev.type == "cuda"

    def flush(group):
        rows = [(qi, ids, p) for qi, ids in group for p in range(1, len(ids) - 1)]
        if not rows:
            return
        T = max(len(ids) for _, ids, _ in rows)
        inp = torch.full((len(rows), T), pad_id, dtype=torch.long)
        att = torch.zeros((len(rows), T), dtype=torch.long)
        pos = torch.empty(len(rows), dtype=torch.long)
        tgt = torch.empty(len(rows), dtype=torch.long)
        for r, (_, ids, p) in enumerate(rows):
            inp[r, :len(ids)] = torch.tensor(ids)
            att[r, :len(ids)] = 1
            tgt[r] = ids[p]; pos[r] = p
            inp[r, p] = mask_id
        inp, att, pos, tgt = inp.to(dev), att.to(dev), pos.to(dev), tgt.to(dev)
        with torch.autocast(dev.type, dtype=torch.float16, enabled=use_amp):
            h = model.bert(input_ids=inp, attention_mask=att).last_hidden_state
            h = h[torch.arange(len(rows), device=dev), pos]
            logits = model.cls(h).float()
        nll = -torch.log_softmax(logits, -1).gather(1, tgt[:, None]).squeeze(1).cpu().numpy()
        owners = np.array([qi for qi, _, _ in rows])
        sums = np.bincount(owners, weights=nll, minlength=len(out))
        cnts = np.bincount(owners, minlength=len(out))
        hit = cnts > 0
        out[hit] = sums[hit] / cnts[hit]
        tot[hit] = sums[hit]

    group, n_rows = [], 0
    for qi, ids in enumerate(ids_list):
        k = max(0, len(ids) - 2)
        if group and n_rows + k > max_rows:
            flush(group); group, n_rows = [], 0
        group.append((qi, ids)); n_rows += k
    flush(group)
    return out, tot


def _score_both(m2: M2Model, df: pd.DataFrame, batch_rows: int | None):
    m2.model.eval()
    names = [_norm_qname(q) for q in df["qname"].tolist()]
    uniq, inv = np.unique(np.array(names, dtype=object), return_inverse=True)
    ids = m2.tokenizer(list(uniq), truncation=True, max_length=m2.cfg["max_len"])["input_ids"]
    mean_nll, tot_nll = _pseudo_nll(m2, ids, batch_rows or m2.cfg["score_batch_rows"])
    return mean_nll[inv], tot_nll[inv]


def score(m2: M2Model, df: pd.DataFrame, batch_rows: int | None = None) -> np.ndarray:
    """Pseudo-log-perplexity per query (mean masked-token NLL, nats). Higher = more suspicious.

    exp(score) is the pseudo-perplexity; the log form keeps scores finite.
    Unique qnames are scored once and broadcast back.
    """
    return _score_both(m2, df, batch_rows)[0].astype(np.float32)


def info_bits(m2: M2Model, df: pd.DataFrame, batch_rows: int | None = None) -> np.ndarray:
    """Estimated information per query in bits: I(q) = -sum_i log2 P(t_i | q without t_i).

    Proposal eq. (1). Unlike `score`, this grows with name length, so it is the
    quantity to accumulate per host / infrastructure group for leakage detection.
    """
    return (_score_both(m2, df, batch_rows)[1] / math.log(2)).astype(np.float32)


# --------------------------------------------------------------------------- persistence
def save(m2: M2Model, path) -> None:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    m2.model.save_pretrained(path)
    m2.tokenizer.save_pretrained(path)
    with open(path / "m2_config.json", "w") as f:
        json.dump({"cfg": m2.cfg, "history": m2.history}, f, indent=2, default=str)


def load(path, device: str | None = None) -> M2Model:
    path = Path(path)
    meta = json.loads((path / "m2_config.json").read_text())
    cfg = {**DEFAULT_CFG, **meta["cfg"]}
    dev = torch.device(device) if device else _device(cfg)
    tok = PreTrainedTokenizerFast.from_pretrained(path)
    model = BertForMaskedLM.from_pretrained(path).to(dev).eval()
    return M2Model(tok, model, cfg, meta.get("history", []))
