# Testbed suffix ablation: are the testbed scores real once the lab zone is hidden?

**Question.** Every testbed tunnel name ends in its tool's zone under `tunnel.test` (all 113,837 tunnel rows),
and no benign name does (0 of 111,724). The lab is built that way on purpose, for containment
(`testbed/attacker-ns/named.conf`). So any model reading the whole name can label a query from
its last labels alone. This ablation retrains on names with that zone hidden and checks how much of each
testbed score survives.

**Setup.** `python -m parser.mask` writes `data/processed_nozone/testbed/queries.parquet`. In it, every
registered domain is replaced by the same placeholder, `masked.domain`. The whole lab zone counts as the
registered domain (`d.tunnel.test`, `i.tunnel.test`, `exfil.tunnel.test`, `dns2tcp.tunnel.test`). Dropping
only the last two labels would leave the tool label (`d`, `i`, `exfil`, `dns2tcp`) behind as a new giveaway.
Example: `aGVsbG8.d.tunnel.test` -> `aGVsbG8.masked.domain`, `www.cloudflare.com` -> `www.masked.domain`.

The rows, splits, labels and test sets are the same as in the original table; only the names change. Each
model is trained twice with the same code, once per table.

```bash
python -m parser.mask
for r in processed processed_nozone; do for m in m1 m3; do for e in E1 E3; do
  python -m eval.run --model $m --exp $e --data-root data/$r --results-dir nz/$r --overwrite
done; done; done
python -m eval.summarise --results-dir nz/processed_nozone --no-plots   # likewise for nz/processed
```

These are ablation runs, not entries in the main results selection.

## Results (17-18 Nov, full testbed table)

### M3 (char-CNN / char-BiLSTM, Colab T4)
On the **original** table, every run below scores 1.0 on every metric with 0 false positives (as in
`docs/m3.md`). **Masked** table, CNN / BiLSTM:

| Run | ROC-AUC | Recall | Recall at 1% FPR | Missed tunnels | False positives (of 33,519 benign) |
|---|---|---|---|---|---|
| Experiment 1 (within-testbed) | 1.000 / 1.000 | 0.998 / 1.000 | 1.000 / 1.000 | 62 / 13 of 34,180 | 2 / 6 |
| Experiment 3 (leave-one-tool-out), dns2tcp held out | 0.848 / 0.930 | **0.000 / 0.000** | 0.018 / 0.113 | 7,764 / 7,763 of 7,764 | 0 / 3 |
| Experiment 3, dnscat2 held out | 0.995 / 0.999 | 0.323 / 0.913 | 0.923 / 0.973 | 4,184 / 537 of 6,182 | 5 / 12 |
| Experiment 3, dnsexfiltrator held out | 1.000 / 0.999 | 0.485 / 0.945 | 1.000 / 0.976 | 4,840 / 518 of 9,402 | 1 / 7 |
| Experiment 3, iodine held out | 0.887 / 0.988 | 0.748 / 0.750 | 0.752 / 0.802 | 2,733 / 2,711 of 10,832 | 2 / 3 |
| Experiment 5 (low-and-slow) | 1.000 / 1.000 | 0.989 / 1.000 | 1.000 / 1.000 | 5 / 0 of 457 | 3 / 11 |

Experiment 5 was run on 18 Nov with the same masked table (team notebook, cell 8):
`python -m eval.run --model m3 --exp E5 --data-root data/processed_nozone --results-dir nz/processed_nozone`.
Its test set is the 457 slow tunnel queries (iodine 271, dnscat2 118, DNSExfiltrator 68) and 33,519 benign.
The CNN's 5 misses are all dnscat2 (113 of 118 caught), names such as
`9d0601fe0b8009866b24d4001795a787c3.masked.domain`.

### M1 (XGBoost, per-query + per-host features, local CPU)
Recall and ROC-AUC are 1.0 in every run, on both tables. False positives out of 33,519 benign, original / masked:

| Run | Original | Masked |
|---|---|---|
| Experiment 1 (within-testbed) | 200 | 324 |
| Experiment 3, dns2tcp held out | 208 | 247 |
| Experiment 3, dnscat2 held out | 241 | 94 |
| Experiment 3, dnsexfiltrator held out | 215 | 254 |
| Experiment 3, iodine held out | 311 | 5 |

### M2 (DNS-BERT + Isolation Forest, Colab T4)
Run on 18 Nov from the team notebook ("Yehan: testbed suffix check", cells 5-7). The masked runs use the same
settings as Phase 2: the Phase 1 model, continued pre-training on masked testbed benign (10 epochs, learning rate
1e-4), and one model per tokenizer. The original numbers are the Phase 2 results in `results/` (`docs/m2.md`).

M2 trains on benign names only, so Experiment 3 reuses the Experiment 1 model and scores each tool on its own.
The four Experiment 3 rows therefore add up to Experiment 1 (masked BPE: 1,002 + 20 + 0 + 2,748 = 3,770 missed).

Recall, original -> masked. False positives are out of 33,519 benign.

| Run | BPE | Character (ablation 1) | BPE + host averaging | Character + host averaging |
|---|---|---|---|---|
| Experiment 1 (within-testbed) | 0.812 -> 0.890 | 0.937 -> **0.737** | 1.000 -> 1.000 | 1.000 -> 1.000 |
| Experiment 1 false positives | 72 -> 278 | 64 -> 277 | 168 -> 65 | 10 -> 45 |
| Experiment 1 ROC-AUC | 0.9959 -> 0.9780 | 0.9991 -> 0.9762 | 1.0000 -> 1.0000 | 1.0000 -> 1.0000 |
| Experiment 3, dns2tcp held out | 0.998 -> 0.871 | 1.000 -> **0.223** | 1.000 -> 1.000 | 1.000 -> 1.000 |
| Experiment 3, dnscat2 held out | 0.404 -> 0.997 | 0.655 -> 0.965 | 1.000 -> 1.000 | 1.000 -> 1.000 |
| Experiment 3, dnsexfiltrator held out | 1.000 -> 1.000 | 1.000 -> 1.000 | 1.000 -> 1.000 | 1.000 -> 1.000 |
| Experiment 3, iodine held out | 0.748 -> 0.746 | 1.000 -> **0.746** | 1.000 -> 1.000 | 1.000 -> 1.000 |

Per-query FPR goes from 0.19-0.21% to 0.83% for both tokenizers; with host averaging it is 0.19% (BPE) and
0.13% (character). Recall at 1% FPR equals recall in every M2 row. Both tokenizers miss exactly the same 2,748
iodine queries on the masked table.

Experiment 5 (low-and-slow, 457 slow tunnel queries), original -> masked: BPE 0.425 -> 0.573, character
0.891 -> 0.567, both with host averaging 1.000 -> 1.000, Isolation Forest 1.000 -> 1.000 (`docs/m2.md`).

The Isolation Forest does not change: recall 1.0 and ROC-AUC at least 0.9998 in every run; false positives
306 -> 293 per query, and 0 -> 0 with host averaging.

## What it shows
- **The suffix explains M3's perfect Experiment 3 results.** With the zone hidden, recall on the held-out tool
  falls from 1.0 to between 0.000 and 0.945, depending on the tool and model.
- **M3's Experiment 1 result is real.** When a tool is in training, its encoded subdomains alone are enough
  (recall at least 0.998, at most 6 false positives).
- **M3's Experiment 5 result is mostly real too.** All three slow tools are also in the Experiment 5 training
  set at normal speed, so this shows that throttling does not hide a known tool from a name-only model. It
  does not show that M3 would catch a slow tool it has never seen.
- **For dnscat2 and DNSExfiltrator, M3 still ranks well; its threshold is what fails.** ROC-AUC stays at 0.995
  or above while recall at the validation threshold drops. The threshold is picked on
  validation rows from the training tools, so it is too strict for a tool the model has not seen. Recall at 1%
  FPR shows what a better-placed threshold could recover. Experiment 4 shows the same gap (`docs/m3.md`).
- **The BiLSTM generalises better than the CNN** on every held-out tool.
- **dns2tcp is hard for a name-only model either way.** Its names are short (median 30 characters), so once
  the zone is gone there is little left to read. Experiment 4 CIC -> testbed misses it for the same reason.
- **M1 doesn't rely on the suffix.** Its features are lengths, entropy and per-host counts, so the ranking does
  not change. The false-positive shifts come from threshold placement. One caveat: on the masked table, M1's
  per-host `h_parent_uniq` counts distinct names per host, because every name now has the same parent.
- **M2's main model (BPE) doesn't rely on the suffix.** It never sees a tunnel in training, so it cannot learn
  that `tunnel.test` means a tunnel. Masked, its overall recall rises (0.812 -> 0.890, dnscat2 0.404 -> 0.997);
  only dns2tcp drops (0.998 -> 0.871). The cost is false positives: 0.21% -> 0.83% FPR, still under 1%.
- **M2's character model (ablation 1) did lean on the suffix.** Masked, dns2tcp falls from 1.000 to 0.223 and
  iodine from 1.000 to 0.746, so its lead over BPE on the original table (`docs/m2.md`) does not hold.
- **M2 with per-host averaging is unaffected:** recall 1.0 on every tool, 0.13-0.19% FPR.
- **The Isolation Forest is unaffected.** Like M1, it reads name statistics, not the suffix itself.

## For the report
- RQ2 (unseen tools): quote M3's **masked** Experiment 3 numbers, not the original ones. The original
  Experiment 3 measures whether the model can read `tunnel.test`.
- Experiment 5 (low-and-slow): quote M3's masked numbers too; the original result carries the suffix.
- M1's testbed numbers stand as reported.
- M2: quote the **masked** numbers for the character model (ablation 1) and drop the claim that it beats BPE on
  the testbed. M2 BPE, M2 with host averaging and the Isolation Forest stand as reported; the masked numbers can
  sit beside them.
- Experiment 4 (cross-dataset) remains the strongest test of generalisation for every model.

## Limits
- M2's Experiment 5 (masked and original) is derived from its Experiment 1 results (`scripts/m2_e5.py`, same model
  and threshold, since M2 trains on benign only); numbers in `docs/m2.md`.
- One seed per run. GPU training is not bit-for-bit repeatable (`docs/m3.md`).
- M2's masked result JSONs (Experiments 1, 3 and 5, with the Isolation Forest) are in `results_nozone/`. M3's come
  from Colab runs (`nz.zip` for Experiments 1 and 3; `nz_e5.zip` for Experiment 5, in `m3/` of the "leakmate captures"
  Drive folder); M1 reruns in minutes with the commands above.
