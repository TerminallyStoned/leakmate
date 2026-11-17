# Testbed suffix ablation: are the testbed scores real once the lab zone is hidden?

**Question.** Every testbed tunnel name ends in its tool's zone under `tunnel.test` (all 113,837 tunnel rows),
and no benign name does (0 of 111,724). The lab is built that way on purpose, for containment
(`testbed/attacker-ns/named.conf`). The catch is that any model reading the whole name can label a query from
its last labels alone. This ablation retrains on names with that zone hidden and checks how much of each
testbed score survives.

**Setup.** `python -m parser.mask` writes `data/processed_nozone/testbed/queries.parquet`. In it, every
registered domain is replaced by the same placeholder, `masked.domain`. The whole lab zone counts as the
registered domain (`d.tunnel.test`, `i.tunnel.test`, `exfil.tunnel.test`, `dns2tcp.tunnel.test`). Dropping
only the last two labels would leave the tool label (`d`, `i`, `exfil`, `dns2tcp`) behind as a new giveaway.
Example: `aGVsbG8.d.tunnel.test` -> `aGVsbG8.masked.domain`, `www.cloudflare.com` -> `www.masked.domain`.

The rows, splits, labels and test sets are the same as in the original table; only the names change. Each
model is trained twice with the same code (main at `7d8e97e`): once on the original table, once on the masked
one.

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

### M1 (XGBoost, per-query + per-host features, local CPU)
Recall and ROC-AUC are 1.0 in every run, on both tables. False positives out of 33,519 benign, original / masked:

| Run | Original | Masked |
|---|---|---|
| Experiment 1 (within-testbed) | 200 | 324 |
| Experiment 3, dns2tcp held out | 208 | 247 |
| Experiment 3, dnscat2 held out | 241 | 94 |
| Experiment 3, dnsexfiltrator held out | 215 | 254 |
| Experiment 3, iodine held out | 311 | 5 |

## What it shows
- **The suffix explains M3's perfect Experiment 3 results.** With the zone hidden, M3 misses a held-out
  dns2tcp entirely and catches only about 75% of a held-out iodine. The CNN catches about a third of dnscat2
  and half of DNSExfiltrator. The suffix explanation in `docs/m3.md` is now measured, not just likely.
- **M3's Experiment 1 result is real.** When a tool is in training, its encoded subdomains alone are enough
  (recall at least 0.998, at most 6 false positives).
- **M3's scores still rank well; its threshold is what fails on a new tool.** For dnscat2 and DNSExfiltrator,
  ROC-AUC stays at 0.995 or above while recall at the validation threshold drops. The threshold is picked on
  validation rows from the training tools, so it is too strict for a tool the model has not seen. Recall at 1%
  FPR shows what a better-placed threshold could recover. Experiment 4 shows the same gap (`docs/m3.md`).
- **The BiLSTM generalises better than the CNN** on every held-out tool.
- **dns2tcp is hard for a name-only model either way.** Its names are short (median 30 characters), so once
  the zone is gone there is little left to read. Experiment 4 CIC -> testbed misses it for the same reason.
- **M1 doesn't rely on the suffix.** Its features are lengths, entropy and per-host counts, so the ranking does
  not change. The false-positive shifts come from threshold placement. One caveat: on the masked table, M1's
  per-host `h_parent_uniq` counts distinct names per host, because every name now has the same parent.

## For the report
- RQ2 (unseen tools): quote M3's **masked** Experiment 3 numbers, not the original ones. The original
  Experiment 3 measures whether the model can read `tunnel.test`.
- M1's testbed numbers stand as reported.
- Experiment 4 (cross-dataset) remains the strongest test of generalisation for every model.

## Limits
- Not rerun masked: Experiment 5 (low-and-slow) for M3, and M2 (DNS-BERT + Isolation Forest), which also reads
  the name. M3's original Experiment 5 result (all 457 slow tunnels caught) carries the same suffix and should
  not be quoted as evidence about slowness.
- One seed per run. GPU training is not bit-for-bit repeatable (`docs/m3.md`).
- Result JSONs are not committed; they are in `nz.zip` in the team's shared data folder.
