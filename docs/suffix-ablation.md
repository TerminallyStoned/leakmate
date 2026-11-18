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

These are ablation runs. The main selection (`results/selection.csv`) does not read them; the masked selection
below does.

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

### M1 and Random Forest (per-query + per-host features, Colab CPU)
Rerun on 18 Nov with the validation threshold (`docs/m1.md`), on the same Colab CPU setup as the files in
`results/m1` and `results/rf`: `python -m eval.run --model {m1,rf} --exp {E1,E3,E5} --data-root
data/processed_nozone --results-dir results_nozone`. ROC-AUC and recall at 1% FPR are 1.0000 in every run on both
tables, and neither model has a false positive on the masked table. Recall at the model's own threshold,
original -> masked (missed tunnels in brackets):

| Run | M1 | RF |
|---|---|---|
| Experiment 1 (within-testbed) | 1.000 -> 1.000 (0 -> 0 of 34,180) | 1.000 -> 1.000 (0 -> 0) |
| Experiment 3, dns2tcp held out | 1.000 -> 1.000 (0 -> 0 of 7,764) | 1.000 -> 1.000 (0 -> 0) |
| Experiment 3, dnscat2 held out | **0.218 -> 0.218** (4,834 -> 4,834 of 6,182) | 0.958 -> 1.000 (259 -> 0) |
| Experiment 3, dnsexfiltrator held out | 1.000 -> 1.000 (0 -> 0 of 9,402) | 1.000 -> 1.000 (0 -> 0) |
| Experiment 3, iodine held out | 0.999 -> 1.000 (10 -> 0 of 10,832) | 0.999 -> 1.000 (8 -> 2) |
| Experiment 5 (low-and-slow) | 1.000 -> 1.000 (0 -> 0 of 457) | 0.993 -> 1.000 (3 -> 0) |

False positives, original -> masked, out of 33,519 benign: M1 3 -> 0 (dns2tcp held out) and 1 -> 0 (dnsexfiltrator
held out), otherwise 0 -> 0; RF 0 -> 0 in every run. RF's dnscat2 row moves between machines and runs
(`docs/m1.md`), so read its 0.958 -> 1.000 as within that noise.

The 17 Nov M1 runs that this section used to show had their threshold set on the test data (200 to 324 false
positives per run, recall 1.0); they are replaced by the runs above.

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

## Selection with the domain hidden
`results/selection.csv` reads the original testbed runs, where a name-reading model can score perfectly from the
`tunnel.test` suffix. `results_nozone/selection.csv` applies the same rule (best F1 with FPR at most 1% and
latency at most 10 ms; an F1 tie goes to the faster model) to the masked runs of M1, RF, M3, and M2 and the Isolation
Forest with and without host averaging. As in `results/selection.csv`, ablation runs such as M2's character
model are left out. Rebuild it with `python -m eval.summarise --results-dir results_nozone --no-plots`.

Latency comes from `latency_cpu.csv`: every model timed on one CPU, the machine that runs the live detector
(`scripts/time_models.py`, below).

| Run | Original table picks | Masked table picks | Masked F1 | Masked FPR |
|---|---|---|---|---|
| Experiment 1 (within-testbed) | M3 BiLSTM | M1 | 1.0000 | 0% |
| Experiment 3, dns2tcp held out | M3 BiLSTM | M1 | 1.0000 | 0% |
| Experiment 3, dnscat2 held out | M3 BiLSTM | RF | 1.0000 | 0% |
| Experiment 3, dnsexfiltrator held out | M3 BiLSTM | M1 | 1.0000 | 0% |
| Experiment 3, iodine held out | M3 BiLSTM | M1 | 1.0000 | 0% |
| Experiment 5 (low-and-slow) | M3 BiLSTM | M1 | 1.0000 | 0% |

- **With the domain hidden, M1 wins every run but one.** M3 is picked for none of them.
- **RF covers M1's gap.** With dnscat2 held out, M1 catches 22% at its own threshold and RF catches all of it.
  RF's dnscat2 recall moves between machines (0.49 to 0.96 on the original table, `docs/m1.md`), so treat that
  pick as less firm than the others.
- **M2 is out on CPU.** M2 BPE takes 23.2 ms per query and the character model 27.9 ms, against 6 to 7 ms on the
  Colab GPU, so neither meets the 10 ms rule.
- **The original-table M3 picks are a tie.** The CNN and BiLSTM both score F1 1.0, and the BiLSTM wins by 0.004 ms.
- Experiments 2 and 4 use CIC and are not in the masked selection; for them `results/selection.csv` stands.

### One-CPU latency
`python scripts/time_models.py` loads each saved model and scores the same 500 Experiment 1 test queries one at
a time, three times, in one process, and writes `results/latency_cpu.csv` with the CPU name. `eval.summarise`
uses that file for the latency table and the 10 ms rule when it exists; `summary.csv` keeps each run's own
timing. A host-averaging variant gets its base model's time, as in the per-run timings. Timed on 18 Nov on an
AMD Ryzen 7 9800X3D (WSL), ms per query: M3 BiLSTM 0.81, M3 CNN 0.82, M1 5.04, RF 8.07, Isolation Forest 9.09,
M2 BPE 23.2, M2 character 27.9. M1 and RF were retrained for Experiment 1 with the current code (seconds); M2 is
the `m2/phase2_weights` testbed models from the shared Drive; M3 is a saved Experiment 1 model.

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
- **M1 and RF don't rely on the suffix.** Their features are lengths, entropy and per-host counts, so the
  ranking does not change, and at the validation threshold the errors barely move. M1 misses the same 4,834
  held-out dnscat2 queries on both tables, so that miss is not a suffix effect. One caveat: on the masked table,
  the per-host `h_parent_uniq` counts distinct names per host, because every name now has the same parent.
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
- M1 and RF: the original and masked numbers agree, so either can be quoted; details in `docs/m1.md`.
- Model selection on testbed experiments (1, 3 and 5): quote `results_nozone/selection.csv` (section above),
  and say that latency was timed on one CPU after the results freeze.
- M2: quote the **masked** numbers for the character model (ablation 1) and drop the claim that it beats BPE on
  the testbed. M2 BPE, M2 with host averaging and the Isolation Forest stand as reported; the masked numbers can
  sit beside them.
- Experiment 4 (cross-dataset) remains the strongest test of generalisation for every model.

## Limits
- M2's Experiment 5 (masked and original) is derived from its Experiment 1 results (`scripts/m2_e5.py`, same model
  and threshold, since M2 trains on benign only); numbers in `docs/m2.md`.
- One seed per run. GPU training is not bit-for-bit repeatable (`docs/m3.md`).
- Every masked result JSON is in `results_nozone/` (Experiments 1, 3 and 5): M1, RF, M2 with ablations 1 and 2,
  the Isolation Forest, and M3. M3's files are copies of the Colab runs in `nz.zip` (Experiments 1 and 3) and
  `nz_e5.zip` (Experiment 5) in the "leakmate captures" Drive folder.
- `results_nozone/latency_cpu.csv` is a copy of `results/latency_cpu.csv`: the timing depends on the model, not on
  the table it was trained on. Each run's own timing (Colab CPU or GPU) stays in `summary.csv`.
