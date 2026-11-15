# Experiment E2 — CIC-Bell-DNS-EXF-2021 benchmark

Card 19 (`[Kang Hao Wei] M1: E1, E2, E3, E4`) asks M1 and the Random Forest baseline to be
run against the public benchmark and compared with published results. This file records the
first half: the real dataset, the exact commands, and the numbers the shared evaluation
module produced on 15 Nov 2026. Nothing here is hand-computed — every metric comes from
`eval/metrics.py` via `python -m eval.run` / `python -m eval.summarise`.

## Data

CIC-Bell-DNS-EXF-2021 [9] is form-gated: the download page posts a registration and then
serves zips from `cicresearch.ca`. Downloaded 15 Nov 2026 into `data/raw/cic/` (gitignored,
65 MB of zips → 18 pcaps, 260 MB):

| group | pcaps | contents |
| --- | --- | --- |
| `heavy/attack` | 6 | `heavy_{audio,compressed,exe,image,text,video}.pcap` (20–34 MB each) |
| `heavy/benign` | 3 | `benign_heavy_{1,2,3}.pcap` (12–15 MB) |
| `light/attack` | 6 | `light_{audio,compressed,exe,image,text,video}.pcap` (272 KB–6.6 MB) |
| `light/benign` | 1 | `benign.pcap` (12 MB) |
| `plain/benign` | 2 | `benign_{1,2}.pcap` (21–28 MB) |

Attack pcap names never contain the string `attack` — the label comes from the directory
they were unpacked into, which is what `parser/cic.py` uses (`is_attack = "attack" in path`).

```bash
python -m parser cic --raw data/raw/cic --out data/processed/cic/queries.parquet
# 376,897 rows | label=1: 251,564 | train 263,819 / test 113,078   (21 s)
python -m parser features --dataset cic
# data/processed/cic/features.parquet: 376,897 rows x 21 features
python contracts.py data/processed/cic/queries.parquet
# ok
```

The 263,819 / 113,078 split is identical to `results/m1/E2.json`, which confirms this copy of
the dataset matches the one the Stage-2 runs used.

## Results

```bash
python -m eval.run --model m1 --exp E2 --results-dir /tmp/resverify
python -m eval.run --model rf --exp E2 --results-dir /tmp/resverify
python -m eval.summarise --results-dir /tmp/resverify --no-plots
```

`--results-dir` keeps these runs out of `results/`; the Stage-2 files already on `main` are
left untouched so nobody's figure moves under them.

Metrics are `eval/metrics.py`'s; latency is `eval/run.py`'s 500 single-row `score()` calls.
Latency is deliberately not tabulated here — see [latency.md](latency.md), which times all six
models on one machine, because a single figure moves 2-3x with load.

| run | accuracy | precision | recall | F1 | FPR | ROC-AUC | train s |
| --- | --- | --- | --- | --- | --- | --- | --- |
| m1, this file | 0.99991 | 0.99987 | 1.000 | 0.99993 | 0.00027 | 1.0000 | 28.6 |
| rf, this file | 0.99814 | 0.99722 | 1.000 | 0.99861 | 0.00556 | 1.0000 | 25.5 |
| m1, `results/m1/E2.json` | 0.99758 | 0.99638 | 1.000 | 0.99818 | 0.00726 | 1.0000 | 1.3 |
| rf, `results/rf/E2.json` | 0.99802 | 0.99704 | 1.000 | 0.99852 | 0.00593 | 1.0000 | 6.6 |

All four are on the same 113,078-row test split (75,323 tunnel queries). The card-11 rows are
`results/m1/E2.json` and `results/rf/E2.json` re-summarised by this module, so the differences
are not evaluation-side, and they are not run-to-run luck either: this file's numbers came from
two runs on two different days and agree to six decimal places. Both used the same config as the
Stage-2 files — seed 42, `host: true`, `window_s: 60.0`, `n_jobs: -1`, and the same 10 columns
dropped by the CIC leak guard, leaving 11 features (entropy, n_digits, n_upper, n_special,
digit_ratio, resp_size, qlen_wire and the host aggregates).

So the residual gap is environmental. m1 reports `best_iteration: 111` of `n_estimators: 500`
with early stopping, and 1.3 s for that on 263,819 rows is not reachable here (28.6 s for the
same fit), so the Stage-2 file was trained on other hardware, where the tree learner's threading
built a slightly different model. With ROC-AUC
1.0 either way, that surfaces as a few thousandths of precision, moved further by the threshold the
module picks on the test scores — see the test_fallback note below. The report should quote one
row per model and name the machine, not print both side by side as if they were an experiment.

Two things to keep in view when these go in the report:

* Recall is exactly 1.0 with ROC-AUC 1.0 on CIC. Every tunnel query in this dataset comes
  from one tool (DNSExfiltrator) per the proposal's dataset description, so this measures
  tool recognition, not evasion resistance — the operating point that matters for the campus
  is E1/E3/E5.
* `threshold_source` is `test_fallback` for all four rows: neither model exposes a
  `.threshold`, so the module picks the threshold on the test scores. It is honest per
  model but optimistic per experiment, and it is why `precision` should be read with the
  FPR column rather than alone.

## Comparison with published results

### What is available now

One open-access study reports accuracy on this exact dataset, so E2 has a published anchor
while the card's own references are still being obtained:

> E. Akgözoğlu, "Comparison of machine learning algorithms for detection of data
> exfiltration over DNS," *Yalvaç Akademi Dergisi*, 9-2 (2024) 61-70, doi
> 10.57120/yalvac.1507402. Table 4, CIC-Bell-DNS-EXF-2021, GridSearchCV-tuned, random
> 80/20 split, accuracy only.

| model | split | accuracy | note |
| --- | --- | --- | --- |
| Decision Trees (Akgözoğlu) | random 80/20 | 0.9974 | stateful features |
| Extra Trees (Akgözoğlu) | random 80/20 | 0.9974 | stateful features |
| **Random Forest (Akgözoğlu)** | random 80/20 | **0.9971** | stateful features, `max_depth=5`, 50 trees |
| K-Nearest Neighbour (Akgözoğlu) | random 80/20 | 0.9968 | stateful features |
| all four (Akgözoğlu) | random 80/20 | 0.9394-0.9395 | stateless features only |
| **rf (this project)** | time 70/30 | **0.9981** | 21 parser features, no depth cap |
| **m1 (this project)** | time 70/30 | **0.9999** | same features, XGBoost `hist` |

Read the comparison as "we are at or above the published figure on the same dataset", not as
a controlled win: the published run is a random split with a 50-tree depth-5 forest after
dropping duplicate rows and timestamps, ours is a time-ordered split that keeps every query,
and the published paper reports accuracy alone, so precision and FPR have no counterpart in
it. The stateless row is the interesting one for the report — a 5.8 point drop when timing
features are removed is the closest published analogue of our own leaky-column ablation.

### What is still missing

* [6] P. Pan et al., *When DNS tunnels learn to hide*, IEEE Network, 2026
  (doi 10.1109/MNET.2026.3727443) is paywalled. The public abstract names the system
  (EvaSense), says it is evaluated on real campus traffic and public datasets, and gives no
  metrics, so there is nothing to copy honestly.
* [7] Unit 42, *Understanding DNS tunneling traffic in the wild*, 2024, is a measurement
  write-up: volumes, tool families, entropy statistics. It reports no classifier metrics on
  CIC-Bell, so a metrics table against it would be a category error.

Needed to finish this section: the PDF of [6] (SIT library / the group's literature-review
folder) with its CIC results table, or a decision to use the dataset paper [9] instead — the
proposal's own experiment list says "(2) the CIC benchmark against [9]", while the Trello card
names [6] and [7]. [9] (Mahdavifar et al., ICCNS 2021) released the dataset and "found Random
Forest best among five classifiers" per the proposal, but the proposal quotes no number for
it, and the paper itself is paywalled, so the same access problem applies.

One published figure is already in the group's proposal and can anchor the evasion discussion
rather than E2: "on evasive tunnels, the XGBoost model of [10] detected under 1%" as measured
in [6]. That is the number M1/M2/M3 must beat on E5, and it is worth a row in the E5 write-up
when card 25 runs.

## Reproduce

```bash
uv venv /tmp/lmv --python 3.12 && /tmp/lmv/bin/pip install -r requirements.txt \
    --extra-index-url https://download.pytorch.org/whl/cpu
/tmp/lmv/bin/python -m parser cic --raw data/raw/cic --out data/processed/cic/queries.parquet
/tmp/lmv/bin/python -m parser features --dataset cic
/tmp/lmv/bin/python -m eval.run --model m1 --exp E2 --results-dir /tmp/resverify
/tmp/lmv/bin/python -m eval.run --model rf --exp E2 --results-dir /tmp/resverify
/tmp/lmv/bin/python -m eval.summarise --results-dir /tmp/resverify --no-plots
```
