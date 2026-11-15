# Experiment E2 — CIC-Bell-DNS-EXF-2021 benchmark

Card 19 (`[Kang Hao Wei] M1: E1, E2, E3, E4`) asks M1 and the Random Forest baseline to be
run against the public benchmark and compared with published results. This file records the
first half: the real dataset, the exact commands, and the numbers the shared evaluation
module produced on 15 Nov 2026. Nothing here is hand-computed — every metric comes from
`eval/metrics.py` via `python -m eval.run` / `python -m eval.summarise`.

## Data

CIC-Bell-DNS-EXF-2021 [9] is form-gated: the download page posts a registration and then
serves zips from `cicresearch.ca`. Downloaded 15 Nov 2026 into `data/raw/cic/` (gitignored,
325 MB of zips → 18 pcaps, 340 MB):

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

| run | accuracy | precision | recall | F1 | FPR | ROC-AUC | latency ms/query | train s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| m1, this file | 0.99991 | 0.99987 | 1.000 | 0.99993 | 0.00027 | 1.0000 | 24.64 | 28.2 |
| rf, this file | 0.99814 | 0.99722 | 1.000 | 0.99861 | 0.00556 | 1.0000 | 23.03 | 20.5 |
| m1, `results/m1/E2.json` | 0.99758 | 0.99638 | 1.000 | 0.99818 | 0.00726 | 1.0000 | 13.55 | 1.3 |
| rf, `results/rf/E2.json` | 0.99802 | 0.99704 | 1.000 | 0.99852 | 0.00593 | 1.0000 | 29.31 | 6.6 |

All four are on the same 113,078-row test split (75,323 tunnel queries). The card-11 rows are
`results/m1/E2.json` and `results/rf/E2.json` re-summarised by this module, so the numbers
agree to three decimals and the differences are training-side, not evaluation-side:
`train_time_s` 1.3 s (m1) and 6.6 s (rf) against 28.2 s / 20.5 s here means the Stage-2 run
trained on faster hardware with more cores, and the extra precision in the re-run follows
from a differently-seeded forest and tree. **Latency is the number that is not comparable at
all**: 13.55 ms/query was recorded on that box, 24.64 ms/query on this one. That is exactly
why card 25 re-measures every model on one machine.

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

Card 19 asks for the numbers in [6] and [7] in a comparison table. Not transcribed yet:

* [6] P. Pan et al., *When DNS tunnels learn to hide*, IEEE Network, 2026
  (doi 10.1109/MNET.2026.3727443) is paywalled. The public abstract names the system
  (EvaSense), says it is evaluated on real campus traffic and public datasets, and gives no
  metrics, so there is nothing to copy honestly.
* [7] Unit 42, *Understanding DNS tunneling traffic in the wild*, 2024, is a measurement
  write-up: volumes, tool families, entropy statistics. It reports no classifier metrics on
  CIC-Bell, so a metrics table against it would be a category error.

Needed to finish this section: the PDF of [6] (SIT library / the group's literature-review
folder) with its CIC results table, or confirmation that the comparison should use the
dataset paper [9] (Mahdavifar et al., ICCNS 2021), whose Random Forest figure the group has
already cited in the proposal.

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
