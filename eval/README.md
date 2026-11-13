# Phase 1 (Neo): shared evaluation module + M3 character-level models

Drop `eval/`, `models/`, `scripts/` and `tests/` into the repo root. Every command runs from the repo root.

## Layout

| Path | What it is |
|---|---|
| `eval/metrics.py` | All metric code: precision, recall, F1, FPR, ROC-AUC, recall at 1% FPR, per-tool recall, selection rule |
| `eval/plots.py` | ROC curves (all models per experiment), confusion matrices, latency bar chart |
| `eval/summarise.py` | Reads every `results/<model>/<exp>.json` and writes `summary.csv`, `latency.csv`, `per_tool.csv`, `selection.csv`, `figures/` (ROC, confusion, `latency.png`) |
| `eval/run.py` | Trains a model on one experiment and writes its results JSON |
| `eval/experiments.py` | Train/test splits for E1–E5 and S (uses the table's `split` column when present) |
| `eval/results_io.py` | Read/write the results JSON (format from the CONTRACTS card) |
| `models/m3_cnn.py` | Char-CNN: embedding, Conv1D kernels 3/5/7, global max-pool, dense (~0.36M params) |
| `models/m3_bilstm.py` | Char-BiLSTM: 1 layer × 128 units, mean+max pooling (~0.23M params) |
| `models/m3_common.py` | Shared encoding, training loop, threshold, save/load for both M3 variants |
| `scripts/make_fake_data.py` | Fake, contract-valid results JSONs and query tables for testing |
| `tests/test_eval.py` | Unit tests for the metric code |

## Quick start

```bash
python -m pytest -q tests/test_eval.py               # evaluation unit tests

python scripts/make_fake_data.py results             # fake, contract-valid results for 5 models
python -m eval.summarise                             # -> results/summary.csv, latency.csv, selection.csv, figures/

python scripts/make_synthetic_sample.py              # the team's 1,000-row contract sample
python -m eval.run --model m3 --exp E2 --dataset synthetic --epochs 1   # M3 end to end, no real data needed

python -m eval.run --model m3 --exp E2               # trains m3_cnn and m3_bilstm on real CIC
python -m eval.run --model m3 --exp E2 --epochs 1 --max-rows 20000      # quick smoke test on CIC
python contracts.py results/m3_*/*.json              # check results files against the contract
```

Experiments: `E1`, `E2`, `E3` (all tools, or `--holdout iodine`), `E4_cic2testbed`, `E4_testbed2cic`, `E5`,
`S` (shuffled-row split; compare with `E1`, or with `E2` when run with `--dataset cic`).
Use `--dataset cic` for `E3`/`S` before testbed data exists.

Splits follow `models/m1_run.py`: the query table's `split` column when present, otherwise a time- and
session-based 70/30 split. Only `S` shuffles rows.

## Results JSON

`eval.run` writes every key in `docs/contracts.md` section 3 (including `session_ids` and `ts`, needed
before E3/E5) and refuses to write a file that fails `contracts.py`.

The evaluation module itself only needs `scores`, `labels`, `train_time_s` and `latency_ms_per_query`, so it
also reads older files. It uses each file's own `model` and `experiment` keys: ablation runs (model name
contains `ablation`) are listed under their experiment but never picked by the selection rule.

Extra keys it uses when present:

- `threshold`: decision threshold chosen on the model's **validation** split at ≤1% FPR. Without it, the eval
  module picks one on the test set and marks the row `threshold_source = test_fallback`, which is optimistic.
- `tools`: per-tool detection rates in `per_tool.csv` (E3 chart, error analysis).

## Notes

- M3 lower-cases names and keeps the last 256 characters; 41-symbol vocabulary.
- M3 holds out the latest 10% of training sessions for early stopping and the threshold. Test data is never used for either.
- `latency_ms_per_query` from `eval.run` scores one query at a time on whatever machine ran it. The official latency table is re-run on one fixed machine (Kang Hao Wei's E5 card).
