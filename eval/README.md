# Phase 1 (Neo): shared evaluation module + M3 character-level models

Drop `eval/`, `models/`, `scripts/` and `tests/` into the repo root. Every command runs from the repo root.

## Layout

| Path | What it is |
|---|---|
| `eval/metrics.py` | All metric code: precision, recall, F1, FPR, ROC-AUC, recall at 1% FPR, per-tool recall, selection rule |
| `eval/plots.py` | ROC curves (all models per experiment), confusion matrices, latency bar chart |
| `eval/summarise.py` | Reads every `results/<model>/<exp>.json` and writes `summary.csv`, `latency.csv`, `per_tool.csv`, `selection.csv`, `figures/` (ROC, confusion, `latency.png`) |
| `eval/run.py` | Trains a model on one experiment and writes its results JSON |
| `eval/experiments.py` | **Placeholder** splits for E1–E5 and S. Replace with Yehan's splits when they land |
| `eval/results_io.py` | Read/write the results JSON (format from the CONTRACTS card) |
| `models/m3_cnn.py` | Char-CNN: embedding, Conv1D kernels 3/5/7, global max-pool, dense (~0.36M params) |
| `models/m3_bilstm.py` | Char-BiLSTM: 1 layer × 128 units, mean+max pooling (~0.23M params) |
| `models/m3_common.py` | Shared encoding, training loop, threshold, save/load for both M3 variants |
| `scripts/make_fake_data.py` | Fake results JSONs and fake query tables for testing |
| `tests/test_eval.py` | Unit tests for the metric code |

## Quick start

```bash
pip install -r requirements.txt
python -m pytest -q                                  # metric unit tests

python scripts/make_fake_data.py results             # fake results for 5 models
python -m eval.summarise                             # -> results/summary.csv, selection.csv, figures/

python scripts/make_fake_data.py queries             # fake CIC/testbed query tables (skip once real data exists)
python -m eval.run --model m3 --exp E2               # trains m3_cnn and m3_bilstm on CIC
python -m eval.run --model m3 --exp E2 --epochs 1 --max-rows 20000   # quick smoke test
```

Experiments: `E1`, `E2`, `E3` (all tools, or `--holdout iodine`), `E4_cic2testbed`, `E4_testbed2cic`, `E5`, `S_time`, `S_shuffled`.

## Results JSON

Required (CONTRACTS card): `scores`, `labels`, `train_time_s`, `latency_ms`, `config`.

Optional, used when present:

- `threshold`: decision threshold chosen on the model's **validation** split at ≤1% FPR. Without it, the eval module picks one on the test set and marks the row `threshold_source = test_fallback`, which is optimistic.
- `tools`: tool name per test row. Gives the per-tool detection rates in `per_tool.csv` (E3 chart, error analysis).

## Notes

- M3 lower-cases names and keeps the last 256 characters; 41-symbol vocabulary.
- M3 holds out the latest 10% of training sessions for early stopping and the threshold. Test data is never used for either.
- `latency_ms` from `eval.run` scores one query at a time on whatever machine ran it. The official latency table is re-run on one fixed machine (Kang Hao Wei's E5 card).
