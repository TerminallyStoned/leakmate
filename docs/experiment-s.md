# Experiment S (shuffled vs time split): how much shuffling inflates scores

**Question.** Every other experiment splits by time and session. Experiment S asks how much better
a model looks if rows are shuffled at random instead. That's the shortcut many papers take, and the
proposal promised to measure it.

**Setup.** M1 (XGBoost, per-query + per-host features) is trained twice on the same table: once on
the time split, and once on a random 70/30 row shuffle (seed 42). Everything else is the same.

| Dataset | Time split (file) | Shuffled (file) |
|---|---|---|
| CIC | `results/m1/E2.json` (Experiment 2) | `results/m1/S.json` |
| Testbed | Experiment 1 run, same command as `results/m1/E1.json` | `results/m1/S_testbed.json` |

Rerun the testbed pair:
```bash
python -m models.m1_run --model m1 --exp S --split shuffled --tag testbed --no-shap --data data/processed/testbed/queries.parquet
python -m models.m1_run --model m1 --exp E1 --no-shap --data data/processed/testbed/queries.parquet
```

## Results (17 Nov)

| Dataset | Split | F1 | FPR | Recall | ROC-AUC | Recall at 1% FPR | FP / test rows |
|---|---|---|---|---|---|---|---|
| CIC | time | 0.9982 | 0.0073 | 1.0000 | 1.0000 | 1.0000 | 274 / 113,078 |
| CIC | shuffled | 0.9993 | 0.0028 | 1.0000 | 1.0000 | 1.0000 | 106 / 113,070 |
| Testbed | time | 0.9981 | 0.0040 | 1.0000 | 1.0000 | 1.0000 | 133 / 67,699 |
| Testbed | shuffled | 0.9966 | 0.0068 | 1.0000 | 1.0000 | 1.0000 | 230 / 67,669 |
| Testbed, per-query features only | time | 0.9952 | 0.0099 | 1.0000 | 1.0000 | 1.0000 | 332 / 67,699 |
| Testbed, per-query features only | shuffled | 0.9951 | 0.0100 | 1.0000 | 1.0000 | 1.0000 | 335 / 67,669 |

## What it shows

- **No measurable inflation for M1 on either dataset.** Both splits give ROC-AUC 1.0 and recall 1.0.
  The F1 and false-positive gaps are under 0.005 and go in opposite directions on CIC (+0.0011 F1
  when shuffled) and the testbed (−0.0015 F1 when shuffled).
- **The false-positive differences are threshold placement, not the model.** These runs have no
  threshold of their own (`threshold_source: test_fallback`), so the evaluation module sets one on
  the test set at about 1% FPR. The ranking metrics, which don't depend on a threshold, are identical.
- **The reason is saturation, not that shuffling is harmless.** Within one dataset, tunnel and benign
  queries are separable from the query name alone. Even the weaker per-query-only model scores 1.0
  ROC-AUC under both splits. With no headroom, shuffling has nothing to inflate.
- **For the report:** time-based splits remain the honest default, but the inflation they guard
  against doesn't appear here for M1. Where scores are not saturated is in Experiments 3
  (leave-one-tool-out), 4 (cross-dataset) and 5 (low-and-slow). That's where generalisation is
  actually tested.

## Limits

- One model (M1) and one seed. M3 (char-CNN/BiLSTM) was not run, as the card allowed.
- The CIC pair dates from 13 Nov (same code version for both files). The testbed pair is from 17 Nov.
