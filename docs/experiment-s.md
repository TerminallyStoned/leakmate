# Experiment S (shuffled vs time split): how much shuffling inflates scores

**Question.** Every other experiment splits by time and session. Experiment S asks how much better
a model looks if rows are shuffled at random instead. That's the shortcut many papers take, and the
proposal promised to measure it.

**Setup.** M1 (XGBoost, per-query + per-host features) is trained twice on the same table: once on
the time split, and once on a random 70/30 row shuffle (seed 42). Everything else is the same.

| Dataset | Time split (file) | Shuffled (file) |
|---|---|---|
| CIC | `results/m1/E2.json` (Experiment 2) | `results/m1/S.json` |
| Testbed | `results/m1/E1.json` (Experiment 1, freeze) | `results/m1/S_testbed.json` |

Rerun the testbed pair:
```bash
python -m models.m1_run --model m1 --exp S --split shuffled --tag testbed --no-shap --data data/processed/testbed/queries.parquet
python -m eval.run --model m1 --exp E1
```

## Results (18 Nov rerun)
All four files were rerun on 18 Nov with M1's validation threshold (`docs/m1.md`), on one machine.

| Dataset | Split | F1 | FPR | Recall | ROC-AUC | Recall at 1% FPR | FP / test rows | Missed tunnels |
|---|---|---|---|---|---|---|---|---|
| CIC | time | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 1.0000 | 0 / 113,078 | 1 / 75,323 |
| CIC | shuffled | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 1.0000 | 0 / 113,070 | 0 / 75,551 |
| Testbed | time | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 1.0000 | 0 / 67,699 | 0 / 34,180 |
| Testbed | shuffled | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 1.0000 | 0 / 67,669 | 0 / 34,073 |

The 17 Nov version of this table also had two "per-query features only" testbed rows (F1 0.9952 time, 0.9951
shuffled, ROC-AUC 1.0 for both). Those runs have no file in `results/` and were not redone; their F1 and
false-positive counts were at a threshold set on the test data.

## What it shows

- **No measurable inflation for M1 on either dataset.** Both splits give ROC-AUC 1.0 and recall 1.0, and
  the only error in the four runs is one missed CIC tunnel query under the time split.
- **The earlier false-positive differences were threshold placement, not the model.** Before 18 Nov these
  runs had no threshold of their own, so the evaluation module set one on the test set at about 1% FPR,
  which produced 106 to 274 false positives per run. With the threshold chosen on validation data there
  are none. The ranking metrics, which don't depend on a threshold, were identical then and are now.
- **The reason is saturation, not that shuffling is harmless.** Within one dataset, tunnel and benign
  queries are separable from the query name alone. Even the weaker per-query-only model scores 1.0
  ROC-AUC under both splits. With no headroom, shuffling has nothing to inflate.
- **For the report:** time-based splits remain the honest default, but the inflation they guard
  against doesn't appear here for M1. M1 also scores ROC-AUC 1.0 on Experiments 3 (leave-one-tool-out)
  and 5 (low-and-slow) (`docs/m1.md`); only Experiment 4 (cross-dataset) leaves it headroom (0.94
  CIC -> testbed), so that is where its generalisation is actually tested.

## Limits

- One model (M1) and one seed. M3 (char-CNN/BiLSTM) was not run, as the card allowed.
- All four files are from the 18 Nov rerun (same code version, same machine).
