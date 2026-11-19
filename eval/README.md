# eval: train, score and summarise

Shared evaluation for every model. Run everything from the repo root. The experiment names are
`eval.experiments.NAMES`; splits follow `models/m1_run.py` (the table's `split` column when present,
otherwise a time- and session-based 70/30 split; only Experiment S shuffles rows).

```bash
python -m pytest -q tests/test_eval.py               # evaluation unit tests
python scripts/make_synthetic_sample.py              # the 1,000-row contract sample
python -m eval.run --model m3 --exp E2 --dataset synthetic --epochs 1   # end to end, no real data needed
python -m eval.run --model m3 --exp E2               # trains m3_cnn and m3_bilstm on CIC
python -m eval.run --model m3 --exp E3 --holdout iodine
python contracts.py results/m3_*/*.json              # check results files against the contract
python -m eval.summarise                             # -> results/summary.csv, latency.csv, per_tool.csv, selection.csv, figures/
```

`latency_ms_per_query` from `eval.run` scores one query at a time on whatever machine ran it; the latency
table and the selection use `results/latency_cpu.csv` (`scripts/time_models.py`) instead. M3 details: `docs/m3.md`.

## Results JSON

`eval.run` writes every key in `docs/contracts.md` section 3 (including the optional `session_ids` and `ts`)
and refuses to write a file that fails `contracts.py`.

The evaluation module itself only needs `scores`, `labels`, `train_time_s` and `latency_ms_per_query`, so it
also reads older files. It uses each file's own `model` and `experiment` keys: ablation runs (model name
contains `ablation`) are listed under their experiment but never picked by the selection rule.

Extra keys it uses when present:

- `threshold`: decision threshold chosen on the model's **validation** split at ≤1% FPR. Without it, the eval
  module picks one on the test set and marks the row `threshold_source = test_fallback`, which is optimistic.
- `tools`: per-tool detection rates in `per_tool.csv` (Experiment 3 chart, error analysis).
