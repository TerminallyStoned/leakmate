# One-box latency for every model

Card 25 ("M1: E5 low-and-slow + latency for ALL models + apply selection rule") needs one
table where all six models are timed on the same machine, because the Stage-2 figures were
produced on different hardware and are not comparable. This is that table. The E5 half of the
card still needs the Stage-3 testbed captures and is not covered here.

## Machine and method

* VMware VM, 4 vCPUs of an Intel Core Ultra 9 275HX, torch 2.15.0+cpu
  (`torch.get_num_threads() == 4`, `OMP_NUM_THREADS` unset), Python 3.12.
* One command per model, nothing else running:

  ```bash
  python -m eval.run --model <m> --exp E2 --max-rows 40000 [--epochs 1 for the torch models] \
      --results-dir <dir>
  python -m eval.summarise --results-dir <dir> --no-plots
  ```

* Latency is `eval/run.py`'s own measure: 500 single-row `score()` calls after one warm-up
  call, batch size 1. That is the streaming cost the campus question is about, not a
  throughput test.
* Two independent passes were done. Pass A trained the torch models on 4,000 rows to keep the
  first sweep short; pass B used 40,000 rows for every model. Training-set size does not
  change per-query latency (the architecture does), so both passes are valid latency samples.

## Result

| model | pass A ms/query | pass B ms/query | train s (40k) | < 10 ms |
| --- | --- | --- | --- | --- |
| m1 (XGBoost) | 12.95 | 7.37 | 1.9 | only sometimes |
| rf (Random Forest) | 22.04 | 16.97 | 1.9 | no |
| iforest | 20.88 | 18.16 | 0.6 | no |
| m3_cnn | 24.38 | 7.46 | 386.7 | only sometimes |
| m3_bilstm | 25.18 | 24.99 | 156.6 | no |
| m2_dnsbert | 54.84 | not finished | — | no |

`m1` on this box brackets the 13.55 ms/query recorded in `results/m1/E2.json`, which was
measured on the machine that ran Stage 2 — the two machines are the same class after all.

## What this says

1. **One run cannot decide a 10 ms gate.** The same model measured 7.4 and 13.0 ms/query an
   hour apart on the same box, and `m3_cnn` ranged 7.5-45.6 ms depending on what else was
   running. `eval.summarise` writes `n_runs = 1` and `latency_ms_min == latency_ms_max`, so
   the table looks more precise than it is. The official E5 table should carry a median of
   several runs; the module already aggregates multiple results files per experiment, so
   running `--exp E5` three times into `E5_r1.json`, `E5_r2.json`, `E5_r3.json` is enough
   (or `eval.run` grows a `--repeats`).
2. **Only M1 and the M3 CNN get under 10 ms, and only when the box is quiet.** M1 is the
   cheaper of the two by training time (1.9 s against 387 s), which is the argument the
   selection rule is meant to make.
3. **The gate in the code is not the gate in the proposal.** `eval/metrics.py` sets
   `MAX_FPR = 0.01, MAX_LATENCY_MS = 10.0` ("best F1 at under 1% FPR and under 10 ms", the
   board wording). The proposal's selection rule is stricter on false positives: best recall
   at **under 0.1%** false positives. At 1% FPR, `rf`, `iforest` and both M3 variants clear
   the FPR bar; at 0.1% only `m1` does (fpr 0.0003 vs 0.0098 for rf on the same split). With
   every model failing on latency, `results/selection.csv` came out with an empty
   `selected_model` — which is a true statement about this box, not about the models. Someone
   (Neo, as eval owner) should reconcile the constant with the proposal before the E5 verdict
   goes in the report.
4. **M2 does not belong on the CPU box.** Its 4,000-row run scored 54.8 ms/query, and the
   40,000-row E2 run was still going after an hour when this was written; the Stage-2 M2
   numbers were produced on a Colab T4. For E5, either measure M2 on the GPU and say so, or
   keep it in the table with a footnote — reporting a CPU figure next to GPU figures from the
   same models would be the mistake.
5. **13,000 queries/s is a batch question.** Single-stream latency of 7-25 ms is 40-140 qps;
   the campus figure is met by batching (`score()` already takes a DataFrame), not by a
   faster model. If the report quotes 13,000 qps it should quote the batched throughput
   alongside the per-query latency, since they answer different questions.

## Reproduce

Results are not committed (they are a latency probe, not an experiment verdict):

```bash
mkdir -p /tmp/reslat
for m in rf iforest m1; do
  python -m eval.run --model $m --exp E2 --max-rows 40000 --results-dir /tmp/reslat
done
for m in m3_cnn m3_bilstm; do
  python -m eval.run --model $m --exp E2 --max-rows 40000 --epochs 1 --results-dir /tmp/reslat
done
python -m eval.run --model m2_dnsbert --exp E2 --max-rows 40000 --epochs 1 --results-dir /tmp/reslat
python -m eval.summarise --results-dir /tmp/reslat --no-plots
```

Do it with the lab and any browser workloads stopped: the tcpdump capture loops and a
competing training run are both enough to triple a latency number.
