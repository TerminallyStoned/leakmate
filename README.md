# leakmate

**Detecting DNS tunnels with supervised, unsupervised and language-model detectors.**
ICT3214 Security Analytics, Coursework 2 · Group 32 · Singapore Institute of Technology

DNS is allowed out of almost every network, so attackers hide stolen data and C2 traffic in DNS
query names. Off-the-shelf tunnelling tools are easy to catch; tunnels from unseen tools, or ones that
send data slowly, are not. This project builds a contained testbed that generates labelled tunnel
traffic, compares three ML/AI detectors on it and on a public benchmark, and runs the best one on live
DNS traffic behind a dashboard.

> Status: **Phase 4 (report and submission)**. Every model has result files for Experiments 1–5 on `main`, and
> the frozen results are at the `results-freeze` tag. Sections marked *planned* are not in the repo yet.
> The plan and owners live on the team Trello board **ICT3214**.

## Research questions
- **RQ1** Which model gives the best trade-off between detection, false positives and speed?
- **RQ2** How much does detection drop on tunnelling tools absent from training?
- **RQ3** Can a benign-only model (M2) match supervised models, especially on unseen tools?

## Models
| | Model | Supervision | Baseline | Status |
|---|---|---|---|---|
| **M1** | XGBoost on per-query + per-host features, SHAP explanations | supervised | Random Forest | ✅ Experiments 1–5 run with a validation threshold ([`docs/m1.md`](docs/m1.md)) |
| **M2** | DNS-BERT: small BERT trained only on benign names; flags high pseudo-perplexity | benign-only | Isolation Forest | ✅ Experiments 1–5, ablations 1 and 2, error analysis ([`docs/m2.md`](docs/m2.md)) |
| **M3** | Character-level CNN on the raw query name | supervised | BiLSTM | ✅ Experiments 1–5, error analysis ([`docs/m3.md`](docs/m3.md)) |

Selection rule: best F1 with false-positive rate at most 1% and latency at most 10 ms per query; an F1 tie goes to the faster model.
Every model picks its decision threshold on validation data from its training set, never on test data.

> Note: numbering follows the Trello board. The proposal numbered the models differently
> (autoencoder as M2, the leakage/language-model detector as M3); the report uses the board's numbering.

## Experiments
| ID (in code) | Experiment |
|---|---|
| `E1` | Experiment 1 (within-testbed): train and test on our testbed data |
| `E2` | Experiment 2 (CIC benchmark): compared with published results |
| `E3` | Experiment 3 (leave-one-tool-out): unseen tools, RQ2 |
| `E4` | Experiment 4 (cross-dataset): CIC ↔ testbed |
| `E5` | Experiment 5 (low-and-slow): slow, throttled tunnels |
| `S` | Experiment S (shuffled vs time split): how much shuffling inflates scores |

All splits are time/session based, never shuffled rows (except in Experiment S).
The short IDs are only what you type (`--exp E3`) and what files are named (`results/m1/E2.json`);
summaries, figures and docs use the full names.

## Data
- **CIC-Bell-DNS-EXF-2021** (University of New Brunswick): public benchmark, DNSExfiltrator attacks.
  Download the **PCAP** folder (registration required): https://www.unb.ca/cic/datasets/dns-exf-2021.html.
  ⚠️ Captured with snaplen = 96 B: exfil query names are truncated to ~40 chars and lose their qtype.
  Details in [`docs/m2.md`](docs/m2.md).
- **Testbed**: closed Docker network with resolver + authoritative server generating labelled
  traffic from iodine, dnscat2, dns2tcp and DNSExfiltrator, plus benign traffic (Tranco, apt, curl,
  browser). Containment is tested so no traffic leaves the network. The network
  ([`testbed/`](testbed/README.md)), the benign generator ([`testbed/benign/`](testbed/benign/README.md)) and
  the four tunnel tools ([`testbed/tools/`](testbed/tools/README.md)) are all in the repo. The 16 Nov query
  table has 59 captures and 225,561 queries: 113,837 tunnel and 111,724 benign
  ([`data/raw/manifest.csv`](data/raw/manifest.csv) lists the captures).
- **Tranco** top-1M list: benign domain names (https://tranco-list.eu).

Raw data, processed data and model weights are **not** committed (see `.gitignore`); scripts regenerate them.

## Repository layout
```
models/       model code, one file per model: train / score / save / load
  m2_dnsbert.py        M2 DNS-BERT (BPE + char tokenizers, batched pseudo-perplexity)
  iforest_baseline.py  Isolation Forest baseline for M2
  m2_run.py            train + score, writes the results JSON
  m2_supervised.py     M2 ablation 2: supervised fine-tune of the same DNS-BERT
  m1_xgb.py            M1 XGBoost + exact TreeSHAP explanations + validation threshold
  rf_baseline.py       Random Forest baseline for M1 (same features, same validation rows)
  m1_features.py       M1/RF feature matrix + CIC snaplen leakage guard
  host_features.py     per-host sliding-window features (past-only)
  m1_run.py            M1/RF train + score, writes results JSON + SHAP outputs
  m3_cnn.py, m3_bilstm.py, m3_common.py   M3 char-CNN + BiLSTM
contracts.py  validator + session/qtype helpers for the shared contracts (docs/contracts.md)
scripts/      time_models.py (one-CPU latency), make_synthetic_sample.py, parse_capture.py (quick capture check used by run_tool.sh),
              check_setup.py (setup check), m2_phase2.py, m2_ablation2.py, m2_e5.py, m2_error_analysis.py (M2 runs, docs/m2.md),
              external_baselines.py + external/ (Splunk's pretrained model and RITA, docs/external-baselines.md)
notebooks/    m2_dnsbert_colab.ipynb and m2_phase2_colab.ipynb (Colab GPU runs), m1_xgb_colab.ipynb (Colab CPU run)
results/      <model>/<experiment>.json in the shared results format; summary.csv, selection.csv, latency.csv,
              per_tool.csv and figures/ from python -m eval.summarise
results_nozone/  every model's result files on the masked testbed table (Experiments 1, 3, 5) and their
              selection.csv (docs/suffix-ablation.md)
results_external/  Splunk's pretrained model and RITA on the Experiment 1 test rows (docs/external-baselines.md)
docs/         per-component notes: contracts.md, m1.md, m2.md, m3.md, suffix-ablation.md, experiment-s.md, external-baselines.md
tests/        smoke tests
testbed/      lab network (docker compose), run_tool.sh, capture_matrix.sh
  benign/            benign traffic generator (Tranco, CDN names, curl, apt, browser)
  tools/             iodine, dnscat2, dns2tcp and DNSExfiltrator containers
parser/       python -m parser {cic,features,pcap,testbed}; `from parser import load; train, test = load("cic")`
eval/         shared evaluation module: splits, metrics, plots, run.py, summarise.py
data/         raw/, external/, processed/ (not committed; see data/README.md)
live/         live detector: python -m live -> live/alerts.db; live_test.sh and python -m live.report (live/README.md)
dashboard/    Streamlit app (planned; app.py is a placeholder)
```

## Shared contracts
Coding to these lets anyone rerun or take over anyone's part. The full field tables, allowed values and sources
are in [`docs/contracts.md`](docs/contracts.md). Check a table or results file with
`python contracts.py <file.parquet|file.json> ...`. To change the contract, follow
[Changing the contract](docs/contracts.md#changing-the-contract): extra fields need no approval, while changes to
shared fields go through a `contract:` issue and a versioned PR.
1. **Query table** `data/processed/<dataset>/queries.parquet`, one row per DNS query:
   `ts` (epoch s UTC), `src_host`, `session_id`, `qname`, `qtype`, `resp_size`, `rcode`, `label` (0/1), `tool`,
   `dataset`, `throttle` (ms); optional `split`, `qname_truncated`, `qlen_wire`, `source_file`.
2. **Model interface** `models/<name>.py`: `train(train_df, cfg=None) -> model`, `score(model, df) -> np.ndarray`
   (higher = more suspicious), `save(model, path)`, `load(path)`.
3. **Results** `results/<model>/<experiment>.json`: raw per-row `scores`, `labels`, `tools`, `src_hosts`, plus
   train time (s), per-query latency (ms), `score_meaning` and `config`. The shared evaluation module computes all
   metrics and plots; model owners never write metric code.

## Developer setup
Check what your machine is missing. Each failed line prints the exact command that fixes it:
```bash
python scripts/check_setup.py              # dev tools, M1 and M2 packages
python scripts/check_setup.py testbed data # Docker, and the data files the runners need
```
Install the linter and test runner with `pip install -r requirements-dev.txt`. Before you push:
```bash
ruff check --fix .      # bug rules, every file
ruff format new_file.py # formatting, only on files you added (old files get one cleanup after the freeze)
python -m pytest        # test files whose packages you don't have are skipped, with the install command
```
CI runs the same checks on every pull request. If a job fails, its summary says how to reproduce and fix it.

## One command per stage
Everything runs from the repo root after `pip install -r requirements.txt` (or one `requirements-<part>.txt`).
The user manual is built from these commands.

| Stage | Command | Status |
|---|---|---|
| Testbed network | `cd testbed && docker compose up -d` | ✅ |
| Benign traffic | `testbed/benign/run_benign.sh --hosts 4 --minutes 10 --docker` | ✅ |
| Tunnel traffic | `testbed/run_tool.sh --tool dns2tcp --size 100000 --rate 2000 --capture` | dns2tcp, DNSExfiltrator, iodine, dnscat2 ✅ (`testbed/tools/README.md`) |
| Capture runs | `testbed/capture_matrix.sh` (iodine + dnscat2 matrix with benign alongside), or `testbed/run_tool.sh ... --capture --manifest data/raw/manifest.csv` for any tool | ✅ (see "Quick start (capture runs)") |
| Parse CIC | `python -m parser cic --raw data/raw/cic --out data/processed/cic/queries.parquet` | ✅ |
| CIC features | `python -m parser features --dataset cic` -> `data/processed/cic/features.parquet` | ✅ |
| Parse testbed | `python -m parser testbed --capture <tool>.pcap[@<throttle ms>] ... --capture <resolver>.pcap` | ✅ (benign from a resolver capture) |
| Check a table | `python contracts.py data/processed/cic/queries.parquet` | ✅ |
| Train + score M1 / RF / IF / M3 | `python -m eval.run --model m1 --exp E3` | ✅ needs the query tables under `data/processed/`; won't overwrite existing results without `--overwrite` |
| Train + score M1 with SHAP | `python -m models.m1_run --model m1 --exp E2 --data data/processed/cic/queries.parquet` | ✅ |
| Train + score M2 | `python -m models.m2_run --model m2 --exp E2 --data ... --tranco data/external/tranco.csv` | ✅ |
| Metrics, plots, selection | `python -m eval.summarise` | ✅ |
| Live detector | `live/run_live.sh --at bridge` in the testbed, or `python -m live --pcap <capture>.pcap` | ✅ M1 by default (needs `artifacts/m1_xgb/E1.pt`): scores live traffic and writes alerts with their top SHAP features to `live/alerts.db` ([`live/README.md`](live/README.md)) |
| Live test + report | `live/live_test.sh`, then `python -m live.report` | ✅ 19 Nov run: all 1,720 tunnel queries flagged, 0 of 5,405 benign, median 0.43 s to alert ([`live/live_test.md`](live/live_test.md)) |
| Dashboard | `streamlit run dashboard/app.py` | placeholder (20 Nov) |

## Quick start (M2 on CIC)
Unzip each CIC PCAP zip into its own folder under `data/raw/cic/` (attack zips into a folder whose
name contains "attack"), then follow the Run section of [`docs/m2.md`](docs/m2.md#run) (local and Colab).

## Quick start (benign traffic generator)
```bash
cd testbed && docker compose up -d                                   # card-5 network
./benign/run_benign.sh --hosts 4 --minutes 10 --docker               # 10 min of benign lookups
python3 -m pytest testbed/benign/tests -q                            # from the repo root; no network needed
```
Writes `data/raw/benign/<run id>/<ip>.ndjson` sidecars in the query-table schema (see
Contracts) plus `run.json`; `check_benign.py` runs automatically and enforces the card's
acceptance bar. `--no-send` plans the lookups offline. Details: `testbed/benign/README.md`.

## Quick start (capture runs)
```bash
cd testbed && docker compose up -d       # the lab network
./capture_matrix.sh --dry-run            # list the runs
./capture_matrix.sh                      # iodine + dnscat2 matrix, benign traffic alongside
```
File names, the manifest, the parser command, capturing at the resolver by hand and why only one run
may use the lab at a time: [`testbed/tools/README.md`](testbed/tools/README.md#capture-runs-capture_matrixsh).

## Results
The shared evaluation module (`python -m eval.summarise`) reads the result files and writes the summary files
listed here; the tables in the docs are copied from them.

| What | Where |
|---|---|
| All metrics, one row per model and experiment | `results/summary.csv` |
| Selection rule applied per experiment | `results/selection.csv` |
| Per-query latency and training time | `results/latency.csv` (from `latency_cpu.csv`), `results/figures/latency.png` |
| Recall per tunnelling tool | `results/per_tool.csv` |
| ROC curves and confusion matrices | `results/figures/` |
| Write-up, error analysis and limits per model | [`docs/m1.md`](docs/m1.md), [`docs/m2.md`](docs/m2.md), [`docs/m3.md`](docs/m3.md) |
| Testbed runs with the lab domain hidden | [`docs/suffix-ablation.md`](docs/suffix-ablation.md), `results_nozone/` |
| Shuffled against time-based split | [`docs/experiment-s.md`](docs/experiment-s.md) |

Read these before quoting a number:
- **The lab domain gives the testbed away.** Every tunnel name in the testbed ends in `tunnel.test` and no benign
  name does, so a model that reads the name can separate the classes by the suffix alone. For M2 and M3, quote the
  runs with the domain hidden (`docs/suffix-ablation.md`).
- **CIC is easy.** It has one tool and no throttling, so every model is near perfect on Experiment 2. Experiments 3
  to 5 (leave-one-tool-out, cross-dataset, low-and-slow) are the real test.
- **A perfect ROC-AUC is not a perfect detector.** With dnscat2 held out, M1 reaches ROC-AUC 1.0 but
  catches only 22% of it at its own threshold (`docs/m1.md`). Quote recall at the model's threshold next to ROC-AUC.
- **Two selection tables.** `results/selection.csv` reads the original testbed runs, where M3 BiLSTM wins
  Experiments 1, 3 and 5 at F1 1.0, and its Experiment 3 score comes from the `tunnel.test` suffix. For the testbed
  experiments quote `results_nozone/selection.csv`, the same rule on the runs with the domain hidden: it picks M1
  for every run except dnscat2 held out, where it picks RF
  ([`docs/suffix-ablation.md`](docs/suffix-ablation.md), "Selection with the domain hidden").
- **Latency is timed on one CPU.** The 10 ms rule uses `results/latency_cpu.csv`: every model timed on the machine
  that runs the live detector (`python scripts/time_models.py`). There M2 takes 23 to 28 ms per query and fails the
  rule, while RF (8.1 ms) and the Isolation Forest (9.1 ms) pass. Each run's own timing, from Colab CPUs and GPUs,
  stays in `summary.csv`. This was added after the results freeze; the frozen selection is at the
  `results-freeze` tag.

## Timeline (SGT)
| Phase | Dates | Focus |
|---|---|---|
| 1 | 12–14 Nov | Contracts, parser, eval module, all models built on CIC |
| 2 | 15–17 Nov | Testbed captures, Experiments 1–4, checkpoint 16 Nov 21:00 |
| 3 | 18 Nov | Experiment 5 (low-and-slow), ablations, **results freeze 18 Nov 23:59** (git tag `results-freeze`) |
| 4 | 19–22 Nov | Live detector, dashboard, report, slides, user manual, submit 22 Nov |

Hard deadline 23 Nov 23:59 (late penalty 20%/day). No live demo: the dashboard and live detector are
shown as a recorded video.

## Team
| Member | Main responsibilities |
|---|---|
| Tan Yehan | Contracts, parser + features + splits, results freeze, report editor, submission |
| Justin Hiap | Testbed network, iodine + dnscat2, live sniffer |
| Joshua Tan | M1 (XGBoost + Random Forest + SHAP), report skeleton, user manual |
| Kang Hao Wei | Benign traffic generator, dns2tcp + DNSExfiltrator, reproduction test, demo video |
| Thierry Tang | M2 (DNS-BERT + Isolation Forest), presentation slides |
| Neo Chuan Yu | Shared evaluation module, M3 (char-CNN + BiLSTM), dashboard, code tidy |

## Ethics
All attack traffic is generated by the team on machines we control inside an isolated network, using
public open-source tools. No real user data is collected. Public datasets are used under their licences
and cited in the report.
