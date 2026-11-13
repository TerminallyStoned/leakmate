# leakmate

**Detecting DNS tunnels with supervised, unsupervised and language-model detectors.**
ICT3214 Security Analytics, Coursework 2 · Group 32 · Singapore Institute of Technology

DNS is allowed out of almost every network, so attackers hide stolen data and C2 traffic in DNS
query names. Off-the-shelf tunnelling tools are easy to catch; tunnels from unseen tools, or ones that
send data slowly, are not. This project builds a contained testbed that generates labelled tunnel
traffic, compares three ML/AI detectors on it and on a public benchmark, and runs the best one on live
DNS traffic behind a dashboard.

> Status: **Phase 1 (build on CIC)**. Sections marked *planned* are not in the repo yet.
> The plan and owners live on the team Trello board **ICT3214**.

## Research questions
- **RQ1** Which model gives the best trade-off between detection, false positives and speed?
- **RQ2** How much does detection drop on tunnelling tools absent from training?
- **RQ3** Can a benign-only model (M2) match supervised models, especially on unseen tools?

## Models
| | Model | Supervision | Baseline | Status |
|---|---|---|---|---|
| **M1** | XGBoost on per-query + per-host features, SHAP explanations | supervised | Random Forest | ✅ Phase 1 code ([`docs/m1.md`](docs/m1.md)) |
| **M2** | DNS-BERT: small BERT trained only on benign names; flags high pseudo-perplexity | benign-only | Isolation Forest | ✅ Phase 1 done |
| **M3** | Character-level CNN on the raw query name | supervised | BiLSTM | code in `models/m3_*.py`, no results yet |

Selection rule: best F1 with false-positive rate < 1% and latency < 10 ms per query.

> Note: numbering follows the Trello board. The proposal numbered the models differently
> (autoencoder as M2, the leakage/language-model detector as M3); the report uses the board's numbering.

## Experiments
| ID | Experiment |
|---|---|
| E1 | Within-testbed (train and test on our testbed data) |
| E2 | CIC benchmark, compared with published results |
| E3 | Leave-one-tool-out (unseen tools, RQ2) |
| E4 | Cross-dataset (CIC ↔ testbed) |
| E5 | Low-and-slow tunnels |
| S  | Shuffled vs time-based split (how much shuffling inflates scores) |

All splits are time/session based, never shuffled rows (except in S).

## Data
- **CIC-Bell-DNS-EXF-2021** (University of New Brunswick): public benchmark, DNSExfiltrator attacks.
  Download the **PCAP** folder (registration required): https://www.unb.ca/cic/datasets/dns-exf-2021.html.
  ⚠️ Captured with snaplen = 96 B: exfil query names are truncated to ~40 chars and lose their qtype.
  Details in [`docs/m2.md`](docs/m2.md).
- **Testbed** (*partial*): closed Docker network with resolver + authoritative server generating labelled
  traffic from iodine, dnscat2, dns2tcp and DNSExfiltrator, plus benign traffic (Tranco, apt, curl,
  browser). Containment is tested so no traffic leaves the network. Available now: the network itself
  ([`testbed/`](testbed/README.md)) and the benign generator ([`testbed/benign/`](testbed/benign/README.md));
  the four tunnel tools are in progress.
- **Tranco** top-1M list: benign domain names (https://tranco-list.eu).

Raw data, processed data and model weights are **not** committed (see `.gitignore`); scripts regenerate them.

## Repository layout
```
models/       model code, one file per model: train / score / save / load
  m2_dnsbert.py        M2 DNS-BERT (BPE + char tokenizers, batched pseudo-perplexity)
  iforest_baseline.py  Isolation Forest baseline for M2
  m2_run.py            train + score, writes the results JSON
  m1_xgb.py            M1 XGBoost + exact TreeSHAP explanations
  rf_baseline.py       Random Forest baseline for M1 (same features)
  m1_features.py       M1/RF feature matrix + CIC snaplen leakage guard
  host_features.py     per-host sliding-window features (past-only)
  m1_run.py            M1/RF train + score, writes results JSON + SHAP outputs
contracts.py  validator + session/qtype helpers for the shared contracts (docs/contracts.md)
scripts/      cic_to_queries.py (CIC pcaps -> query table, stopgap until parser/), make_synthetic_sample.py
notebooks/    m2_dnsbert_colab.ipynb (Colab GPU run), m1_xgb_colab.ipynb (Colab CPU run)
results/      <model>/<experiment>.json in the shared results format
docs/         per-component notes (m2.md)
tests/        smoke tests
testbed/
  benign/            benign traffic generator (Tranco, CDN names, curl, apt, browser)
  m3_cnn.py, m3_bilstm.py, m3_common.py   M3 char-CNN + BiLSTM
parser/       python -m parser {cic,pcap,testbed}: captures -> query table (wraps the scripts/ stopgaps for now)
eval/         shared evaluation module: splits, metrics, plots, run.py, summarise.py
data/         raw/, external/, processed/ (not committed; see data/README.md)
live/         live detector (planned)
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
| Tunnel traffic | `testbed/run_tool.sh --tool dns2tcp --size 100000 --rate 2000 --capture` | dns2tcp, DNSExfiltrator ✅; iodine, dnscat2 planned |
| Parse CIC | `python -m parser cic --raw data/raw/cic --out data/processed/cic/queries.parquet` | ✅ (stopgap inside) |
| Parse testbed | `python -m parser testbed --add <run dir> ... --out data/processed/testbed/queries.parquet` | ✅ (stopgap inside) |
| Check a table | `python contracts.py data/processed/cic/queries.parquet` | ✅ |
| Train + score M1 / RF / IF / M3 | `python -m eval.run --model m1 --exp E3` | needs testbed data; won't overwrite existing results without `--overwrite` |
| Train + score M1 with SHAP | `python -m models.m1_run --model m1 --exp E2 --data data/processed/cic/queries.parquet` | ✅ |
| Train + score M2 | `python -m models.m2_run --model m2 --exp E2 --data ... --tranco data/external/tranco.csv` | ✅ |
| Metrics, plots, selection | `python -m eval.summarise` | ✅ |
| Live detector | `python -m live` | planned (19 Nov) |
| Dashboard | `streamlit run dashboard/app.py` | placeholder (20 Nov) |

## Quick start (M2 on CIC)
```bash
pip install -r requirements-m2.txt
# unzip each CIC PCAP zip into its own folder under data/raw/cic/
# (attack zips into a folder whose name contains "attack", e.g. data/raw/cic/heavy_attacks), then:
python -m parser cic --raw data/raw/cic --out data/processed/cic/queries.parquet
python -m models.m2_run --model m2 --exp E2 --data data/processed/cic/queries.parquet \
    --tranco data/external/tranco.csv --tokenizer bpe
python -m models.m2_run --model m2 --exp E2 --tokenizer char --tag ablation1_char \
    --data data/processed/cic/queries.parquet --tranco data/external/tranco.csv
python -m models.m2_run --model iforest --exp E2 --data data/processed/cic/queries.parquet
python -m pytest tests -q
```
On Google Colab: open `notebooks/m2_dnsbert_colab.ipynb`, choose a T4 GPU, Run all
(reads the zips from `MyDrive/ICT3214 datasets`).

## Quick start (benign traffic generator)
```bash
cd testbed && docker compose up -d                                   # card-5 network
./benign/run_benign.sh --hosts 4 --minutes 10 --docker               # 10 min of benign lookups
python3 -m pytest testbed/benign/tests -q                            # from the repo root; no network needed
```
Writes `data/raw/benign/<run id>/<ip>.ndjson` sidecars in the query-table schema (see
Contracts) plus `run.json`; `check_benign.py` runs automatically and enforces the card's
acceptance bar. `--no-send` plans the lookups offline. Details: `testbed/benign/README.md`.

## Results so far (E2, CIC)
From the shared evaluation module (`python -m eval.summarise`); M2 latency measured on an RTX 4060.

| Model | F1 | ROC-AUC | Latency / query |
|---|---|---|---|
| M2 DNS-BERT (BPE) | 0.9980 | 0.99998 | 5.2 ms |
| M2 DNS-BERT (char, ablation 1) | 0.9979 | 1.00000 | 6.3 ms |
| Isolation Forest | 0.9980 | 1.00000 | 20.1 ms (excl. feature extraction) |

M1 results: see `docs/m1.md`.

CIC contains one tool and no throttling, so it is near-trivially separable; E3–E5 on the testbed are the
real test.

## Timeline (SGT)
| Phase | Dates | Focus |
|---|---|---|
| 1 | 12–14 Nov | Contracts, parser, eval module, all models built on CIC |
| 2 | 15–17 Nov | Testbed captures, E1–E4, checkpoint 16 Nov 21:00 |
| 3 | 18 Nov | E5, ablations, **results freeze 18 Nov 23:59** (git tag `results-freeze`) |
| 4 | 19–22 Nov | Live detector, dashboard, report, slides, user manual, submit 22 Nov |

Hard deadline 23 Nov 23:59 (late penalty 20%/day). No live demo: the dashboard and live detector are
shown as a recorded video.

## Team
| Member | Main responsibilities |
|---|---|
| Tan Yehan | Contracts, parser + features + splits, results freeze, report editor, submission |
| Justin Hiap | Testbed network, iodine + dnscat2, live sniffer, demo video |
| Joshua Tan | M1 (XGBoost + Random Forest + SHAP), report skeleton, user manual |
| Kang Hao Wei | Benign traffic generator, dns2tcp + DNSExfiltrator, reproduction test |
| Thierry Tang | M2 (DNS-BERT + Isolation Forest), presentation slides |
| Neo Chuan Yu | Shared evaluation module, M3 (char-CNN + BiLSTM), dashboard, code tidy |

## Ethics
All attack traffic is generated by the team on machines we control inside an isolated network, using
public open-source tools. No real user data is collected. Public datasets are used under their licences
and cited in the report.
