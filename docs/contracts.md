# Shared contracts

**Version 1.0.0** · agreed 13 Nov 2026 · owner Tan Yehan (backup Kang Hao Wei)

## What this is and why it exists

leakmate is built by six people, each owning one part. The parts hand data to each other in three places:

```
 pcap captures ──► parser ──► (1) query table ──► model train/score ──► (3) results file ──► evaluation ──► metrics, plots, report
 (CIC, testbed)                .parquet           (2) model interface    .json                module
```

A **contract** is the agreed format at one of those handoffs: the file name, the columns or keys, their types and
units, and what each value means. As long as each part writes and reads exactly this format:
- nobody waits for anybody else: build against the format with the synthetic sample before real data exists;
- CIC and testbed data are interchangeable, so every model runs on both;
- anyone can take over or rerun anyone's part;
- every model is evaluated by the same code.

The format is checked by code, not by trust: `contracts.py` rejects a file that breaks it and says exactly what to fix.

## Which sections you need

| you are working on | you write | you read |
|---|---|---|
| parser, testbed, CIC extractor | §1 query table | — |
| a model (M1, M2, M3, baselines) | §2 model interface, §3 results file | §1 query table |
| evaluation module, dashboard, report | — | §3 results file |
| anything, and the contract seems wrong or missing something | — | [Changing the contract](#changing-the-contract) |

## How to check your files

```bash
python contracts.py data/processed/cic/queries.parquet results/m1/E2.json
```
prints `ok` for each valid file, or lists every problem with its fix. The same checks from Python:

```python
from contracts import validate, assign_sessions, qtype_name
validate(df)        # a query-table DataFrame
validate(result)    # a results dict
```
`assign_sessions(df)` builds the `session_id` column and `qtype_name(code)` turns a numeric record type into its
name. Use them rather than writing your own.

For a test table without real data, run `python scripts/make_synthetic_sample.py`; it writes 1,000 valid rows to
`data/sample/synthetic_queries.parquet`.

## 1. Query table

- **File:** `data/processed/<dataset>/queries.parquet`, one row per DNS query a client sent, in any row order.
- **Written by:** the parser (testbed pcaps), `parser/cic.py` (CIC pcaps, `python -m parser cic`), `scripts/make_synthetic_sample.py` (tests).
- **Read by:** every model, for training and scoring.
- **Why it's fixed:** CIC and testbed data look identical to the models, so any model runs on either dataset unchanged.

Example rows (from the synthetic sample; the iodine name is cut short here):

| ts | src_host | session_id | qname | qtype | resp_size | rcode | label | tool | dataset | throttle |
|---|---|---|---|---|---|---|---|---|---|---|
| 1700000000.372 | 10.0.0.28 | synthetic/sample.pcap\|10.0.0.28\|0 | python.org | A | 44 | 0 | 0 | benign | synthetic | 0 |
| 1700000000.903 | 10.0.0.50 | synthetic/sample.pcap\|10.0.0.50\|0 | hrxe3hvbuws4…tunnel.test | NULL | 283 | 0 | 1 | iodine | synthetic | 0 |

"Required" means the validator rejects the table without that column. Extra columns (for example model features)
are allowed and ignored.

| column | dtype | req. | meaning and allowed values |
|---|---|---|---|
| `ts` | float64 | yes | query time, **epoch seconds, UTC** (the pcap timestamp). 0 ≤ ts < 2³², the range of pcap's 32-bit seconds field. |
| `src_host` | string | yes | IP address of the client that sent the query |
| `session_id` | string | yes | `<capture>\|<src_host>\|<k>`, see [Sessions](#sessions) |
| `qname` | string | yes | query name as seen on the wire: case kept, **no trailing dot**, not empty. On CIC it may be truncated. |
| `qtype` | string | yes | record type mnemonic (`A`, `AAAA`, `TXT`, `NULL`, `CNAME`, `HTTPS`, …). An unmapped code becomes `TYPE<n>` (RFC 3597), and a type lost to truncation becomes `UNKNOWN`. Use `qtype_name(code)`. |
| `resp_size` | int64 | yes | DNS payload bytes of the matching response; **0 = no response seen** |
| `rcode` | int64 | yes | the 4-bit header RCODE, 0–15; **-1 = no response seen**. `rcode == -1` exactly when `resp_size == 0`. |
| `label` | int64 | yes | `1` tunnel or exfiltration query, `0` benign |
| `tool` | string | yes | `benign`, `iodine`, `dnscat2`, `dns2tcp` or `dnsexfiltrator`. `benign` exactly when `label == 0`. |
| `dataset` | string | yes | `cic`, `testbed` or `synthetic` |
| `throttle` | int64 | yes | configured delay between consecutive tunnel queries, **in milliseconds**. 0 = tool default, and always 0 on benign rows. |
| `split` | string | no | `train` or `test`, decided by time within each capture, never by shuffling rows |
| `qname_truncated` | bool | no | the name was cut off by the capture snaplen (CIC) |
| `qlen_wire` | int64 | no | UDP payload bytes of the query: the true size even when `qname` is truncated |
| `source_file` | string | no | the capture the row came from, e.g. `heavy_attacks/x.pcap`. The testbed parser should fill it too. |

### Sessions

`session_id = "<capture>|<src_host>|<k>"`, where `<capture>` is `source_file` (or `dataset` if the table has no
`source_file`). `k` starts at 0 and goes up by one whenever that host's previous query in that capture was more
than **1800 s** earlier. `assign_sessions(df)` is the only implementation; the validator checks the column against it.
Splits that hold out whole groups (leave-one-session-out, `GroupKFold`) group on `session_id`.

### Throttle

`throttle` records the delay the testbed script configured, so Experiment 5 (low-and-slow) can bin results by it:
DNSExfiltrator `t=<ms>` (default 0), dnscat2 `--delay <ms>` (default 1000), and iodine `-I <s>` multiplied by 1000
(default 4 s).

## 2. Model interface

- **File:** one Python module per model, `models/<name>.py`.
- **Written by:** each model owner (M1, M2, M3 and their baselines).
- **Read by:** the runners, the live detector and the dashboard. They call these four functions and nothing else.
- **Why it's fixed:** any model can be trained, swapped or taken over without reading its internals.

Each model module exposes:

| function | contract |
|---|---|
| `train(train_df, cfg=None) -> model` | `train_df` is a query table, plus feature columns if the model needs them. Benign-only models (M2, Isolation Forest) drop `label == 1` rows themselves. |
| `score(model, df) -> np.ndarray` | float array of shape `(len(df),)`, finite, in `df`'s row order. **Higher = more suspicious.** Must not read `label`, `tool`, `split` or `throttle`. |
| `save(model, path) -> None` | writes everything `load` needs |
| `load(path) -> model` | `score(load(p), df)` equals `score(model, df)` |

Extra parameters are allowed only if they have defaults (for example `load(path, device=None)`).

## 3. Results file

- **File:** `results/<model>/<experiment>[_<tag>].json`, one per run (for example `results/m1/E2.json`).
- **Written by:** each model's runner (`models/m1_run.py`, `models/m2_run.py`, …) after scoring the test set.
- **Read by:** the shared evaluation module, which computes every metric and plot, and the report.
- **Why it's fixed:** every model is measured by the same code, so the comparison is fair. That is why the file holds
raw scores and per-row details, never metrics or thresholded labels.

Example with made-up values, cut to 3 test rows:

```json
{"model": "m1", "experiment": "E2", "dataset": ["cic"], "split": "split_column", "n_train": 263819, "n_test": 3,
 "scores": [0.02, 0.97, 0.01], "labels": [0, 1, 0], "tools": ["benign", "dnsexfiltrator", "benign"],
 "src_hosts": ["192.168.1.5", "192.168.1.9", "192.168.1.5"], "train_time_s": 1.28, "latency_ms_per_query": 13.6,
 "score_meaning": "XGBoost P(tunnel)", "config": {"seed": 42}, "created_utc": "2026-11-13T01:59:04+00:00"}
```

| key | type | req. | meaning |
|---|---|---|---|
| `model` | str | yes | model name, plus `_<tag>` for ablations |
| `experiment` | str | yes | `E1`, `E2`, `E3`, `E4`, `E5` or `S` |
| `dataset` | list[str] | yes | datasets in the test set, drawn from the `dataset` values |
| `split` | str | yes | how train and test were cut, e.g. `split_column`, `time_70_30`, `train=<path>;test=<path>` |
| `n_train`, `n_test` | int | yes | row counts |
| `scores` | list[float] | yes | raw score per test row, higher = more suspicious |
| `labels` | list[int] | yes | 0/1 per test row |
| `tools` | list[str] | yes | `tool` per test row (per-tool breakdowns and Experiment 3, leave-one-tool-out) |
| `src_hosts` | list[str] | yes | `src_host` per test row (per-host metrics) |
| `train_time_s` | number | yes | wall-clock training time |
| `latency_ms_per_query` | number | yes | mean time to score one query (batch of 1) |
| `score_meaning` | str | yes | what the score is, e.g. `XGBoost P(tunnel)` |
| `config` | dict | yes | every setting needed to rerun |
| `created_utc` | str | yes | ISO 8601 with time zone, `datetime.now(timezone.utc).isoformat(timespec="seconds")` |
| `session_ids` | list[str] | **before Experiments 3 and 5** | `session_id` per test row (per-session metrics) |
| `ts` | list[float] | **before Experiments 3 and 5** | `ts` per test row (Experiment 5 time to detect) |

All per-row lists have length `n_test`, in the same order. Any other key (`feature_cols`, `shap`, `info_bits`,
`score_time_s`, …) is allowed. `session_ids` and `ts` are optional now and become required before Experiment 3 and 5 runs.

## Changing the contract

If the contract is wrong, or it doesn't hold something you need, **don't work around it in your own branch**:
renaming or reinterpreting a shared column silently breaks everyone who reads it. Use one of the two paths below.

### You only need extra data: no approval

Add it as an **extra column** in the query table, or an **extra key** in the results JSON. Both are already allowed
and the validator ignores them. Examples are M1's `f_*` feature columns and M2's `info_bits`. Nothing else may
depend on an extra field. If another part starts to need it, propose it as an optional field (next section).
ODCS handles extensions the same way, with `customProperties` kept apart from the defined schema.

### You need the contract itself to change: propose it

1. **Open a GitHub issue** titled `contract: <one-line change>`, and post the link on the Trello contracts card.
   In the issue, say:
   - what to change;
   - why: the problem, with an example row or file;
   - which parts it affects: parser, testbed, M1, M2, M3, eval or dashboard;
   - whether it is compatible or breaking (table below).

   This follows the Architecture Decision Record format: context, decision, consequences.
2. **Classify it** with Semantic Versioning, using the compatibility rules schema registries apply:

   | change | examples | version bump | approval |
   |---|---|---|---|
   | **Patch**: what is valid doesn't change | clearer wording, a fix-it hint, a validator bug that rejected valid data | 1.0.**x** | contract owner |
   | **Minor**: compatible, everything valid stays valid | add an *optional* column or key; add an allowed value (e.g. a new `tool`); loosen a check | 1.**x**.0 | contract owner + owners of the affected parts |
   | **Major**: breaking, existing data or code may become invalid | rename or remove a column or key; change a dtype, unit or meaning; make an optional field required; narrow allowed values; change `session_id` or `assign_sessions` | **x**.0.0 | **every** part owner (Yehan, Justin, Joshua, Kang Hao Wei, Thierry, Neo) |

3. **One pull request does the whole change**:
   - edit this doc and bump the version line;
   - update `CONTRACT_VERSION` and the checks in `contracts.py`;
   - update `tests/test_contracts.py`;
   - update every producer (`parser/cic.py`, the testbed parser, `scripts/make_synthetic_sample.py`);
   - add a changelog entry below.

   For a **major** change the PR also lists what must be regenerated or rerun (for example "rebuild the CIC parquet,
   rerun Experiment 2"), and its owners do that before it merges. `python contracts.py data/processed/*/queries.parquet results/*/*.json`
   must print `ok` for every file.
4. **Deprecate before removing** where time allows: mark the field deprecated in a minor release, and remove it in
   the next major one. Semantic Versioning requires deprecations to be announced in a minor release.
5. **Freeze:** no major changes after the results freeze (18 Nov 23:59, git tag `results-freeze`). After it, only
   patch changes go in, so frozen results stay valid.

Not sure which path applies? Open the issue anyway. Asking costs less than a silent mismatch found after the freeze.

### Changelog

| version | date | change |
|---|---|---|
| 1.0.0 | 13 Nov 2026 | First agreed contract |

### Where this process comes from

- Semantic Versioning 2.0.0, https://semver.org: MAJOR for incompatible changes, MINOR for backward-compatible
  additions and for marking features deprecated, PATCH for backward-compatible fixes.
- Confluent Schema Registry, *Schema Evolution and Compatibility*,
  https://docs.confluent.io/platform/current/schema-registry/fundamentals/schema-evolution.html: adding or removing an
  optional field (one with a default) is compatible; adding or removing a required field is not.
- Open Data Contract Standard (Bitol, a Linux Foundation project), https://bitol.io: a versioned data contract;
  changes go through RFCs; extensions go in `customProperties`, not the defined schema.
- M. Nygard, *Documenting Architecture Decisions* (2011), see https://www.martinfowler.com/bliki/ArchitectureDecisionRecord.html:
  record each significant decision with its context, decision and consequences, kept in the repository.
- The approval levels (owner, affected owners, everyone) and the freeze rule are **this team's choice**. We found no
  standard that sets who approves; it follows the project's owners table and timeline in the README.


## Why these choices

Every rule above, and every number in it, is backed in [contracts-evidence.md](contracts-evidence.md), which cites
Zeek, ECS, OCSF, the DNS RFCs, CIC-Bell-DNS-EXF-2021, published papers and the tunnelling tools' source code.
It also marks which choices are team decisions with no source.
