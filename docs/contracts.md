# Shared contracts

Every part of leakmate codes to these three contracts, so anyone can rerun or take over anyone's part and CIC
and testbed tables are interchangeable. Agreed 13 Nov 2026 (Trello: *[Yehan] CONTRACTS*).

`contracts.py` (repo root) checks them and names each problem with its fix:

```python
from contracts import validate, assign_sessions, qtype_name
validate(df)        # query-table DataFrame
validate(result)    # results dict
```
```bash
python contracts.py data/processed/cic/queries.parquet results/*/*.json
```

## 1. Query table

`data/processed/<dataset>/queries.parquet`: one row per DNS query (client to resolver), any row order.
Extra columns (for example model features) are allowed.

| column | dtype | req. | meaning and allowed values |
|---|---|---|---|
| `ts` | float64 | yes | query time, **epoch seconds, UTC** (the pcap timestamp). Must fall in 2000–2100. |
| `src_host` | string | yes | IP address of the client that sent the query |
| `session_id` | string | yes | `<capture>\|<src_host>\|<k>`, see [Sessions](#sessions) |
| `qname` | string | yes | query name as seen on the wire: case kept, **no trailing dot**, not empty. On CIC it may be truncated. |
| `qtype` | string | yes | record type mnemonic (`A`, `AAAA`, `TXT`, `NULL`, `CNAME`, `HTTPS`, …). An unmapped code becomes `TYPE<n>` (RFC 3597), and a type lost to truncation becomes `UNKNOWN`. Use `qtype_name(code)`. |
| `resp_size` | int64 | yes | DNS payload bytes of the matching response; **0 = no response seen** |
| `rcode` | int64 | yes | response code 0–15; **-1 = no response seen**. `rcode == -1` exactly when `resp_size == 0`. |
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

`throttle` records the delay the testbed script configured, so E5 can bin results by it:
DNSExfiltrator `t=<ms>`, dnscat2 `--delay <ms>`, and iodine `-I <s>` multiplied by 1000.

## 2. Model interface

Each model module (`models/<name>.py`) exposes:

| function | contract |
|---|---|
| `train(train_df, cfg=None) -> model` | `train_df` is a query table, plus feature columns if the model needs them. Benign-only models (M2, Isolation Forest) drop `label == 1` rows themselves. |
| `score(model, df) -> np.ndarray` | float array of shape `(len(df),)`, finite, in `df`'s row order. **Higher = more suspicious.** Must not read `label`, `tool`, `split` or `throttle`. |
| `save(model, path) -> None` | writes everything `load` needs |
| `load(path) -> model` | `score(load(p), df)` equals `score(model, df)` |

Extra parameters are allowed only if they have defaults (for example `load(path, device=None)`).

## 3. Results record

`results/<model>/<experiment>[_<tag>].json`: one file per run. The shared evaluation module computes every
metric from it, so it must hold raw scores and per-row metadata, not thresholded labels.

| key | type | req. | meaning |
|---|---|---|---|
| `model` | str | yes | model name, plus `_<tag>` for ablations |
| `experiment` | str | yes | `E1`, `E2`, `E3`, `E4`, `E5` or `S` |
| `dataset` | list[str] | yes | datasets in the test set, drawn from the `dataset` values |
| `split` | str | yes | how train and test were cut, e.g. `split_column`, `time_70_30`, `train=<path>;test=<path>` |
| `n_train`, `n_test` | int | yes | row counts |
| `scores` | list[float] | yes | raw score per test row, higher = more suspicious |
| `labels` | list[int] | yes | 0/1 per test row |
| `tools` | list[str] | yes | `tool` per test row (per-tool breakdowns and E3) |
| `src_hosts` | list[str] | yes | `src_host` per test row (per-host metrics) |
| `train_time_s` | number | yes | wall-clock training time |
| `latency_ms_per_query` | number | yes | mean time to score one query (batch of 1) |
| `score_meaning` | str | yes | what the score is, e.g. `XGBoost P(tunnel)` |
| `config` | dict | yes | every setting needed to rerun |
| `created_utc` | str | yes | ISO 8601 with time zone, `datetime.now(timezone.utc).isoformat(timespec="seconds")` |
| `session_ids` | list[str] | **before E3/E5** | `session_id` per test row (per-session metrics) |
| `ts` | list[float] | **before E3/E5** | `ts` per test row (E5 time to detect) |

All per-row lists have length `n_test`, in the same order. Any other key (`feature_cols`, `shap`, `info_bits`,
`score_time_s`, …) is allowed. `session_ids` and `ts` are optional now and become required before E3/E5 runs.

## Evidence

| choice | source | what it says |
|---|---|---|
| `ts` in epoch seconds, client address, qname, string qtype, integer rcode; response fields optional | Zeek `DNS::Info` record, https://docs.zeek.org/en/master/scripts/base/protocols/dns/main.zeek.html | `ts` is a `time`; `query`, `qtype_name`, `rcode`, `rtt` and `answers` are all `&optional`, so "no response seen" is a normal state and needs a defined value |
| qtype as a mnemonic string | Elastic Common Schema, DNS fields, https://www.elastic.co/docs/reference/ecs/ecs-dns | `dns.question.type` is a keyword such as `AAAA`; `dns.question.name` is the queried name |
| integer rcode, string type, client endpoint | OCSF 1.3.0 DNS Activity (class 4003), https://schema.ocsf.io/1.3.0/classes/dns_activity | `query.hostname` is required, `query.type` is a string, `rcode_id` is an integer, `src_endpoint` is the client |
| `TYPE<n>` for unmapped codes | RFC 3597 §5, https://rfc-editor.org/rfc/rfc3597 | unknown types are written as "TYPE" followed by the decimal type number |
| per-query rows labelled by tool | Palau et al., *DNS Tunneling: A Deep Learning based Lexicographical Detection Approach*, arXiv:2006.06122 | a CNN on the domain name only; tunnel queries from dnscat2, iodine and DNSExfiltrator labelled by attacker domain and run time |
| raw CIC fields and labels | Mahdavifar et al., *Lightweight Hybrid Detection of Data Exfiltration using DNS based on Machine Learning*, ICCNS 2021; dataset page https://www.unb.ca/cic/datasets/dns-exf-2021.html | PCAPs plus per-packet CSV features, labelled by timestamp. Their split is a shuffled 70/30, which experiment S measures. |
| query name, response and record type as inputs; time-based training | Nadler, Aminov & Shabtai, *Detection of malicious and low throughput data exfiltration over the DNS protocol*, Computers & Security 80, 2019, arXiv:1709.08395 | per-domain features over 60-minute collection sets; trained on the first day of traffic, tested on the rest |
| time and session splits, never shuffled rows | Arp et al., *Dos and Don'ts of Machine Learning in Computer Security*, USENIX Security 2022; Pendlebury et al., *TESSERACT*, USENIX Security 2019 | mixing past and future samples ("temporal snooping") overestimates detectors; respect time when splitting |
| `split` and `config` in every results record | Kapoor & Narayanan, *Leakage and the reproducibility crisis in machine-learning-based science*, Patterns 4(9), 2023 | eight kinds of leakage; record how data was split and prepared ("model info sheets") |
| group-aware splits need a group column | scikit-learn `model_selection`, https://scikit-learn.org/stable/api/sklearn.model_selection.html | `GroupKFold` keeps each group on one side; `TimeSeriesSplit` respects time but ignores groups |
| session = 30 min of inactivity | Google Analytics help, *About Analytics sessions*, https://support.google.com/analytics/answer/2731565 | a session lasts until 30 minutes of inactivity, the most widely used session rule |
| why not a flow id (Zeek `uid`, Community ID) | Community ID spec, https://github.com/corelight/community-id-spec; RFC 5452, https://www.rfc-editor.org/rfc/rfc5452 | both identify a 5-tuple including ports; resolvers randomise the source port per query, so for UDP DNS a flow is about one query |
| a live tunnel never idles for 30 min | iodine(8), https://www.mankier.com/8/iodine | `-I` defaults to 4 s; iodined drops a client after 60 s idle |
| `throttle` in milliseconds | DNSExfiltrator README, https://github.com/Arno0x/DNSExfiltrator; dnscat2 client docs, https://www.kali.org/tools/dnscat2 | `throttleTime` is "the time in milliseconds to wait between each DNS request"; dnscat2 `--delay <ms>` defaults to 1000 |

**Design judgements without a source:** `resp_size = 0` and `rcode = -1` as the no-response markers (kept from the
CIC extractor so M1's features don't change); the 2000–2100 range check on `ts`; the exact list of required
results keys, which is what both runners already wrote on 13 Nov 2026.
