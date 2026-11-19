# Live detector

Sniffs DNS, scores every query with the trained model as it is seen and writes alerts, each with its top SHAP
features, to `live/alerts.db` (SQLite), which the dashboard reads. Owner: Justin · Backup: Yehan · Trello:
"[Justin] Live sniffer service skeleton" and "[Justin] Live detector end to end with SHAP alerts".

**Status (19 Nov):** M1 (XGBoost), the model the selection picks with the lab domain hidden
(`results_nozone/selection.csv`), runs live in the testbed. Results of the live test are under
"Live test" below.

## The model
**M1 is the default.** With no `--model`, the detector loads M1 from `artifacts/m1_xgb/E1.pt`: M1 trained on
the testbed training split, the model behind `results/m1/E1.json`. It carries its own threshold (0.4999, chosen
on validation data), so no `--threshold` is needed. That file is committed (123 KB), so
this works from a fresh clone. To use a model you trained yourself instead:

```bash
# retrain (about 30 s, needs data/processed/testbed); writes artifacts/live/m1_xgb/E1.pt, not results/,
# so then add --weights artifacts/live/m1_xgb/E1.pt
python -m eval.run --model m1 --exp E1 --results-dir /tmp/live
```

If the file is missing the detector stops and prints how to get it. It never falls back to another scorer.

- `--weights <file>` loads a different M1 file.
- `--model <name> --weights <file>` loads another model through the contract interface (`models/<name>.py`).
  Only M1 has been run live. Alerts carry explanations only if the model's module has `explain`, which M1 does
  (exact TreeSHAP). M2 and the Isolation Forest keep their threshold in the results file, so they need
  `--threshold`; M2 also takes 23 to 28 ms per query on a CPU (`results/latency_cpu.csv`), which is why it is
  not the live model.
- `--model dummy` is a placeholder that scores a name by its length alone, for testing the pipeline without a
  model. It is not a detector.

## Run it

```bash
# Replay a capture file. No root, no Scapy: needs only requirements-m1.txt.
python -m live --pcap data/raw/tools/<capture>.pcap
python -m live --pcap <capture>.pcap --speed 1          # at the recorded pace

# In the testbed (docker compose up -d in testbed/ first). Builds a small image the first time.
live/run_live.sh                                        # at the resolver
live/run_live.sh --at bridge                            # on the lab bridge: every lab host at once
live/run_live.sh --at dns2tcp-client                    # inside one container's network

# On any Linux interface. Needs root and requirements-live.txt (Scapy, libpcap).
sudo python -m live --iface eth0

# What a run detected and how fast, as Markdown (reads live/alerts.db)
python -m live.report

# The whole live test in one command: sniffer, benign hosts, all four tools, report (about 14 minutes)
live/live_test.sh
```

Then, in another terminal, start a tunnel (`testbed/run_tool.sh --tool dnscat2 --size 8192`) and look:

```bash
sqlite3 live/alerts.db "SELECT datetime(ts, 'unixepoch'), src_host, substr(qname, 1, 50), score FROM alerts ORDER BY id DESC LIMIT 5"
```

The sniffer prints one status line every 10 seconds (queries seen, alerts written, the last alert).
`live/alerts.db` is not committed. Delete it to start empty; a new run appends to an existing file.

## Live test (19 Nov): the trained model on traffic generated live
`live/live_test.sh` starts the lab, puts one sniffer with M1 on the lab bridge, runs two benign hosts for 6 minutes
and, alongside them, each tunnel tool in turn: dnscat2 (4,096 bytes at 5 queries/s), iodine (65,536 bytes),
dns2tcp (16,384 bytes), DNSExfiltrator (4,096 bytes at 5 queries/s) and a low-and-slow dnscat2 session (one
query every 5 s). Nothing is replayed: every query is generated while the detector runs, and the model was
trained on the 15 Nov captures. All four tools completed their transfers. The full output of the run is
[`live_test.md`](live_test.md) (`python -m live.report`); the machine was a laptop with an Intel Core Ultra 7
155H, Docker Desktop on WSL2.

| Host | Traffic | Queries | Alerts | Flagged |
|---|---|---|---|---|
| 172.28.0.30 | iodine | 1,082 | 1,082 | 100% |
| 172.28.0.31 | dnscat2 (fast, then one query every 5 s) | 539 | 539 | 100% |
| 172.28.0.44 | dns2tcp | 68 | 68 | 100% |
| 172.28.0.43 | DNSExfiltrator | 31 | 31 | 100% |
| 172.28.0.4, 172.28.0.5 | benign | 5,405 | 0 | 0% |

- **Detection:** all 1,720 tunnel queries were flagged and none of the 5,405 benign ones. The highest benign
  score was 0.187, against a threshold of 0.4999; the lowest tunnel score was 0.979 (iodine's short keep-alive
  queries, such as `pabaesqy.i.tunnel.test`).
- **Time to alert** (query on the wire to alert written, 1,720 alerts): median 0.43 s, 95th percentile 1.22 s,
  maximum 1.72 s. Most of this is waiting: for the query's reply, then for the 0.5 s batch.
- **Processing** (features, score and explanations): 1.78 ms per query on average over 7,125 queries in 679
  batches. The slowest batch took 162 ms and the largest held 81 queries.
- **Explanations:** every alert stores its top three SHAP features. The strongest one in all 1,720 alerts was
  `h_uniq_ratio` (the share of the host's names in the last 60 s that are unique, 1.0 for a tunnel client).
  The other two were almost always `h_txt_null_ratio` and `h_len_mean` (`is_txt_null` in 76 iodine alerts,
  `h_ent_mean` in 2 dnscat2 alerts). So M1 flags these hosts mainly by how they
  behave over a minute, not by one name.

Read these with their limits: one run of about 7 minutes on one machine, two benign hosts, and small counts for
dns2tcp (68) and DNSExfiltrator (31). The lab's `victim` host sent no queries. The tools are the four the model
was trained on, so this shows the trained model working on fresh traffic, not on a new tool
(`docs/m1.md`: with dnscat2 held out of training, M1 catches 22% of it).

## How it works

```
frames (Scapy on an interface, or a pcap file)
  -> QueryAssembler   parser.pcap.dns_packet per frame; pairs each query with its reply
  -> HostWindows      the M1 feature set; its per-host part on each host's last 60 s of queries
  -> scorer           models/<name>.py through load() / score() / explain(), or the placeholder
  -> AlertStore       live/alerts.db
```

- **Same code as offline.** Frames are decoded by the function the file parser uses, and features come from
  `models.m1_features` and `models.host_features`, the feature set M1 trains on. `tests/test_live.py` checks
  that a query scored live gets exactly the features it would get from the parsed capture.
- **When a query is scored.** Once its reply has been seen, or after `--reply-wait` (1 s) without one;
  `resp_size` and `rcode` are features, so scoring at the query alone would differ from training. Queries
  are released in arrival order, and scored in batches of `--batch` (0.5 s). In the live test the slowest
  alert was written 1.72 s after its query, and half were written within 0.43 s.
- **One thread for the model.** `live/__init__.py` sets `OMP_NUM_THREADS=1` unless it is already set. A live
  batch is a few queries, and XGBoost spends longer starting a thread per core than scoring them: on a machine
  with 22 logical cores M1 took about 19 ms to score 10 queries and 2 ms with one thread, with identical scores and
  explanations.
- **The resolver's own queries are dropped** (`--ignore-src`, default 172.28.0.2), as in the testbed parser:
  at the resolver each lookup is seen twice, once from the client and once forwarded.

## alerts.db (read by the dashboard)

`alerts`: one row per query whose score reached the threshold.

| column | type | meaning |
|---|---|---|
| `id` | INTEGER | row id, increasing |
| `ts` | REAL | query time, epoch seconds UTC (the packet timestamp, as in the query table) |
| `src_host` | TEXT | IP address of the client that sent the query |
| `qname` | TEXT | query name as seen on the wire |
| `qtype` | TEXT | record type mnemonic (`A`, `TXT`, `NULL`, ...) |
| `score` | REAL | model score, higher = more suspicious |
| `threshold` | REAL | threshold the score was compared with |
| `model` | TEXT | scorer that produced it (`dummy`, `m1_xgb`, ...) |
| `top_features` | TEXT | JSON list, most important first: `[{"feature": "q_len", "value": 117.0, "shap": 2.31}]`. `shap` is `null` when the scorer has no explanation |
| `detected_ts` | REAL | wall-clock time the alert was written; `detected_ts - ts` is the time to alert |

`host_stats`: per host and 10-second bucket, for "score over time" and alert rates without storing every query.

| column | type | meaning |
|---|---|---|
| `bucket_ts` | REAL | start of the 10 s bucket, epoch seconds UTC |
| `src_host` | TEXT | client IP |
| `queries` | INTEGER | queries scored in the bucket |
| `alerts` | INTEGER | of those, how many reached the threshold |
| `max_score` | REAL | highest score in the bucket |
| `sum_score` | REAL | sum of scores; `sum_score / queries` is the mean |

`batches`: one row per scored batch, for the latency numbers (`python -m live.report` reads it). Added on 19 Nov;
the other tables did not change.

| column | type | meaning |
|---|---|---|
| `id` | INTEGER | row id, increasing |
| `scored_ts` | REAL | wall-clock time the batch was written |
| `first_ts`, `last_ts` | REAL | packet time of the oldest and newest query in the batch |
| `queries` | INTEGER | queries scored in the batch |
| `alerts` | INTEGER | of those, how many reached the threshold |
| `process_ms` | REAL | time spent on features, scoring and explanations for the batch |

`meta`: `schema_version` (1), `model`, `threshold`, `source` (interface or pcap), `mode` (`sniff` or `replay`),
`started_utc`. The file holds every run appended to it and `meta` describes the last one.

## Known limits

- **The placeholder scorer is not a detector.** `--model dummy` scores a name by its length alone (0 up to 40
  characters, 1 from 100). It exists to exercise the pipeline.
- **One vantage point per sniffer.** At the resolver it does not see the dns2tcp and DNSExfiltrator clients,
  which talk straight to their own servers (`testbed/tools/README.md`). Either sniff the lab bridge
  (`--at bridge`, one sniffer for every lab host, as the live test does), or run a second sniffer with
  `--at dns2tcp-client` or `--at dnsexfiltrator-cli`; sniffers can share one `alerts.db`. The bridge needs a
  Docker host whose bridges are visible to host-network containers; it was run on Docker Desktop on WSL2. The
  tool-client vantage points were not run.
- **Time to alert needs live packets.** A replayed capture's packet times are in the past, so
  `python -m live.report` gives processing time for a replay and time to alert only for a sniffed run.
- **Late replies are ignored.** A reply slower than `--reply-wait` leaves `resp_size` 0 and `rcode` -1 for that
  query, and a retransmission after the wait counts as a new query. The file parser has no such deadline.
- **Speed under load.** Each batch recomputes the per-host features of the hosts in it from their last 60 s of
  queries, so the cost grows with a host's query rate. Replaying captures as fast as possible, processing
  averaged 4 to 5 ms per query (43,450 benign queries, and 18,721 tunnel queries from four captures), measured
  before the one-thread setting above. The live test stayed far below that load; a sustained rate of several
  hundred queries per second from one host was not tested live.
- **`live_test.sh` waits for the benign generator,** which first refreshes its name lists from the internet
  (several minutes here). The whole test took about 14 minutes.
