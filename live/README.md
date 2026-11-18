# Live sniffer

Sniffs DNS, scores every query as it is seen and writes alerts to `live/alerts.db` (SQLite), which the
dashboard reads. Owner: Justin · Backup: HW · Trello: "[Justin] Live sniffer service skeleton".

**Status (18 Nov):** the sniffer, the per-host feature windows and the alert store work end to end with a
placeholder scorer. The selected model and its SHAP explanations are plugged in on 19 Nov
("[Justin] Live detector end to end with SHAP alerts"); `--model m1 --weights <file>` already works.

## Run it

```bash
# Replay a capture file. No root, no Scapy: needs only requirements-m1.txt.
python -m live --pcap data/raw/tools/<capture>.pcap
python -m live --pcap <capture>.pcap --speed 1          # at the recorded pace

# In the testbed (docker compose up -d in testbed/ first). Builds a small image the first time.
live/run_live.sh                                        # at the resolver
live/run_live.sh --at dns2tcp-client                    # inside another container's network
live/run_live.sh --at bridge                            # on the lab bridge: every lab host at once
live/run_live.sh --model m1 --weights <m1.joblib>       # a trained model instead of the placeholder

# On any Linux interface. Needs root and requirements-live.txt (Scapy, libpcap).
sudo python -m live --iface eth0
```

Then, in another terminal, start a tunnel (`testbed/run_tool.sh --tool dnscat2 --size 8192`) and look:

```bash
sqlite3 live/alerts.db "SELECT datetime(ts, 'unixepoch'), src_host, substr(qname, 1, 50), score FROM alerts ORDER BY id DESC LIMIT 5"
```

The sniffer prints one status line every 10 seconds (queries seen, alerts written, the last alert).
`live/alerts.db` is not committed. Delete it to start empty; a new run appends to an existing file.

## How it works

```
frames (Scapy on an interface, or a pcap file)
  -> QueryAssembler   parser.pcap.dns_packet per frame; pairs each query with its reply
  -> HostWindows      models.m1_features.build on each host's last 60 s of queries
  -> scorer           placeholder, or models/<name>.py through load() / score() / explain()
  -> AlertStore       live/alerts.db
```

- **Same code as offline.** Frames are decoded by the function the file parser uses, and features come from
  `models.m1_features.build`, the feature set M1 trains on. `tests/test_live.py` checks that a query scored
  live gets exactly the features it would get from the parsed capture.
- **When a query is scored.** Once its reply has been seen, or after `--reply-wait` (1 s) without one;
  `resp_size` and `rcode` are features, so scoring at the query alone would differ from training. Queries
  are released in arrival order, and scored in batches of `--batch` (0.5 s). So an alert is written within
  about 1.5 s of the query in the worst case, and well under a second when replies arrive.
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

`meta`: `schema_version` (1), `model`, `threshold`, `source` (interface or pcap), `started_utc`.

## Known limits

- **The placeholder scorer is not a detector.** It scores a name by its length alone (0 up to 40 characters,
  1 from 100). It misses short tunnel names such as dns2tcp's and will flag any long benign name.
- **One vantage point per sniffer.** At the resolver it does not see the dns2tcp and DNSExfiltrator clients,
  which talk straight to their own servers (`testbed/tools/README.md`). Either sniff the lab bridge
  (`--at bridge`, one sniffer for every lab host), or run a second sniffer with `--at dns2tcp-client` or
  `--at dnsexfiltrator-cli`; sniffers can share one `alerts.db`. Checked on 18 Nov with Docker Desktop on
  WSL2: `--at resolver` with a real dnscat2 tunnel (104 alerts, each written 0.11 to 0.53 s after its
  query), and `--at bridge` saw the lab's queries; the tool-client vantage points were not run.
- **Late replies are ignored.** A reply slower than `--reply-wait` leaves `resp_size` 0 and `rcode` -1 for that
  query, and a retransmission after the wait counts as a new query. The file parser has no such deadline.
- **Speed.** Each batch rebuilds the features of the hosts in it from their last 60 s of queries. That is
  simple and exact, but the cost grows with a host's query rate. Latency under load is measured on 19 Nov.
