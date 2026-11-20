## Live run

Model `m1_xgb`, alert at score >= 0.4999. Source: br-161e761217ee (sniff), last run started 2026-11-19T03:48:49+00:00.

### Per host

| src_host | traffic | queries | alerts | flagged | max_score |
|---|---|---|---|---|---|
| 172.28.0.44 | dns2tcp | 68 | 68 | 100.00% | 1.0000 |
| 172.28.0.31 | dnscat2 | 539 | 539 | 100.00% | 1.0000 |
| 172.28.0.43 | dnsexfiltrator | 31 | 31 | 100.00% | 1.0000 |
| 172.28.0.30 | iodine | 1,082 | 1,082 | 100.00% | 1.0000 |
| 172.28.0.4 | benign | 2,848 | 0 | 0.00% | 0.0020 |
| 172.28.0.5 | benign | 2,557 | 0 | 0.00% | 0.1871 |

### Tunnel against benign

| kind | queries | alerts | flagged |
|---|---|---|---|
| tunnel | 1,720 | 1,720 | 100.00% |
| benign | 5,405 | 0 | 0.00% |

### Latency

- Processing (features, score, explanations): 1.78 ms per query over 7,125 queries in 679 batches; per batch, median 1.92 and 95th percentile 10.79 ms per query. Slowest batch: 162 ms. Largest batch: 81 queries.

- Time to alert (query on the wire to alert written), 1,720 alerts: median 0.43 s, 95th percentile 1.22 s, max 1.72 s.

- Time to a verdict for the oldest query of each batch (alert or not): median 0.60 s, 95th percentile 1.46 s, max 1.72 s.
