# External baselines: Splunk's pretrained model and RITA (Experiment 1)

Two well-known detectors, run unchanged on the Experiment 1 test rows (67,699 queries, the rows in
`results/<model>/E1.json`). Neither is trained on our data. Results: `results_external/` (from
`python -m eval.summarise --results-dir results_external`); code: `scripts/external_baselines.py`.

| Detector | Kind | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|---|
| Splunk pretrained model (threshold 0.5) | deep learning, per query | 0.9991 | 0.7545 | 0.8597 | 0.07% | 0.9341 |
| RITA, Medium or above | rules, per domain | 1.0000 | 1.0000 | 1.0000 | 0% | 1.0000 |
| RITA, any severity (Low included) | rules, per domain | 0.9064 | 1.0000 | 0.9509 | 10.53% | 1.0000 |
| M1 XGBoost (`results/m1`) | ours | 1.0000 | 1.0000 | 1.0000 | 0% | 1.0000 |
| M3 BiLSTM, lab domain hidden (`results_nozone/m3_bilstm`) | ours | 0.9998 | 0.9996 | 0.9997 | 0.02% | 1.0000 |

Recall per tool: Splunk dns2tcp 0.009, dnscat2 0.908, iodine 0.989, DNSExfiltrator 1.000; RITA 1.000 for all four.

## Splunk pretrained model
- **What it is:** "Detect DNS Data Exfiltration using pretrained model in DSDL" from
  [splunk/security_content](https://github.com/splunk/security_content), described in Splunk's blog post
  "Machine Learning in Security: Detect DNS Data Exfiltration Using Deep Learning". A multilayer perceptron on
  98 inputs: counts of the 94 printable characters in the query, length and entropy of the query without its
  last two labels, and their means over recent queries from the same source to the same domain. Splunk marked
  the detection removed in May 2026.
- **Weights:** `detect_dns_data_exfiltration_using_pretrained_model_in_dsdl.tar.gz` from
  `https://seal.splunkresearch.com/` (110,871 bytes; sha256 of the archive
  `6670973549bab6f6c631abb6107c9b711820889bf4203962ba66fc6e19c9b14c`, measured here; Splunk publishes none).
  Loaded with `torch.load(..., weights_only=True)`, so only tensors are read. Not committed.
- **Changes from Splunk's notebook**, both needed for it to run as intended: bytes outside
  `string.printable` (iodine's raw-byte names) are escaped as `\xNN`, as Zeek and Splunk store them (the notebook
  raises on them); predictions keep their row order (the notebook's `DataLoader(shuffle=True)` pairs predictions
  with the wrong rows). The means use the 10 latest queries from the same source and domain, as the notebook's
  description says (its code averages over everything in the search).
- **Finding:** it misses dns2tcp (names of about 30 characters), the same short-name blind spot as M3 in
  Experiment 4. 23 false alarms, all CDN host names (`akamaized.net`, `amazonaws.com`).

## RITA
- **What it is:** [activecm/rita](https://github.com/activecm/rita) v5.1.2 with its default config. Its
  DNS-tunnelling check counts unique subdomains per domain over the imported logs: 100 or more and the domain is
  reported, with severity from the count.
- **Input:** Zeek 9.0.1 `dns.log` from the 59 pcaps behind the test rows, cut to each capture's test part (the
  split is per capture: last 30% by time), 73,552 log rows. All of it falls on one UTC day, so it is imported as
  one dataset, as a sensor on the lab network would see it. A query gets its domain's severity.
- **Findings:** `tunnel.test` High (30,497 unique subdomains); 11 benign domains Low (CDNs such as
  `amazonaws.com` 191 subdomains, `azureedge.net`, `windows.net`, plus `com.internal` and `com.lan`).
- **Not only the shared suffix:** each tool's own zone has thousands of unique names in the test part
  (`i.tunnel.test` 10,832, `exfil.tunnel.test` 9,401, `dns2tcp.tunnel.test` 7,764, `d.tunnel.test` 6,182), above
  RITA's 1,000 "High" level, so tools on separate real domains would still be flagged.
- **Limits:** a verdict per domain after a batch import, not per query as it arrives; a domain needs 100 or more
  unique subdomains first (one small slow dnscat2 capture imported on its own was not flagged); every query to a
  flagged domain counts, legitimate ones too. The latency column is import time per row, not comparable with
  per-query scoring.

## What this means for the report
Both tools work out of the box. Splunk's model misses short tunnel names; RITA catches high-volume tunnel
zones with no false alarms at Medium but gives domain verdicts in batches and is noisy at Low. Our models flag
single queries as they arrive, catch all four tools, and stay under 1% FPR. Only Experiment 1 was run: the
test rows come from the same capture runs as training, which does not matter for tools never trained on them.

## Reproduce
```bash
python scripts/external_baselines.py splunk --weights <unpacked .pt from the tar.gz above>

mkdir -p work/zeek
python scripts/external_baselines.py zeek-list --out work/zeek/zeek_list.tsv
cp scripts/external/zeek_run.sh work/zeek/
docker run --rm -v "$PWD/data/raw:/raw:ro" -v "$PWD/work/zeek:/out" zeek/zeek:latest sh /out/zeek_run.sh
python scripts/external_baselines.py zeek-test-only --zeek work/zeek --out work/rita/zeek_test

# RITA config files from its v5.1.2 tag, then the compose file
cd work/rita && mkdir -p threat_intel_feeds
for f in default_config.hjson deployment/config.xml deployment/http_extensions_list.csv; do
  curl -sSLO "https://raw.githubusercontent.com/activecm/rita/v5.1.2/$f"; done
mv default_config.hjson config.hjson
printf 'LOGGING_ENABLED=false\nDB_ADDRESS=db:9000\nCLICKHOUSE_USERNAME=default\nCLICKHOUSE_PASSWORD=\n' > .env
cp ../../scripts/external/rita-compose.yml . && docker compose -f rita-compose.yml -p rita up -d clickhouse
docker compose -f rita-compose.yml -p rita run --rm rita import --database leakmate_e1 --logs /logs --rebuild
docker compose -f rita-compose.yml -p rita run --rm -T rita view --stdout leakmate_e1 > rita_e1.csv
docker compose -f rita-compose.yml -p rita down && cd ../..
python scripts/external_baselines.py rita --csv work/rita/rita_e1.csv

python -m eval.summarise --results-dir results_external
```
