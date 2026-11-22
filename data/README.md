# data

Nothing under the subfolders is committed (see `.gitignore`). Every file is either downloaded
or rebuilt by a command from the main README.

| Folder | What goes there | Made by |
|---|---|---|
| `raw/cic/` | CIC-Bell-DNS-EXF-2021 PCAP zips, one folder per zip; attack zips in a folder whose name contains `attack` | download (registration required) |
| `raw/benign/<run id>/` | benign generator sidecars `<ip>.ndjson` + `run.json`, and `resolver.pcap` (what the parser reads) | `testbed/benign/run_benign.sh`, with `tcpdump` capturing `udp port 53` at the resolver on its **lab** interface (the one that holds 172.28.0.2; it is not always `eth0`). `testbed/capture_matrix.sh` does this for you; the by-hand command is in `testbed/tools/README.md` |
| `raw/tools/<tool>_<utc>/` | tunnel tool pcap + parsed `<tool>.ndjson` | `testbed/run_tool.sh --capture --out data/raw/tools/<tool>_<utc>` (default output is `testbed/tools/out/`) |
| `raw/tools/<tool>_<size>_<rate>_<encoding>_<utc>.pcap` | the iodine and dnscat2 capture runs, with `raw/benign/benign_<n>h_with-tools_<utc>/resolver.pcap` for the benign traffic that ran alongside | `testbed/capture_matrix.sh` |
| `raw/manifest.csv` | one row per capture: settings, start and end time, query count, sha256 (the only file under `raw/` that is committed) | `testbed/run_tool.sh --manifest`, `testbed/capture_matrix.sh` |
| `external/` | Tranco top-1M list (`tranco.csv`) | downloaded and cached by `testbed/benign/domains.py` |
| `processed/<dataset>/queries.parquet` | the contract query table, `<dataset>` = `cic` or `testbed` | `python -m parser cic` / `python -m parser testbed` |
| `sample/` | small schema-valid samples for tests | `scripts/make_synthetic_sample.py` |

Check any table against the contract with `python contracts.py <file.parquet>`.
