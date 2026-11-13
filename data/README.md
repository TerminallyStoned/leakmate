# data/

Nothing under the subfolders is committed (see `.gitignore`). Every file is either downloaded
or rebuilt by a command from the main README.

| Folder | What goes there | Made by |
|---|---|---|
| `raw/cic/` | CIC-Bell-DNS-EXF-2021 PCAP zips, one folder per zip; attack zips in a folder whose name contains `attack` | download (registration required) |
| `raw/benign/<run id>/` | benign generator sidecars `<ip>.ndjson` + `run.json` | `testbed/benign/run_benign.sh` |
| `raw/tools/<tool>_<utc>/` | tunnel tool pcap + parsed `<tool>.ndjson` | `testbed/run_tool.sh --capture --out data/raw/tools/<tool>_<utc>` (default output is `testbed/tools/out/`) |
| `external/` | Tranco top-1M list (`tranco.csv`) | downloaded and cached by `testbed/benign/domains.py` |
| `processed/<dataset>/queries.parquet` | the contract query table, `<dataset>` = `cic` or `testbed` | `python -m parser cic` / `python -m parser testbed` |
| `sample/` | small schema-valid samples for tests | `scripts/make_synthetic_sample.py` |

Check any table against the contract with `python contracts.py <file.parquet>`.
