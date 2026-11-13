"""Parser entry point: one subcommand per data source.

    python -m parser cic --raw data/raw/cic --out data/processed/cic/queries.parquet
    python -m parser pcap CAPTURE.pcap --out rows.ndjson --tool dns2tcp
    python -m parser testbed --add data/raw/benign/<run id> --add data/raw/tools/<run> \\
        --out data/processed/testbed/queries.parquet

Every subcommand passes its remaining arguments to the script it wraps, so
`python -m parser cic --help` shows that script's options.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# subcommand -> (module in scripts/, one-line help)
STAGES = {
    "cic": ("cic_to_queries", "CIC-Bell-DNS-EXF-2021 pcaps -> data/processed/cic/queries.parquet"),
    "pcap": ("parse_capture", "one testbed pcap -> contract rows (.ndjson/.csv/.parquet)"),
    "testbed": ("build_queries_parquet", "sidecars + parsed captures -> data/processed/testbed/queries.parquet"),
}


def usage() -> str:
    lines = ["usage: python -m parser {" + ",".join(STAGES) + "} [args...]", ""]
    lines += [f"  {name:8} {help_}" for name, (_, help_) in STAGES.items()]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help"):
        print(usage())
        return 0
    stage, rest = argv[0], argv[1:]
    if stage not in STAGES:
        print(f"unknown stage {stage!r}\n\n{usage()}", file=sys.stderr)
        return 2
    sys.path.insert(0, str(ROOT / "scripts"))
    mod = importlib.import_module(STAGES[stage][0])
    sys.argv = [f"python -m parser {stage}", *rest]
    return mod.main() or 0


if __name__ == "__main__":
    sys.exit(main())
