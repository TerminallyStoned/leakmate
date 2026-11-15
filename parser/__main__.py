"""Parser entry point: one subcommand per data source.

    python -m parser cic --raw data/raw/cic --out data/processed/cic/queries.parquet
    python -m parser features --dataset cic
    python -m parser testbed --capture TOOL.pcap --capture SLOW.pcap@200 --capture RESOLVER.pcap
    python -m parser features --dataset testbed

Every subcommand passes its remaining arguments to its module, so
`python -m parser cic --help` shows that module's options.
"""

from __future__ import annotations

import importlib
import sys

# subcommand -> (module, one-line help)
STAGES = {
    "cic": ("parser.cic", "CIC-Bell-DNS-EXF-2021 pcaps -> data/processed/cic/queries.parquet"),
    "features": ("parser.features", "queries.parquet -> features.parquet (per-query + per-host)"),
    "testbed": ("parser.testbed", "testbed pcaps -> data/processed/testbed/queries.parquet"),
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
    mod = importlib.import_module(STAGES[stage][0])
    sys.argv = [f"python -m parser {stage}", *rest]
    return mod.main() or 0


if __name__ == "__main__":
    sys.exit(main())
