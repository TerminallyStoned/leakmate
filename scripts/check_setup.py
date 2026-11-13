from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMPORT_NAMES = {"scikit-learn": "sklearn"}
GROUPS = {
    "dev": ("requirements-dev.txt", "linting (ruff) and tests (pytest)"),
    "m1": ("requirements-m1.txt", "M1 XGBoost, Random Forest, SHAP, CIC pcap reader"),
    "m2": ("requirements-m2.txt", "M2 DNS-BERT and the Isolation Forest baseline"),
    "testbed": (None, "Docker testbed (iodine, dnscat2, dns2tcp, DNSExfiltrator server)"),
    "data": (None, "processed CIC data and the Tranco list used by the runners"),
}
DATA_FILES = [
    (
        "data/processed/cic/queries.parquet",
        "download the CIC PCAP zips (README > Data), unzip each into data/raw/cic/<name>/, then run\n"
        "        python scripts/cic_to_queries.py --raw data/raw/cic --out data/processed/cic/queries.parquet",
    ),
    (
        "data/external/tranco.csv",
        "download the Tranco top-1M list from https://tranco-list.eu and save it as data/external/tranco.csv",
    ),
]
GPU_HINT = (
    "CPU-only torch is enough for tests; install it first with\n"
    "        pip install torch --index-url https://download.pytorch.org/whl/cpu"
)


def _version_tuple(v: str) -> tuple[int, ...]:
    """Turn '2.10.1rc1' into (2, 10, 1) for a simple minimum-version check."""
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def check_requirements(req_file: str) -> list[str]:
    """Return one problem line per package in req_file that is missing or older than required."""
    problems = []
    for line in (ROOT / req_file).read_text().splitlines():
        m = re.match(r"\s*([A-Za-z0-9_.\-]+)\s*(?:>=\s*([\d.]+))?", line)
        if not m or line.strip().startswith(("#", "-")):
            continue
        name, minimum = m.group(1), m.group(2)
        if importlib.util.find_spec(IMPORT_NAMES.get(name, name).replace("-", "_")) is None:
            problems.append(f"{name} is not installed")
            continue
        try:
            have = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
        if minimum and _version_tuple(have) < _version_tuple(minimum):
            problems.append(f"{name} {have} is older than the required {minimum}")
    return problems


def check_group(group: str) -> tuple[list[str], list[str]]:
    """Return (problems, fix commands) for one group."""
    req_file, _ = GROUPS[group]
    if req_file:
        problems = check_requirements(req_file)
        fixes = [f"pip install -r {req_file}"] if problems else []
        if group == "m2" and any(p.startswith("torch ") for p in problems):
            fixes.insert(0, GPU_HINT)
        if group == "dev" and not problems and shutil.which("ruff") is None:
            problems.append("ruff is installed for this Python but not on PATH")
            fixes.append("use `python -m ruff` instead of `ruff`, or activate the virtual environment")
        return problems, fixes
    if group == "testbed":
        if shutil.which("docker") is None:
            return ["docker is not installed or not on PATH"], [
                "install Docker Desktop (Windows/macOS) or Docker Engine (Linux): https://docs.docker.com/get-docker/"
            ]
        ok = subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0
        return (
            ([], [])
            if ok
            else (
                ["the `docker compose` plugin is missing or Docker is not running"],
                ["start Docker Desktop, or install the compose plugin: https://docs.docker.com/compose/install/"],
            )
        )
    missing = [(path, how) for path, how in DATA_FILES if not (ROOT / path).exists()]
    return [f"{path} is missing" for path, _ in missing], [how for _, how in missing]


def main(argv: list[str] | None = None) -> int:
    """Check the setup for the chosen groups and print how to fix anything missing."""
    ap = argparse.ArgumentParser(description="Check that this machine can run leakmate, and say how to fix it.")
    ap.add_argument(
        "groups", nargs="*", metavar="GROUP", help=f"what to check: {', '.join(GROUPS)} (default: dev m1 m2)"
    )
    groups = ap.parse_args(argv).groups or ["dev", "m1", "m2"]
    unknown = [g for g in groups if g not in GROUPS]
    if unknown:
        ap.error(f"unknown group {', '.join(unknown)}; choose from {', '.join(GROUPS)}")

    failed = False
    if sys.version_info < (3, 10):
        print(f"[FAIL] python  Python {sys.version.split()[0]} is too old; install Python 3.10 or newer")
        failed = True
    for group in groups:
        problems, fixes = check_group(group)
        if not problems:
            print(f"[ ok ] {group:8} {GROUPS[group][1]}")
            continue
        failed = True
        print(f"[FAIL] {group:8} {GROUPS[group][1]}")
        for p in problems:
            print(f"         - {p}")
        for f in fixes:
            print(f"       fix: {f}")
    if failed:
        print(
            "\nRun the fix commands above, then run this check again: python scripts/check_setup.py " + " ".join(groups)
        )
        return 1
    if "dev" in groups:
        print(
            "\nBefore you push:  ruff check --fix .   (and ruff format <new files you added>)"
            "\nRun tests with:   python -m pytest"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
