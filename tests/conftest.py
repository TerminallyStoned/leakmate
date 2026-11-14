from pathlib import Path

import pytest
from _pytest.terminal import TerminalReporter
from check_setup import check_group

NEEDS = {"test_m1.py": "m1", "test_m2.py": "m2", "test_eval.py": "m1", "test_parser.py": "m1", "test_testbed.py": "m1"}
_skipped: dict[str, list[str]] = {}


def pytest_ignore_collect(collection_path: Path, config: pytest.Config) -> bool | None:
    """Skip a test file whose packages are missing, and remember the install command."""
    group = NEEDS.get(collection_path.name)
    if group is None:
        return None
    problems, fixes = check_group(group)
    if not problems:
        return None
    _skipped[collection_path.name] = problems + [f"fix: {f}" for f in fixes]
    return True


def pytest_terminal_summary(terminalreporter: TerminalReporter) -> None:
    """List every skipped test file with what is missing and how to install it."""
    for name, lines in _skipped.items():
        terminalreporter.write_line(f"SKIPPED {name}: its packages are missing", yellow=True)
        for line in lines:
            terminalreporter.write_line(f"    {line}")
    if _skipped:
        terminalreporter.write_line("Check your whole setup with: python scripts/check_setup.py", yellow=True)
