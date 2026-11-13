import importlib.metadata
from pathlib import Path

import check_setup
import pytest


def test_installed_packages_pass(tmp_path: Path) -> None:
    """Installed packages at or above their minimum version report no problems."""
    req = tmp_path / "requirements.txt"
    req.write_text("# comment\npytest>=1\n-r other.txt\n")
    assert check_setup.check_requirements(str(req)) == []


def test_missing_and_old_packages_print_the_fix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Missing or too-old packages fail the check and print the pip command that fixes them."""
    req = tmp_path / "requirements.txt"
    req.write_text("not-a-real-package-xyz>=1\npytest>=999\n")
    monkeypatch.setitem(check_setup.GROUPS, "dev", (str(req), "linting and tests"))
    assert check_setup.main(["dev"]) == 1
    out = capsys.readouterr().out
    assert "not-a-real-package-xyz is not installed" in out
    assert f"pytest {importlib.metadata.version('pytest')} is older than the required 999" in out
    assert f"fix: pip install -r {req}" in out
