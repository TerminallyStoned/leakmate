import importlib

import pytest
from check_setup import check_group

MODELS = [
    ("models.m1_xgb", "m1"),
    ("models.rf_baseline", "m1"),
    ("models.m2_dnsbert", "m2"),
    ("models.iforest_baseline", "m2"),
]


@pytest.mark.parametrize(("module", "group"), MODELS)
def test_model_follows_shared_interface(module: str, group: str) -> None:
    """Every model module exposes train, score, save and load (README > Shared contracts)."""
    problems, fixes = check_group(group)
    if problems:
        pytest.skip(f"{module} needs its packages: {'; '.join(fixes)}")
    mod = importlib.import_module(module)
    missing = [f for f in ("train", "score", "save", "load") if not callable(getattr(mod, f, None))]
    assert not missing, f"{module} is missing {missing}; see README > Shared contracts"
