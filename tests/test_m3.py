"""M3 threshold and validation slice: python -m pytest tests/test_m3.py -q"""

import numpy as np
import pandas as pd

from eval.metrics import threshold_at_fpr
from models.m3_common import _val_split, pick_threshold


def test_threshold_in_the_gap_when_classes_separate():
    y = np.r_[np.zeros(100), np.ones(100)]
    s = np.r_[np.linspace(0, 0.1, 100), np.linspace(0.9, 1, 100)]
    lo, hi = threshold_at_fpr(y, s, 0.01), np.quantile(s[100:], 0.01)
    assert pick_threshold(y, s, 0.01) == (lo + hi) / 2


def test_threshold_keeps_target_fpr_when_classes_overlap():
    y = np.r_[np.zeros(100), np.ones(100)]
    s = np.r_[np.linspace(0, 1, 100), np.linspace(0, 1, 100)]
    assert pick_threshold(y, s, 0.01) == threshold_at_fpr(y, s, 0.01)
    no_tunnel = np.zeros(5), np.linspace(0, 1, 5)
    assert pick_threshold(*no_tunnel, 0.01) == threshold_at_fpr(*no_tunnel, 0.01)


TOOLS = ["benign", "iodine", "dnscat2", "dns2tcp", "dnsexfiltrator"]


def test_val_split_keeps_benign_and_every_tool_when_latest_sessions_are_one_class():
    # testbed shape: benign captured first, then each tool on a later day, one session each
    parts = [pd.DataFrame({"ts": np.arange(100) + 1000.0 * k, "session_id": tool, "tool": tool,
                           "label": int(tool != "benign"), "qname": "x"})
             for k, tool in enumerate(TOOLS)]  # fmt: skip
    tr, va = _val_split(pd.concat(parts, ignore_index=True), 0.1)
    assert va.groupby("tool").size().to_dict() == dict.fromkeys(sorted(TOOLS), 10)
    assert (va.groupby("tool").ts.min() > tr.groupby("tool").ts.max()).all()  # validation is the latest rows per tool
