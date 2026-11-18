"""M2 error analysis: python -m pytest tests/test_m2_error_analysis.py -q"""

import pandas as pd
import pytest


def _case():
    names = ["a.cdn77.org", "b.cdn77.org", "www.google.com", "x" * 30 + ".masked.domain", "y" * 31 + ".t", "zz.t"]
    test_df = pd.DataFrame(
        {
            "qname": names,
            "label": [0, 0, 0, 1, 1, 1],
            "tool": ["benign"] * 3 + ["iodine", "iodine", "dns2tcp"],
            "session_id": ["s0", "s0", "s1", "s2", "s2", "s3"],
            "ts": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
        }
    )
    result = {
        "n_test": 6,
        "labels": [0, 0, 0, 1, 1, 1],
        "session_ids": ["s0", "s0", "s1", "s2", "s2", "s3"],
        "ts": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
        "scores": [9.0, 8.0, 1.0, 2.0, 7.0, 3.0],
        "threshold": 5.0,
    }
    return result, test_df


def test_align_marks_fp_and_fn():
    from scripts.m2_error_analysis import align

    out = align(*_case())
    assert out["error"].tolist() == ["FP", "FP", None, "FN", None, "FN"]
    assert out["flagged"].tolist() == [True, True, False, False, True, False]


def test_align_rejects_mismatched_table():
    from scripts.m2_error_analysis import align

    result, test_df = _case()
    test_df.loc[2, "ts"] = 99.0
    with pytest.raises(ValueError, match="ts"):
        align(result, test_df)


def test_fn_by_length_bins_and_fp_by_domain():
    from scripts.m2_error_analysis import align, summarise_errors

    s = summarise_errors(align(*_case()))
    fp_dom = s["fp_by_domain"].set_index("domain")["count"].to_dict()
    assert fp_dom == {"cdn77.org": 2}
    bins = s["fn_by_length"].set_index("length")["missed"].to_dict()
    assert bins["≤30"] == 1  # "zz.t"
    assert bins["31–60"] == 1  # 44-char iodine name missed; the 33-char one is caught
    assert bins[">200"] == 0
    assert s["fn_by_length"].set_index("length").loc["31–60", "rows"] == 2
    tools = s["fn_by_tool"].set_index("tool")
    assert tools.loc["iodine", "missed"] == 1 and tools.loc["iodine", "rows"] == 2
