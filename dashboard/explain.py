"""Plain words for the features an alert reports, so the demo does not need a translator.

`python -m live` stores each alert's top SHAP features as `[{"feature", "value", "shap"}]` (live/README.md).
The feature names come from models/m1_features.py; what follows describes each one the way the docs do,
without claiming a threshold the model never used. SHAP values are log-odds contributions: positive pushes
the score toward "tunnel", negative away from it, and the magnitudes are comparable within one alert.
"""

from __future__ import annotations

#: feature -> (short label, what the number counts, unit)
FEATURE_DOC: dict[str, tuple[str, str, str]] = {
    "q_len": ("name length", "characters in the whole query name", "chars"),
    "sub_len": ("first label length", "characters before the first dot", "chars"),
    "longest_label": ("longest label", "characters in the longest label", "chars"),
    "n_labels": ("label count", "labels the name is split into by dots", "labels"),
    "entropy": ("name entropy", "how unpredictable the characters of the name are", "bits/char"),
    "sub_entropy": ("first-label entropy", "how unpredictable the characters of the first label are", "bits/char"),
    "n_digits": ("digits", "digit characters in the name", "chars"),
    "n_upper": ("upper case", "upper-case characters in the name", "chars"),
    "n_special": ("special characters", "characters that are not letters, digits or hyphens", "chars"),
    "digit_ratio": ("digit share", "share of the name made of digits", "share"),
    "qtype_code": ("record type", "the record type as a number (A, AAAA, TXT, NULL)", ""),
    "is_txt_null": ("TXT or NULL", "the query asked for a TXT or NULL record", "flag"),
    "resp_size": ("answer size", "size of the DNS answer", "bytes"),
    "qlen_wire": ("query size", "size of the whole query on the wire", "bytes"),
    "h_qpm": ("host query rate", "queries per minute from this host", "q/min"),
    "h_uniq_ratio": ("unique names", "share of this host's names in the window that appear once", "share"),
    "h_ent_mean": ("host mean entropy", "mean name entropy for this host in the window", "bits/char"),
    "h_ent_std": ("host entropy spread", "spread of that entropy", "bits/char"),
    "h_len_mean": ("host mean length", "mean name length for this host in the window", "chars"),
    "h_parent_uniq": ("parent domains", "distinct parent domains this host asked about in the window", "domains"),
    "h_txt_null_ratio": ("TXT or NULL share", "share of this host's queries in the window asking TXT or NULL", "share"),
}

WINDOW = "60 s"


def label(feature: str) -> str:
    doc = FEATURE_DOC.get(feature)
    return doc[0] if doc else feature.replace("_", " ")


def value_text(feature: str, value: float | None) -> str:
    """`117.0` -> `117 chars`, `0.31` -> `0.31`, `1.0` on a flag -> `yes`."""
    doc = FEATURE_DOC.get(feature)
    if value is None:
        return "-"
    if doc and doc[2] == "flag":
        return "yes" if value >= 0.5 else "no"
    number = f"{value:,.2f}".rstrip("0").rstrip(".") if abs(value) < 1 or abs(value) >= 1 else str(value)
    if doc and doc[2] in {"chars", "bytes", "labels", "domains"}:
        number = f"{value:,.0f}"
    elif doc and doc[2] == "q/min":
        number = f"{value:,.1f}"
    unit = doc[2] if doc and doc[2] not in {"flag", ""} else ""
    return f"{number} {unit}".strip()


def direction(shap: float | None) -> str:
    if shap is None:
        return "no explanation stored"
    if shap > 0:
        return "pushes toward tunnel"
    if shap < 0:
        return "pushes away from tunnel"
    return "no effect"


def sentence(feature: str, value: float | None, shap: float | None) -> str:
    """One line for one feature: what it counted, at what value, and which way it pulled."""
    doc = FEATURE_DOC.get(feature)
    what = doc[1] if doc else feature.replace("_", " ")
    if doc and doc[2] == "flag":
        return (
            f"{'asked for TXT or NULL' if (value or 0) >= 0.5 else 'did not ask for TXT or NULL'} - {direction(shap)}"
        )
    return f"{what}: {value_text(feature, value)} - {direction(shap)}"


def meaning(feature: str, shap: float | None) -> str:
    """What the feature counts and which way it pulled, without repeating the value the line above shows."""
    doc = FEATURE_DOC.get(feature)
    what = doc[1] if doc else feature.replace("_", " ")
    return f"{what} - {direction(shap)}"


def headline(features: list[dict]) -> str:
    """The top feature as a phrase, for the alert feed row."""
    for f in features or []:
        name = f.get("feature")
        if not name:
            continue
        return f"{label(name)} {value_text(name, f.get('value'))}"
    return "no explanation"
