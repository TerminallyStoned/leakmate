"""Live detector: sniff DNS, score each query, write alerts to live/alerts.db.

Run with `python -m live` (see live/README.md). The sniffer and its alert store are in place; the
selected model with SHAP alerts is plugged in on 19 Nov.
"""
