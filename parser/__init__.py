"""Turn DNS captures into the contract query table (docs/contracts.md).

Run it with `python -m parser --help`. For now each stage calls the stopgap script that
already does the job (scripts/cic_to_queries.py, scripts/parse_capture.py,
scripts/build_queries_parquet.py). The parser card replaces them here, so the commands stay
the same and the user manual doesn't change.
"""
