"""Moved to parser/cic.py; run `python -m parser cic`. Kept so notebooks and docs using this path still work."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from parser.cic import _qname, main  # noqa: E402, F401

if __name__ == "__main__":
    main()
