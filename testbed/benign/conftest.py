"""Make the sibling modules importable from ``tests/`` without installing the tree."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
