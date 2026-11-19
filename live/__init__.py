"""Live detector: sniff DNS, score each query, write alerts (python -m live, see live/README.md)."""

import os

# One thread for the model's numeric library, unless the user set a number. A live batch is a handful of
# queries, and XGBoost spends far longer starting a thread per core than scoring them: on a 22-core machine
# M1 took about 19 ms to score 10 queries and 2 ms with one thread, with identical scores and explanations.
# This has to be set before xgboost is first imported, which is why it lives here.
os.environ.setdefault("OMP_NUM_THREADS", "1")
