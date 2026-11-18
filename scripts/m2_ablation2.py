"""M2 ablation 2 in one command: supervised fine-tune of the Phase 1 DNS-BERT, on the MASKED testbed table.

    python -m parser.mask                                    # writes data/processed_nozone/testbed/queries.parquet
    python scripts/m2_ablation2.py --root data/processed_nozone \
        --init-from "<leakmate captures>/m2/ckpt_bpe_v2/last" --out nz_ab2 --skip-existing

Six fine-tunes (BPE): E1, E3 with each tool held out, E5. Unlike M2, a supervised model sees
tunnel names, so Experiment 3 trains a new model per held-out tool, and the masked table is
required: on the original table it would learn the tunnel.test suffix (docs/suffix-ablation.md).
Results: <out>/m2_ablation2_sup/<run>.json and <out>/m2_ablation2_sup_hostavg/<run>.json.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.m2_phase2 import TOOLS, run  # noqa: E402

MODEL = "m2_ablation2_sup"


def runs() -> list[tuple[str, list[str]]]:
    """(run name, extra m2_run args) for every ablation 2 run."""
    return (
        [("E1", ["--exp", "E1"])]
        + [(f"E3_{t}", ["--exp", "E3", "--holdout", t]) for t in TOOLS]
        + [("E5", ["--exp", "E5"])]
    )


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default="data/processed_nozone", help="folder holding testbed/queries.parquet (masked)")
    ap.add_argument("--init-from", required=True, help="saved Phase 1 M2 model, e.g. <ckpt_bpe_v2>/last")
    ap.add_argument("--out", default="nz_ab2")
    ap.add_argument("--weights", help="where to save each fine-tuned model (default <out>/weights)")
    ap.add_argument("--epochs", default="2")
    ap.add_argument("--skip-existing", action="store_true")
    a = ap.parse_args(argv)
    if "nozone" not in a.root:
        print(f"warning: --root {a.root} does not look masked; ablation 2 must run on the masked table", flush=True)
    weights = Path(a.weights or Path(a.out) / "weights")
    for name, extra in runs():
        res = Path(a.out) / MODEL / f"{name}.json"
        run(
            [
                "-m",
                "models.m2_run",
                "--model",
                "m2sup",
                "--tag",
                "ablation2_sup",
                "--root",
                a.root,
                "--init-from",
                a.init_from,
                "--epochs",
                a.epochs,
                "--out",
                a.out,
                "--save-model",
                str(weights / name),
                *extra,
            ],
            skip_if=[res] if a.skip_existing else None,
        )


if __name__ == "__main__":
    main()
