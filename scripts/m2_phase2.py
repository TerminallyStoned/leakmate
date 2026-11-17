"""M2 Phase 2 in one command: Experiments 1-4 for DNS-BERT (BPE + character tokenizer,
ablation 1) and its Isolation Forest baseline, with per-host averaging.

    python scripts/m2_phase2.py --phase1-bpe <ckpt_bpe_v2>/last --phase1-char <ckpt_char_v2>/last

M2 needs a GPU for reasonable time; --iforest-only runs just the Isolation Forest (CPU, minutes).
Optionally builds the testbed table first from the extracted capture zips:

    python scripts/m2_phase2.py --build-testbed data/raw/testbed --phase1-bpe ... --phase1-char ...

M2 runs, per tokenizer (character runs are the model m2_ablation1_char):
  E2              new model on CIC benign + Tranco, threshold held out per capture
  E1              continue pre-training the Phase 1 model on testbed benign (benign only), score testbed test
  E3_<tool> x4    M2 trains on benign only, so the E1 model is reused; only the test set changes
  E4_cic2testbed  the E2 model (CIC benign + Tranco, never saw the testbed) scores testbed test
  E4_testbed2cic  a new model trained from scratch on testbed benign only (no Tranco, which overlaps
                  CIC's scripted top-site lookups) scores CIC test
Isolation Forest (--iforest / --iforest-only): E1 (saved), E3 x4 (reuses it), E4 both ways, E2.

Every run also writes the per-host-averaged variant. Results: <out>/<model>/<run>.json, e.g.
m2/E3_iodine.json, m2_hostavg/E3_iodine.json, m2_ablation1_char/E3_iodine.json.
--skip-existing skips runs whose results (and saved model) exist, so after a Colab disconnect the
same command picks up where it stopped; --rerun NAME forces those runs again.
--rescore re-scores every M2 run with the models already saved in --weights (no training), e.g. after
a change to the threshold rule; each result keeps the training time of the run that trained its model.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path

TOOLS = ["dns2tcp", "dnscat2", "dnsexfiltrator", "iodine"]
# Team decision (Trello, 17 Nov, option A): this run captured the resolver's upstream side,
# so every query shows the resolver's address. Newer manifests drop it already; kept as a guard.
EXCLUDE = ["benign_4h_with-tools_20261115T140757Z"]


def run(args: list[str], skip_if: list[Path] | None = None) -> None:
    """Run one step; skip it when every file in skip_if already exists (resume after a disconnect)."""
    if skip_if and all(p.exists() for p in skip_if):
        print(f"\n[skip] already done: {skip_if[0]}", flush=True)
        return
    print("\n$ python " + " ".join(args), flush=True)
    subprocess.run([sys.executable, *args], check=True)


def build_testbed(raw: Path, manifest: Path) -> None:
    with open(manifest, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    caps, tools = [], {}
    for r in rows:
        if any(x in r["file"] for x in EXCLUDE):
            continue
        ms = int(r["throttle_ms"] or 0)
        caps += ["--capture", f"{raw / r['file']}" + (f"@{ms}" if ms else "")]
        if r["tool"] != "benign" and r["client_ip"]:
            if tools.get(r["client_ip"], r["tool"]) != r["tool"]:
                raise SystemExit(
                    f"{manifest}: {r['client_ip']} is used by both {tools[r['client_ip']]} and {r['tool']}"
                )
            tools[r["client_ip"]] = r["tool"]
    tmap = ",".join(f"{ip}={t}" for ip, t in sorted(tools.items()))
    run(["-m", "parser", "testbed", *caps, "--tools-map", tmap, "--out", "data/processed/testbed/queries.parquet"])
    run(["contracts.py", "data/processed/testbed/queries.parquet"])


def migrate_layout(out: Path) -> None:
    """Move results written as <out>/<base>/<run>_<variant>.json into <out>/<model>/<run>.json.

    The model name in each file says where it belongs; contents are not changed.
    """
    for base in ("m2", "iforest"):
        for f in sorted((out / base).glob("*.json")) if (out / base).is_dir() else []:
            model = json.loads(f.read_text())["model"]
            if model == base:
                continue
            variant = model[len(base) + 1 :]
            if not f.stem.endswith("_" + variant):
                continue
            dest = out / model / f"{f.stem[: -len(variant) - 1]}.json"
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(f), str(dest))
            print(f"moved {f} -> {dest}")


def rescore(a, out: Path, extra: list[str]) -> None:
    """Re-score every M2 run with its saved model (no training); keep each run's recorded training time."""
    for tok in a.tokenizers:
        model = "m2" if tok == "bpe" else "m2_ablation1_char"
        tag = [] if tok == "bpe" else ["--tag", "ablation1_char"]
        w = {k: f"{a.weights}/m2_{tok}_{k}" for k in ("cic", "testbed", "testbed_scratch")}
        runs = [("E2", ["--exp", "E2"], w["cic"]), ("E1", ["--exp", "E1"], w["testbed"])]
        runs += [(f"E3_{t}", ["--exp", "E3", "--holdout", t], w["testbed"]) for t in TOOLS]
        runs += [("E4_cic2testbed", ["--exp", "E4_cic2testbed"], w["cic"])]
        runs += [("E4_testbed2cic", ["--exp", "E4_testbed2cic"], w["testbed_scratch"])]
        for name, exp, saved in runs:
            if not (Path(saved) / "m2_config.json").exists():
                raise SystemExit(f"{saved}: saved model not found; run the normal Phase 2 command first")
            old = out / model / f"{name}.json"
            keep = ["--train-time-s", str(json.loads(old.read_text())["train_time_s"])] if old.exists() else []
            run(
                [
                    "-m",
                    "models.m2_run",
                    "--model",
                    "m2",
                    "--tokenizer",
                    tok,
                    "--batch-size",
                    str(a.batch_size),
                    "--out",
                    a.out,
                    *tag,
                    *exp,
                    "--load-model",
                    saved,
                    *keep,
                    *extra,
                ]
            )


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phase1-bpe", help="Phase 1 BPE model folder (e.g. <ckpt_bpe_v2>/last)")
    ap.add_argument("--phase1-char", help="Phase 1 character model folder")
    ap.add_argument("--build-testbed", help="folder with the extracted capture zips (benign/, tools/)")
    ap.add_argument("--manifest", default="data/raw/manifest.csv")
    ap.add_argument("--tokenizers", nargs="+", default=["bpe", "char"], choices=["bpe", "char"])
    ap.add_argument("--continue-epochs", type=int, default=10, help="continued pre-training on testbed benign")
    ap.add_argument("--continue-lr", type=float, default=1e-4)
    ap.add_argument("--scratch-epochs", type=int, default=30, help="E4_testbed2cic model from scratch")
    ap.add_argument("--batch-size", type=int, default=512)
    ap.add_argument("--tranco", default="data/external/tranco.csv", help="Tranco CSV for Experiment 2")
    ap.add_argument("--tranco-n", type=int, default=200_000)
    ap.add_argument("--e2-epochs", type=int, default=3, help="Experiment 2 training epochs (Phase 1 used 3)")
    ap.add_argument("--only-e2", action="store_true", help="M2: run only Experiment 2")
    ap.add_argument("--iforest", action="store_true", help="also run the Isolation Forest baseline (CPU)")
    ap.add_argument("--iforest-only", action="store_true", help="run only the Isolation Forest baseline")
    ap.add_argument("--weights", default="models/weights", help="where the trained models are saved")
    ap.add_argument("--out", default="results", help="results folder (<out>/<model>/<run>.json)")
    ap.add_argument(
        "--skip-existing",
        action="store_true",
        help="skip runs whose results (and saved model) already exist, e.g. after a Colab disconnect",
    )
    ap.add_argument("--rerun", nargs="*", default=[], help="run names to redo even with --skip-existing")
    ap.add_argument("--migrate-layout", action="store_true", help="move old <run>_<variant>.json results first")
    ap.add_argument(
        "--rescore", action="store_true", help="M2: re-score all runs with the saved models in --weights (no training)"
    )
    ap.add_argument("--extra", default="", help="extra arguments for every run (tests: '--dataset synthetic')")
    a = ap.parse_args(argv)
    if not (a.iforest_only or a.rescore) and not (a.phase1_bpe and a.phase1_char):
        ap.error("--phase1-bpe and --phase1-char are required unless --iforest-only or --rescore")

    out, extra = Path(a.out), a.extra.split()
    if a.migrate_layout:
        migrate_layout(out)
    if a.build_testbed:
        build_testbed(Path(a.build_testbed), Path(a.manifest))

    def done(model: str, name: str, saved: str | None = None) -> list[Path] | None:
        if not a.skip_existing or name in a.rerun:
            return None
        return [out / model / f"{name}.json"] + ([Path(saved) / "m2_config.json"] if saved else [])

    if a.rescore:
        rescore(a, out, extra)
    elif not a.iforest_only:
        for tok in a.tokenizers:
            model = "m2" if tok == "bpe" else "m2_ablation1_char"
            tag = [] if tok == "bpe" else ["--tag", "ablation1_char"]
            phase1 = a.phase1_bpe if tok == "bpe" else a.phase1_char
            cic_model = f"{a.weights}/m2_{tok}_cic"
            testbed_model = f"{a.weights}/m2_{tok}_testbed"
            scratch_model = f"{a.weights}/m2_{tok}_testbed_scratch"
            common = ["-m", "models.m2_run", "--model", "m2", "--tokenizer", tok, "--batch-size", str(a.batch_size)]
            common += ["--out", a.out, *tag, *extra]
            e2 = ["--exp", "E2", "--epochs", str(a.e2_epochs), "--tranco", a.tranco, "--tranco-n", str(a.tranco_n)]
            run([*common, *e2, "--save-model", cic_model], done(model, "E2", cic_model))
            if a.only_e2:
                continue
            e1 = ["--exp", "E1", "--init-from", phase1, "--lr", str(a.continue_lr), "--epochs", str(a.continue_epochs)]
            run([*common, *e1, "--save-model", testbed_model], done(model, "E1", testbed_model))
            for tool in TOOLS:
                e3 = ["--exp", "E3", "--holdout", tool, "--load-model", testbed_model]
                run([*common, *e3], done(model, f"E3_{tool}"))
            # the E2 model held out its threshold rows per capture, so they were never trained on
            run([*common, "--exp", "E4_cic2testbed", "--load-model", cic_model], done(model, "E4_cic2testbed"))
            e4 = ["--exp", "E4_testbed2cic", "--epochs", str(a.scratch_epochs), "--save-model", scratch_model]
            run([*common, *e4], done(model, "E4_testbed2cic", scratch_model))

    if a.iforest or a.iforest_only:
        common = ["-m", "models.m2_run", "--model", "iforest", "--out", a.out, *extra]
        if_model = f"{a.weights}/iforest_testbed.joblib"
        e1_done = done("iforest", "E1")
        run([*common, "--exp", "E1", "--save-model", if_model], e1_done and [*e1_done, Path(if_model)])
        for tool in TOOLS:
            run([*common, "--exp", "E3", "--holdout", tool, "--load-model", if_model], done("iforest", f"E3_{tool}"))
        for exp in ("E4_cic2testbed", "E4_testbed2cic", "E2"):
            run([*common, "--exp", exp], done("iforest", exp))

    files = sorted(str(p) for p in out.glob("*/E[1234]*.json"))
    run(["contracts.py", *files])


if __name__ == "__main__":
    main()
