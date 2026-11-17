"""M2 Phase 2 in one command: Experiments 1, 3 and 4 for DNS-BERT (BPE + character
tokenizer, ablation 1), with per-host averaging. Needs a GPU for reasonable time.

    python scripts/m2_phase2.py --phase1-bpe <ckpt_bpe_v2>/last --phase1-char <ckpt_char_v2>/last

Optionally builds the testbed table first from the extracted capture zips:

    python scripts/m2_phase2.py --build-testbed data/raw/testbed --phase1-bpe ... --phase1-char ...

What each run does (one tokenizer at a time; character runs carry the tag ablation1_char):
  E1              continue pre-training the Phase 1 model on testbed benign (benign only), score testbed test
  E3_<tool> x4    M2 trains on benign only, so the E1 model is reused; only the test set changes
  E4_cic2testbed  the Phase 1 model (CIC benign + Tranco, never saw the testbed) scores testbed test
  E4_testbed2cic  a new model trained from scratch on testbed benign only (no Tranco, which overlaps
                  CIC's scripted top-site lookups) scores CIC test
Every run also writes <run>_hostavg.json (per-host averaging).
With --skip-existing, runs whose results (and saved model) exist are skipped, so after a
Colab disconnect the same command picks up where it stopped.
"""
from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from pathlib import Path

TOOLS = ["dns2tcp", "dnscat2", "dnsexfiltrator", "iodine"]
# Team decision (Trello, 17 Nov, option A): this run captured the resolver's upstream side,
# so every query shows the resolver's address; it is left out of the testbed table.
EXCLUDE = ["benign_4h_with-tools_20261115T140757Z"]


def run(args: list[str], skip_if: list[Path] | None = None) -> None:
    """Run one step; skip it when every file in skip_if already exists (resume after a disconnect)."""
    if skip_if and all(p.exists() for p in skip_if):
        print(f"\n[skip] already done: {skip_if[0]}", flush=True)
        return
    print("\n$ python " + " ".join(args), flush=True)
    subprocess.run([sys.executable, *args], check=True)


def build_testbed(raw: Path, manifest: Path) -> None:
    rows = list(csv.DictReader(open(manifest, encoding="utf-8")))
    caps, tools = [], {}
    for r in rows:
        if any(x in r["file"] for x in EXCLUDE):
            continue
        ms = int(r["throttle_ms"] or 0)
        caps += ["--capture", f"{raw / r['file']}" + (f"@{ms}" if ms else "")]
        if r["tool"] != "benign" and r["client_ip"]:
            tools[r["client_ip"]] = r["tool"]
    tmap = ",".join(f"{ip}={t}" for ip, t in sorted(tools.items()))
    run(["-m", "parser", "testbed", *caps, "--tools-map", tmap, "--out", "data/processed/testbed/queries.parquet"])
    run(["contracts.py", "data/processed/testbed/queries.parquet"])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phase1-bpe", required=True, help="Phase 1 BPE model folder (e.g. <ckpt_bpe_v2>/last)")
    ap.add_argument("--phase1-char", required=True, help="Phase 1 character model folder")
    ap.add_argument("--build-testbed", help="folder with the extracted capture zips (benign/, tools/)")
    ap.add_argument("--manifest", default="data/raw/manifest.csv")
    ap.add_argument("--tokenizers", nargs="+", default=["bpe", "char"], choices=["bpe", "char"])
    ap.add_argument("--continue-epochs", type=int, default=10, help="continued pre-training on testbed benign")
    ap.add_argument("--continue-lr", type=float, default=1e-4)
    ap.add_argument("--scratch-epochs", type=int, default=30, help="E4_testbed2cic model from scratch")
    ap.add_argument("--batch-size", type=int, default=512)
    ap.add_argument("--weights", default="models/weights", help="where the trained models are saved")
    ap.add_argument("--out", default="results", help="results folder (writes <out>/m2/...)")
    ap.add_argument("--skip-existing", action="store_true",
                    help="skip runs whose results (and saved model) already exist, e.g. after a Colab disconnect")
    ap.add_argument("--extra", default="", help="extra arguments for every run (tests: '--dataset synthetic')")
    a = ap.parse_args(argv)

    if a.build_testbed:
        build_testbed(Path(a.build_testbed), Path(a.manifest))
    extra = a.extra.split()
    out_m2 = Path(a.out) / "m2"

    def done(name: str, tag: str, model: str | None = None) -> list[Path] | None:
        if not a.skip_existing:
            return None
        files = [out_m2 / f"{name}{'_' + tag if tag else ''}.json"]
        return files + ([Path(model) / "m2_config.json"] if model else [])

    for tok in a.tokenizers:
        phase1 = a.phase1_bpe if tok == "bpe" else a.phase1_char
        tag_name = "" if tok == "bpe" else "ablation1_char"
        tag = ["--tag", tag_name] if tag_name else []
        testbed_model = f"{a.weights}/m2_{tok}_testbed"
        scratch_model = f"{a.weights}/m2_{tok}_testbed_scratch"
        common = ["-m", "models.m2_run", "--model", "m2", "--batch-size", str(a.batch_size), "--out", a.out,
                  *tag, *extra]
        run([*common, "--exp", "E1", "--init-from", phase1, "--lr", str(a.continue_lr),
             "--epochs", str(a.continue_epochs), "--save-model", testbed_model],
            done("E1", tag_name, testbed_model))
        for tool in TOOLS:
            run([*common, "--exp", "E3", "--holdout", tool, "--load-model", testbed_model],
                done(f"E3_{tool}", tag_name))
        run([*common, "--exp", "E4_cic2testbed", "--load-model", phase1], done("E4_cic2testbed", tag_name))
        run([*common, "--exp", "E4_testbed2cic", "--tokenizer", tok, "--epochs", str(a.scratch_epochs),
             "--save-model", scratch_model], done("E4_testbed2cic", tag_name, scratch_model))
    run(["contracts.py", *sorted(str(p) for p in out_m2.glob("E[134]*.json"))])


if __name__ == "__main__":
    main()
