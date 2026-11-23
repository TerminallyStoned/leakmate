"""Draw the system diagram (report Fig. 2, README) as PNGs sized for one IEEE column.

python scripts/system_diagram.py   # docs/images/system_diagram.png (grayscale, report and light README)
                                   # docs/images/system_diagram_dark.png (dark README)
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

IMAGES = Path(__file__).resolve().parents[1] / "docs" / "images"
W, H = 680, 536  # layout units; the figure is 3.5 in wide, one IEEE column
TITLE, SUB = 6.5, 6  # font sizes in points
# GitHub's dark page is #0d1117: the dark version is transparent with light lines, so it sits on it
THEMES = {
    "system_diagram.png": dict(
        source="#e6e6e6", step="#ffffff", ink="#000000", soft="#222222", label="#333333", area="#555555", bg="white"
    ),
    "system_diagram_dark.png": dict(
        source="#30363d", step="#161b22", ink="#e6edf3", soft="#c9d1d9", label="#c9d1d9", area="#8b949e", bg="none"
    ),
}

# (x, y, w, h, title, subtitle lines, kind) with y measured from the top
BOXES = [
    (32, 44, 212, 74, "Docker testbed (pcap)", ["4 DNS tunnelling tools", "and benign traffic"], "source"),
    (32, 132, 212, 74, "CIC-Bell-DNS-EXF-2021", ["Public benchmark (pcap)", "Exfiltration and benign"], "source"),
    (268, 97, 170, 56, "Shared parser", ["One query table"], "step"),
    (464, 97, 176, 56, "Experiment splits", ["Time split, masked copy"], "step"),
    (464, 224, 176, 56, "Three models", ["M1, M2, M3, baselines"], "step"),
    (268, 224, 170, 56, "Evaluation module", ["Metrics, selection rule"], "step"),
    (40, 224, 200, 56, "Frozen results", ["Tables and figures"], "step"),
    (40, 352, 200, 56, "Lab network", ["Tunnel and benign traffic"], "source"),
    (268, 352, 170, 56, "Live sniffer", ["Same code as offline"], "step"),
    (464, 352, 176, 56, "M1 scorer", ["Score and SHAP reasons"], "step"),
    (464, 436, 176, 56, "Alerts database", ["SQLite, one row per alert"], "step"),
    (268, 436, 170, 56, "Dashboard", ["Results, live alerts"], "step"),
]
ARROWS = [
    ((244, 81), (266, 112)),
    ((244, 169), (266, 138)),
    ((438, 125), (462, 125)),
    ((552, 153), (552, 222)),
    ((464, 252), (440, 252)),
    ((268, 252), (242, 252)),
    ((552, 280), (552, 350)),
    ((240, 380), (266, 380)),
    ((438, 380), (462, 380)),
    ((552, 408), (552, 434)),
    ((464, 464), (440, 464)),
]
AREAS = [(20, 20, 640, 276, "Offline: build and compare"), (20, 316, 640, 200, "Live: detect and explain")]


def draw(name: str, c: dict) -> None:
    fig = plt.figure(figsize=(3.5, 3.5 * H / W), dpi=600)
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, W)
    ax.set_ylim(H, 0)
    ax.axis("off")
    for x, y, w, h, label in AREAS:
        ax.add_patch(
            FancyBboxPatch(
                (x, y),
                w,
                h,
                boxstyle="round,pad=0,rounding_size=12",
                fill=False,
                linestyle=(0, (4, 3)),
                linewidth=0.5,
                edgecolor=c["area"],
            )
        )
        ax.text(x + 14, y + 13, label, fontsize=TITLE, va="center", color=c["label"])
    for x, y, w, h, title, subs, kind in BOXES:
        ax.add_patch(
            FancyBboxPatch(
                (x, y),
                w,
                h,
                boxstyle="round,pad=0,rounding_size=7",
                facecolor=c[kind],
                edgecolor=c["ink"],
                linewidth=0.6,
            )
        )
        lines = len(subs)
        top = y + h / 2 - 9 * lines
        ax.text(x + w / 2, top, title, fontsize=TITLE, weight="bold", ha="center", va="center", color=c["ink"])
        for i, s in enumerate(subs):
            ax.text(x + w / 2, top + 19 * (i + 1), s, fontsize=SUB, ha="center", va="center", color=c["soft"])
    for a, b in ARROWS:
        ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>", mutation_scale=5, linewidth=0.6, color=c["ink"]))
    ax.text(562, 306, "Selected M1", fontsize=SUB, va="center", color=c["soft"])
    out = IMAGES / name
    fig.savefig(out, dpi=600, facecolor=c["bg"], transparent=c["bg"] == "none")
    plt.close(fig)
    print(f"wrote {out}")


def main() -> None:
    plt.rcParams["font.family"] = "Times New Roman"
    IMAGES.mkdir(parents=True, exist_ok=True)
    for name, colours in THEMES.items():
        draw(name, colours)


if __name__ == "__main__":
    main()
