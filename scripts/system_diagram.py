"""Draw the report's system diagram (Fig. 2) as a grayscale PNG sized for one IEEE column.

    python scripts/system_diagram.py            # writes docs/system_diagram.png
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "docs" / "system_diagram.png"
W, H = 680, 536  # layout units; the figure is 3.5 in wide, one IEEE column
TITLE, SUB = 6.5, 6  # font sizes in points
FILL = {"source": "#e6e6e6", "step": "#ffffff"}

# (x, y, w, h, title, subtitle lines, kind) with y measured from the top
BOXES = [
    (32, 44, 212, 74, "Docker testbed (pcap)", ["4 DNS tunnelling tools", "and benign traffic"], "source"),
    (32, 132, 212, 74, "CIC-Bell-DNS-EXF-2021", ["Public benchmark (pcap)", "Exfiltration and benign"], "source"),
    (268, 97, 170, 56, "Shared parser", ["One query table"], "step"),
    (464, 97, 176, 56, "Features and splits", ["Time split, masked copy"], "step"),
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
    ((244, 81), (266, 112)), ((244, 169), (266, 138)), ((438, 125), (462, 125)), ((552, 153), (552, 222)),
    ((464, 252), (440, 252)), ((268, 252), (242, 252)), ((552, 280), (552, 350)),
    ((240, 380), (266, 380)), ((438, 380), (462, 380)), ((552, 408), (552, 434)), ((464, 464), (440, 464)),
]
AREAS = [(20, 20, 640, 276, "Offline: build and compare"), (20, 316, 640, 200, "Live: detect and explain")]


def main() -> None:
    plt.rcParams["font.family"] = "Times New Roman"
    fig = plt.figure(figsize=(3.5, 3.5 * H / W), dpi=600)
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, W)
    ax.set_ylim(H, 0)
    ax.axis("off")
    for x, y, w, h, label in AREAS:
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=12", fill=False,
                                    linestyle=(0, (4, 3)), linewidth=0.5, edgecolor="#555555"))
        ax.text(x + 14, y + 13, label, fontsize=SUB, style="italic", va="center", color="#333333")
    for x, y, w, h, title, subs, kind in BOXES:
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=7", facecolor=FILL[kind],
                                    edgecolor="black", linewidth=0.6))
        lines = len(subs)
        top = y + h / 2 - 9 * lines
        ax.text(x + w / 2, top, title, fontsize=TITLE, weight="bold", ha="center", va="center")
        for i, s in enumerate(subs):
            ax.text(x + w / 2, top + 19 * (i + 1), s, fontsize=SUB, ha="center", va="center", color="#222222")
    for a, b in ARROWS:
        ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>", mutation_scale=5, linewidth=0.6, color="black"))
    ax.text(562, 306, "Selected M1", fontsize=SUB, va="center", color="#222222")
    OUT.parent.mkdir(exist_ok=True)
    fig.savefig(OUT, dpi=600, facecolor="white")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
