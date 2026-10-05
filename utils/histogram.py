"""
histogram.py - RGB / brightness histogram analysis.

Unusual histograms can reveal tonal manipulation:
  * Clipping spikes at 0 / 255        -> over-exposure or contrast stretching
  * "Comb" pattern (many empty bins)  -> Levels/Curves applied to 8-bit data
  * Very narrow dynamic range         -> low-contrast / heavy filtering
"""
import numpy as np
from PIL import Image


def analyze_histogram(path):
    """Return per-channel histograms (for Chart.js) plus anomaly statistics."""
    img = Image.open(path).convert("RGB")
    arr = np.asarray(img)
    gray = np.asarray(img.convert("L"))

    hist = {}
    for i, name in enumerate(("red", "green", "blue")):
        hist[name] = np.bincount(arr[:, :, i].ravel(), minlength=256).tolist()
    bright = np.bincount(gray.ravel(), minlength=256)
    hist["brightness"] = bright.tolist()

    total = gray.size
    findings = []

    # --- clipping ---
    clip_black = float(bright[:3].sum()) / total * 100
    clip_white = float(bright[-3:].sum()) / total * 100
    if clip_black > 5:
        findings.append(f"{clip_black:.1f}% of pixels are crushed to black (possible under-exposure/contrast boost).")
    if clip_white > 5:
        findings.append(f"{clip_white:.1f}% of pixels are clipped to white (possible over-exposure/contrast boost).")

    # --- comb / gap detection on luminance (inside the occupied range) ---
    nz = np.nonzero(bright)[0]
    lo, hi = int(nz.min()), int(nz.max())
    span = max(1, hi - lo + 1)
    empty = int((bright[lo:hi + 1] == 0).sum())
    gap_ratio = empty / span
    if span > 100 and gap_ratio > 0.25:
        findings.append(f"{gap_ratio*100:.0f}% of bins inside the tonal range are empty - 'comb' pattern typical of Levels/Curves edits.")

    # --- dynamic range ---
    if span < 128:
        findings.append(f"Narrow dynamic range ({lo}-{hi}); image may be low-contrast or heavily processed.")

    # --- spikes (a bin far above its neighbours) ---
    smooth = np.convolve(bright, np.ones(5) / 5, mode="same")
    spikes = int(((bright > 6 * (smooth + 1)) & (bright > total * 0.002)).sum())
    if spikes:
        findings.append(f"{spikes} abnormal histogram spike(s) detected (possible fill / clone / retouch).")

    # --- per-channel balance ---
    means = arr.reshape(-1, 3).mean(axis=0)
    if means.max() - means.min() > 40:
        findings.append("Strong colour-channel imbalance (colour cast or colour grading).")

    anomaly_score = min(100, len(findings) * 25)
    status = "Normal" if not findings else ("Suspicious" if len(findings) >= 2 else "Minor anomalies")

    return {
        "histograms": hist,
        "stats": {
            "mean_brightness": round(float(gray.mean()), 2),
            "std_brightness": round(float(gray.std()), 2),
            "min": lo, "max": hi,
            "mean_rgb": [round(float(m), 2) for m in means],
            "clip_black_pct": round(clip_black, 2),
            "clip_white_pct": round(clip_white, 2),
            "empty_bin_ratio": round(gap_ratio, 3),
        },
        "findings": findings,
        "status": status,
        "score": anomaly_score,
    }
