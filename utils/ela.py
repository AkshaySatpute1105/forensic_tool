"""
ela.py - Error Level Analysis (ELA).

THEORY
------
JPEG is a lossy format. Every time a region is saved at quality Q it
accumulates a roughly *uniform* amount of error. If we re-save the image
at a known quality (e.g. 90 %) and subtract it from the original:

  * Regions that were already compressed the same number of times show
    LOW, uniform error (dark).
  * Regions that were pasted in / edited / drawn on (and therefore have a
    different compression history) show HIGHER error (bright).

ELA is therefore an *indicator*, not proof; it must be interpreted by an
analyst together with the other tests.
"""
import io
import os

import cv2
import numpy as np
from PIL import Image, ImageChops

BLOCK = 16  # block size (px) for regional statistics


def run_ela(path, out_dir, prefix, quality=90, scale=None):
    """
    Perform ELA and write two images into out_dir:
        <prefix>_ela.png      - amplified error image
        <prefix>_ela_overlay.png - original with suspicious blocks outlined
    Returns a dict with statistics, verdict and file names.
    """
    original = Image.open(path).convert("RGB")

    # 1. Re-compress at known quality into memory.
    buf = io.BytesIO()
    original.save(buf, "JPEG", quality=quality)
    buf.seek(0)
    resaved = Image.open(buf).convert("RGB")

    # 2. Absolute difference between original and re-saved image.
    diff = ImageChops.difference(original, resaved)
    diff_np = np.asarray(diff).astype(np.float32)

    # 3. Amplify so that differences are visible.
    max_diff = float(diff_np.max()) or 1.0
    if scale is None:
        scale = 255.0 / max_diff
    ela_np = np.clip(diff_np * scale, 0, 255).astype(np.uint8)
    ela_path = os.path.join(out_dir, f"{prefix}_ela.png")
    Image.fromarray(ela_np).save(ela_path)

    # 4. Block-wise statistics to locate regions with abnormal error level.
    gray_err = diff_np.mean(axis=2)
    h, w = gray_err.shape
    bh, bw = max(1, h // BLOCK), max(1, w // BLOCK)
    if h < BLOCK or w < BLOCK:
        blocks = np.array([[gray_err.mean()]])
    else:
        blocks = gray_err[: bh * BLOCK, : bw * BLOCK] \
            .reshape(bh, BLOCK, bw, BLOCK).mean(axis=(1, 3))

    mean_b, std_b = float(blocks.mean()), float(blocks.std()) or 1e-6
    # Robust threshold: median + 3 * MAD-derived sigma (resists outliers).
    med = float(np.median(blocks))
    mad = float(np.median(np.abs(blocks - med))) * 1.4826 or 1e-6
    thr = med + 6.0 * mad
    mask = blocks > max(thr, mean_b + 3 * std_b)
    suspicious_ratio = float(mask.mean())

    # 5. Draw outlines of suspicious blocks on the original.
    overlay = cv2.cvtColor(np.asarray(original), cv2.COLOR_RGB2BGR)
    mask_img = cv2.resize(mask.astype(np.uint8) * 255, (bw * BLOCK, bh * BLOCK),
                          interpolation=cv2.INTER_NEAREST)
    mask_img = cv2.morphologyEx(mask_img, cv2.MORPH_CLOSE, np.ones((5, 5), np.uint8))
    contours, _ = cv2.findContours(mask_img, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    regions = 0
    for c in contours:
        if cv2.contourArea(c) >= BLOCK * BLOCK * 4:  # ignore tiny isolated areas
            x, y, cw, ch = cv2.boundingRect(c)
            cv2.rectangle(overlay, (x, y), (x + cw, y + ch), (0, 0, 255), 2)
            regions += 1
    overlay_path = os.path.join(out_dir, f"{prefix}_ela_overlay.png")
    cv2.imwrite(overlay_path, overlay)

    # 6. Verdict / score (0-100).
    score = min(100.0, suspicious_ratio * 500 + regions * 6)
    if score < 20:
        level, text = "Low", "Error levels are fairly uniform. No obvious sign of localized editing."
    elif score < 45:
        level, text = "Medium", "Some regions show a different error level. Possible local editing or re-compression."
    else:
        level, text = "High", "Distinct regions have significantly different error levels, consistent with splicing or editing."

    fmt = (Image.open(path).format or "").upper()
    note = None
    if fmt != "JPEG":
        note = ("Source is not JPEG (%s). ELA is most reliable for JPEG files; "
                "lossless formats may show uniform or misleading results." % fmt)

    return {
        "ela_image": os.path.basename(ela_path),
        "overlay_image": os.path.basename(overlay_path),
        "quality": quality,
        "max_error": round(max_diff, 2),
        "mean_error": round(float(gray_err.mean()), 3),
        "std_error": round(float(gray_err.std()), 3),
        "suspicious_percent": round(suspicious_ratio * 100, 2),
        "suspicious_regions": regions,
        "score": round(score, 1),
        "level": level,
        "summary": text,
        "note": note,
    }
