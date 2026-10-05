"""
comparison.py - Compare two images (resolution, hashes, similarity,
metadata differences and pixel differences).
"""
import os

import cv2
import numpy as np
from skimage.metrics import structural_similarity as ssim

from .hashing import file_hashes, perceptual_hashes, hamming_similarity
from .metadata import extract_metadata


def compare_images(path_a, path_b, name_a, name_b, out_dir, prefix):
    """Compare two images and write a difference heat-map <prefix>_diff.png."""
    meta_a = extract_metadata(path_a, name_a)
    meta_b = extract_metadata(path_b, name_b)
    h_a, h_b = file_hashes(path_a), file_hashes(path_b)
    p_a, p_b = perceptual_hashes(path_a), perceptual_hashes(path_b)

    # ---- resolution ----
    res = {
        "a": meta_a["basic"]["Dimensions"],
        "b": meta_b["basic"]["Dimensions"],
        "same": (meta_a["basic"]["Width"], meta_a["basic"]["Height"]) ==
                (meta_b["basic"]["Width"], meta_b["basic"]["Height"]),
    }

    # ---- hashes ----
    hashes = {
        "md5_a": h_a["md5"], "md5_b": h_b["md5"],
        "sha256_a": h_a["sha256"], "sha256_b": h_b["sha256"],
        "identical": h_a["sha256"] == h_b["sha256"],
    }
    perceptual = {}
    for k in ("ahash", "phash", "dhash", "whash"):
        sim, dist = hamming_similarity(p_a[k], p_b[k])
        perceptual[k] = {"a": p_a[k], "b": p_b[k], "similarity": sim, "distance": dist}
    perceptual_sim = round(float(np.mean([v["similarity"] for v in perceptual.values()])), 2)

    # ---- pixel level (resize B to A if sizes differ) ----
    img_a = cv2.imread(path_a, cv2.IMREAD_COLOR)
    img_b = cv2.imread(path_b, cv2.IMREAD_COLOR)
    resized = False
    if img_a.shape != img_b.shape:
        img_b = cv2.resize(img_b, (img_a.shape[1], img_a.shape[0]), interpolation=cv2.INTER_AREA)
        resized = True

    diff = cv2.absdiff(img_a, img_b)
    diff_gray = cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY)
    changed_pct = float((diff_gray > 10).mean() * 100)
    mse = float(np.mean((img_a.astype(np.float32) - img_b.astype(np.float32)) ** 2))
    psnr = float("inf") if mse == 0 else float(10 * np.log10(255.0 ** 2 / mse))

    ga = cv2.cvtColor(img_a, cv2.COLOR_BGR2GRAY)
    gb = cv2.cvtColor(img_b, cv2.COLOR_BGR2GRAY)
    ssim_val = float(ssim(ga, gb, data_range=255)) if min(ga.shape) >= 7 else 1.0

    # Heat-map and highlighted-changes image
    amp = cv2.normalize(diff_gray, None, 0, 255, cv2.NORM_MINMAX)
    heat = cv2.applyColorMap(amp, cv2.COLORMAP_INFERNO)
    out_path = os.path.join(out_dir, f"{prefix}_diff.png")
    cv2.imwrite(out_path, heat)

    # ---- metadata differences ----
    diffs = []
    skip = {"File Name", "File Size (bytes)", "Width", "Height"}
    for key, va in meta_a["basic"].items():
        if key in skip:
            continue
        vb = meta_b["basic"].get(key)
        diffs.append({"field": key, "a": str(va), "b": str(vb), "different": str(va) != str(vb)})

    similarity_pct = round(0.6 * ssim_val * 100 + 0.4 * perceptual_sim, 2)
    if hashes["identical"]:
        verdict = "IDENTICAL - files are bit-for-bit the same."
    elif similarity_pct >= 95:
        verdict = "Visually near-identical - likely the same picture re-saved/re-compressed or minimally edited."
    elif similarity_pct >= 75:
        verdict = "Similar - same scene with moderate modifications."
    else:
        verdict = "Different - images do not appear to share the same content."

    return {
        "name_a": name_a, "name_b": name_b,
        "resolution": res,
        "hashes": hashes,
        "perceptual": perceptual,
        "perceptual_similarity": perceptual_sim,
        "ssim": round(ssim_val, 4),
        "similarity_percent": similarity_pct,
        "pixel": {
            "changed_percent": round(changed_pct, 2),
            "mse": round(mse, 3),
            "psnr": None if psnr == float("inf") else round(psnr, 2),
            "max_difference": int(diff_gray.max()),
            "resized_for_comparison": resized,
        },
        "metadata_diff": diffs,
        "metadata_diff_count": sum(1 for d in diffs if d["different"]),
        "diff_image": os.path.basename(out_path),
        "verdict": verdict,
    }
