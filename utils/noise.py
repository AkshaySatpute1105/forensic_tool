"""
noise.py - Noise-level and compression-artifact analysis, plus clone detection.

Noise analysis
--------------
A genuine photo has sensor noise that is statistically consistent across the
frame. Spliced or retouched regions often carry a different noise level
(because they came from another image or were smoothed/filtered).

Steps:
  1. Extract the high-frequency residual:  residual = gray - median_blur(gray)
  2. Compute residual std-dev in 32x32 blocks  -> local noise map
  3. Measure inconsistency (coefficient of variation + robust outliers)
  4. Estimate global sigma (Immerkaer's fast method)
  5. Estimate JPEG blocking (8x8 boundary discontinuity ratio)
"""
import os

import cv2
import numpy as np

BLOCK = 32


def _immerkaer_sigma(gray):
    """Immerkaer (1996) fast noise sigma estimation."""
    k = np.array([[1, -2, 1], [-2, 4, -2], [1, -2, 1]], dtype=np.float32)
    h, w = gray.shape
    if h < 3 or w < 3:
        return 0.0
    conv = cv2.filter2D(gray.astype(np.float32), -1, k)[1:-1, 1:-1]
    return float(np.sqrt(np.pi / 2) * np.abs(conv).sum() / (6.0 * (w - 2) * (h - 2)))


def _blockiness(gray):
    """
    Ratio of mean gradient at 8-px block boundaries vs elsewhere.
    ~1.0 = no visible JPEG blocking; >1.2 = blocking artifacts.
    """
    g = gray.astype(np.float32)
    dx = np.abs(np.diff(g, axis=1))
    cols = np.arange(dx.shape[1])
    at_edge = dx[:, (cols % 8) == 7].mean() if dx.shape[1] > 8 else 0
    inside = dx[:, (cols % 8) != 7].mean() if dx.shape[1] > 8 else 1
    return float(at_edge / (inside + 1e-6))


def analyze_noise(path, out_dir, prefix):
    """Return noise statistics and write a heat-map image <prefix>_noise.png."""
    bgr = cv2.imread(path, cv2.IMREAD_COLOR)
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape

    # High-frequency residual
    residual = gray.astype(np.float32) - cv2.medianBlur(gray, 3).astype(np.float32)

    bh, bw = max(1, h // BLOCK), max(1, w // BLOCK)
    if h < BLOCK or w < BLOCK:
        block_std = np.array([[residual.std()]])
    else:
        r = residual[: bh * BLOCK, : bw * BLOCK].reshape(bh, BLOCK, bw, BLOCK)
        block_std = r.std(axis=(1, 3))

    mean_n, std_n = float(block_std.mean()), float(block_std.std())
    cv = std_n / (mean_n + 1e-6)

    # Robust outlier detection (blocks whose noise differs strongly from median)
    med = float(np.median(block_std))
    mad = float(np.median(np.abs(block_std - med))) * 1.4826 or 1e-6
    outliers = np.abs(block_std - med) > 5.0 * mad
    outlier_pct = float(outliers.mean() * 100)

    # Heat-map
    norm = cv2.normalize(block_std, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
    heat = cv2.applyColorMap(cv2.resize(norm, (w, h), interpolation=cv2.INTER_NEAREST),
                             cv2.COLORMAP_JET)
    blended = cv2.addWeighted(bgr, 0.35, heat, 0.65, 0)
    out_path = os.path.join(out_dir, f"{prefix}_noise.png")
    cv2.imwrite(out_path, blended)

    sigma = _immerkaer_sigma(gray)
    blocking = _blockiness(gray)

    findings = []
    if cv > 0.6:
        findings.append(f"High variation of local noise (CV={cv:.2f}) - noise is not uniform across the image.")
    if outlier_pct > 20:
        findings.append(f"{outlier_pct:.1f}% of blocks have noise statistically different from the rest (possible spliced/smoothed areas).")
    if sigma < 0.8:
        findings.append("Extremely low noise - image may be heavily denoised, smoothed or synthetic.")
    if blocking > 1.5:
        findings.append(f"Visible 8x8 JPEG blocking (ratio {blocking:.2f}) - strong compression or double compression.")

    if blocking > 1.5:
        comp = "Heavy"
    elif blocking > 1.15:
        comp = "Moderate"
    else:
        comp = "Low / none"

    score = min(100, int(len(findings) * 25 + min(cv, 1) * 10))
    status = "Consistent" if not findings else ("Inconsistent" if len(findings) >= 2 else "Minor anomalies")

    return {
        "noise_image": os.path.basename(out_path),
        "sigma": round(sigma, 3),
        "mean_block_noise": round(mean_n, 3),
        "std_block_noise": round(std_n, 3),
        "coef_variation": round(cv, 3),
        "outlier_percent": round(outlier_pct, 2),
        "blockiness": round(blocking, 3),
        "compression_artifacts": comp,
        "findings": findings,
        "status": status,
        "score": score,
    }


# --------------------------------------------------------------------------
# Clone (copy-move) detection
# --------------------------------------------------------------------------
def detect_clones(path, out_dir, prefix, max_side=1200, min_shift=40):
    """
    Copy-move forgery detection using ORB keypoints.

    1. Detect ORB keypoints/descriptors.
    2. Match the descriptor set against ITSELF (k=3, first hit is the point itself).
    3. Keep matches passing Lowe's ratio test whose pixel distance > min_shift.
    4. Validate with RANSAC (affine) - consistent geometric transform = clone.
    5. Draw bounding boxes around source and destination regions.
    """
    bgr = cv2.imread(path, cv2.IMREAD_COLOR)
    h0, w0 = bgr.shape[:2]
    scale = min(1.0, max_side / max(h0, w0))
    if scale < 1.0:
        bgr = cv2.resize(bgr, (int(w0 * scale), int(h0 * scale)), interpolation=cv2.INTER_AREA)
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)

    orb = cv2.ORB_create(nfeatures=4000, fastThreshold=10)
    kps, desc = orb.detectAndCompute(gray, None)
    result = {"detected": False, "matches": 0, "regions": 0, "image": None,
              "keypoints": len(kps) if kps else 0, "summary": ""}

    out_path = os.path.join(out_dir, f"{prefix}_clone.png")
    vis = bgr.copy()

    if desc is None or len(kps) < 20:
        cv2.imwrite(out_path, vis)
        result.update(image=os.path.basename(out_path),
                      summary="Not enough texture/keypoints for clone detection.")
        return result

    matcher = cv2.BFMatcher(cv2.NORM_HAMMING)
    knn = matcher.knnMatch(desc, desc, k=3)
    src, dst = [], []
    for m in knn:
        if len(m) < 3:
            continue
        # m[0] is the keypoint itself; compare 2nd and 3rd best.
        if m[1].distance < 0.6 * m[2].distance:
            p1 = np.array(kps[m[1].queryIdx].pt)
            p2 = np.array(kps[m[1].trainIdx].pt)
            if np.linalg.norm(p1 - p2) > min_shift:
                src.append(p1)
                dst.append(p2)

    result["matches"] = len(src)
    if len(src) >= 8:
        src_a, dst_a = np.float32(src), np.float32(dst)
        M, inl = cv2.estimateAffinePartial2D(src_a, dst_a, method=cv2.RANSAC,
                                             ransacReprojThreshold=3.0)
        if inl is not None and int(inl.sum()) >= 8:
            inl = inl.ravel().astype(bool)
            pts = np.vstack([src_a[inl], dst_a[inl]])
            # cluster the points into two groups (source / copy) with k-means
            if len(pts) >= 4:
                crit = (cv2.TERM_CRITERIA_EPS + cv2.TERM_CRITERIA_MAX_ITER, 20, 1.0)
                _, labels, _ = cv2.kmeans(pts, 2, None, crit, 5, cv2.KMEANS_PP_CENTERS)
                labels = labels.ravel()
                for lab, colour in ((0, (0, 0, 255)), (1, (0, 255, 0))):
                    group = pts[labels == lab]
                    if len(group) >= 3:
                        x, y, bw_, bh_ = cv2.boundingRect(group.astype(np.int32))
                        cv2.rectangle(vis, (x, y), (x + bw_, y + bh_), colour, 2)
                        result["regions"] += 1
            for a, b in zip(src_a[inl], dst_a[inl]):
                cv2.line(vis, tuple(int(v) for v in a), tuple(int(v) for v in b), (0, 255, 255), 1)
            result["detected"] = True
            result["matches"] = int(inl.sum())

    cv2.imwrite(out_path, vis)
    result["image"] = os.path.basename(out_path)
    if result["detected"]:
        result["summary"] = (f"{result['matches']} geometrically consistent keypoint pairs found - "
                             "likely copy-move (cloned) regions highlighted with boxes.")
    else:
        result["summary"] = "No significant duplicated regions detected."
    return result
