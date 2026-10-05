"""
conclusion.py - Combine individual test results into an overall forensic verdict.

Weighted risk model (0 = looks authentic, 100 = highly likely manipulated):
    ELA 35 %, Noise 20 %, Metadata 20 %, Clone 15 %, Histogram 10 %
This is a transparent heuristic (not a trained model) so that an examiner
can explain exactly how the conclusion was reached.
"""

WEIGHTS = {"ela": 0.35, "noise": 0.20, "metadata": 0.20, "clone": 0.15, "histogram": 0.10}


def _metadata_score(meta):
    """Score metadata indicators 0-100."""
    score = 0
    if not meta["has_exif"]:
        score += 40
    for flag in meta["flags"]:
        if "Image-editing software detected" in flag:
            score += 60
        elif "modification time" in flag.lower():
            score += 25
        elif "Software tag" in flag:
            score += 15
    return min(100, score)


def build_conclusion(meta, ela, hist, noise, clone, duplicates=None):
    """Return {risk_score, verdict, level, reasons[], recommendations[]}."""
    parts = {
        "ela": ela["score"],
        "noise": noise["score"],
        "metadata": _metadata_score(meta),
        "clone": 90 if clone["detected"] else 0,
        "histogram": hist["score"],
    }
    risk = sum(parts[k] * WEIGHTS[k] for k in parts)
    # A positive clone detection or editor tag is strong evidence on its own.
    if clone["detected"]:
        risk = max(risk, 60)
    if any("Image-editing software detected" in f for f in meta["flags"]):
        risk = max(risk, 45)
    risk = round(min(100, risk), 1)

    if risk < 25:
        level, verdict = "Low", "Likely AUTHENTIC - no significant signs of manipulation found."
    elif risk < 50:
        level, verdict = "Medium", "INCONCLUSIVE / POSSIBLY EDITED - some anomalies need manual review."
    else:
        level, verdict = "High", "LIKELY MANIPULATED - multiple forensic indicators of tampering detected."

    reasons = []
    reasons += meta["flags"]
    if ela["level"] != "Low":
        reasons.append(f"ELA: {ela['summary']} ({ela['suspicious_regions']} region(s), {ela['suspicious_percent']}% blocks flagged).")
    reasons += [f"Noise: {f}" for f in noise["findings"]]
    reasons += [f"Histogram: {f}" for f in hist["findings"]]
    if clone["detected"]:
        reasons.append("Clone detection: " + clone["summary"])
    for d in duplicates or []:
        reasons.append(f"Duplicate library match: {d['name']} ({d['type']}, {d['similarity']}% similar).")
    if not reasons:
        reasons.append("All tests returned values within normal ranges.")

    recs = [
        "Treat results as indicators, not proof - confirm with additional evidence and expert review.",
        "Preserve the original file and record its SHA-256 hash to maintain chain of custody.",
    ]
    if risk >= 25:
        recs.append("Locate the original source/camera file and compare against this copy.")
    if ela.get("note"):
        recs.append(ela["note"])

    return {"risk_score": risk, "level": level, "verdict": verdict,
            "reasons": reasons, "recommendations": recs, "components": parts}
