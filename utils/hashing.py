"""
hashing.py - Cryptographic and perceptual hashing.

* MD5 / SHA-256 prove file-level integrity (any 1-bit change alters them).
* Perceptual hashes (aHash, pHash, dHash, wHash) measure visual similarity,
  so resized / recompressed copies of the same picture can be detected.
"""
import hashlib

import imagehash
from PIL import Image


def file_hashes(path, chunk=1024 * 1024):
    """Return MD5 and SHA-256 hex digests of the file (streamed)."""
    md5, sha = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            md5.update(block)
            sha.update(block)
    return {"md5": md5.hexdigest(), "sha256": sha.hexdigest()}


def perceptual_hashes(path):
    """Return perceptual hash strings for the image."""
    with Image.open(path) as img:
        img = img.convert("RGB")
        return {
            "ahash": str(imagehash.average_hash(img)),
            "phash": str(imagehash.phash(img)),
            "dhash": str(imagehash.dhash(img)),
            "whash": str(imagehash.whash(img)),
        }


def hamming_similarity(hash_a, hash_b):
    """Similarity percent between two hex perceptual hashes (0-100)."""
    ha = imagehash.hex_to_hash(hash_a)
    hb = imagehash.hex_to_hash(hash_b)
    dist = ha - hb
    return round(100.0 * (1 - dist / len(ha.hash.flatten())), 2), int(dist)


def check_expected_hash(hashes, expected):
    """Compare a user-provided hash string against the computed hashes."""
    expected = (expected or "").strip().lower()
    if not expected:
        return None
    if len(expected) == 32:
        algo, ok = "MD5", expected == hashes["md5"]
    elif len(expected) == 64:
        algo, ok = "SHA-256", expected == hashes["sha256"]
    else:
        return {"algorithm": "Unknown", "matched": False,
                "message": "Hash length not recognised (expected 32 or 64 hex chars)."}
    return {
        "algorithm": algo,
        "matched": ok,
        "message": f"{algo} matches - file is IDENTICAL to the reference." if ok
                   else f"{algo} does NOT match - file differs from the reference.",
    }


def find_duplicates(current_phash, current_sha, library, threshold=6):
    """
    Search a library of previously analysed images for duplicates.
    library: list of dicts {name, sha256, phash}
    Returns list of matches (exact or near-duplicate).
    """
    matches = []
    ref = imagehash.hex_to_hash(current_phash)
    for item in library:
        if item["sha256"] == current_sha:
            matches.append({"name": item["name"], "type": "Exact duplicate",
                            "distance": 0, "similarity": 100.0})
            continue
        dist = ref - imagehash.hex_to_hash(item["phash"])
        if dist <= threshold:
            matches.append({"name": item["name"], "type": "Near duplicate (visually similar)",
                            "distance": int(dist),
                            "similarity": round(100 * (1 - dist / 64), 2)})
    return matches[:5]
