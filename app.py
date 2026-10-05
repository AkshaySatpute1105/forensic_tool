"""
app.py - Flask backend for the Digital Image Forensics Tool.

Routes
------
GET  /                         dashboard (single page application shell)
POST /api/analyze              upload one image -> full forensic analysis (JSON)
POST /api/compare              upload two images -> comparison (JSON)
POST /api/report/<case_id>     build PDF report (optionally with comparison)
GET  /api/report/<case_id>/download   download generated PDF
GET  /files/<name>             serve generated images / uploads safely
GET  /health                   health-check for deployment platforms
"""
import json
import os
import threading
import time
import uuid
from datetime import datetime

from flask import Flask, jsonify, render_template, request, send_from_directory, abort
from flask.json.provider import DefaultJSONProvider
from PIL import Image, UnidentifiedImageError
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from utils.metadata import extract_metadata
from utils.hashing import file_hashes, perceptual_hashes, check_expected_hash, find_duplicates
from utils.ela import run_ela
from utils.histogram import analyze_histogram
from utils.noise import analyze_noise, detect_clones
from utils.comparison import compare_images
from utils.conclusion import build_conclusion
from utils.report_generator import generate_report

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
REPORT_DIR = os.path.join(BASE_DIR, "static", "reports")
DATA_DIR = os.path.join(BASE_DIR, "data")          # JSON results (never served)
ALLOWED_EXT = {"jpg", "jpeg", "png", "bmp"}
ALLOWED_FORMATS = {"JPEG", "PNG", "BMP"}            # verified with Pillow, not just extension
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", 16))
MAX_PIXELS = 40_000_000                             # protects against decompression bombs
RETENTION_SECONDS = int(os.environ.get("RETENTION_HOURS", 24)) * 3600

for d in (UPLOAD_DIR, REPORT_DIR, DATA_DIR):
    os.makedirs(d, exist_ok=True)

Image.MAX_IMAGE_PIXELS = MAX_PIXELS
_lock = threading.Lock()                            # protects library.json writes


class NumpyJSONProvider(DefaultJSONProvider):
    """Serialise numpy scalar types that sneak into result dictionaries."""
    @staticmethod
    def default(o):
        try:
            import numpy as np
            if isinstance(o, np.integer):
                return int(o)
            if isinstance(o, np.floating):
                return float(o)
            if isinstance(o, np.ndarray):
                return o.tolist()
        except ImportError:
            pass
        return DefaultJSONProvider.default(o)


app = Flask(__name__)
app.json = NumpyJSONProvider(app)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", uuid.uuid4().hex)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
class UploadError(Exception):
    """Raised for user-correctable upload problems (returned as HTTP 400)."""


def allowed_extension(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def save_upload(file_storage, case_id, tag=""):
    """
    Validate and securely store an uploaded file.
      1. extension whitelist
      2. real content check with Pillow (rejects renamed non-images)
      3. format whitelist + pixel limit
      4. stored under a random UUID name (user filename is never used on disk)
    Returns (stored_path, original_name).
    """
    if file_storage is None or not file_storage.filename:
        raise UploadError("No file selected.")
    original = secure_filename(file_storage.filename) or "image"
    if not allowed_extension(original):
        raise UploadError(f"Unsupported file type. Allowed: {', '.join(sorted(ALLOWED_EXT)).upper()}.")

    ext = original.rsplit(".", 1)[1].lower()
    stored = os.path.join(UPLOAD_DIR, f"{case_id}{tag}_original.{ext}")
    file_storage.save(stored)

    try:
        with Image.open(stored) as im:
            fmt = im.format
            im.verify()                          # detects truncated / corrupt files
        if fmt not in ALLOWED_FORMATS:
            raise UploadError(f"File content is {fmt}, which is not supported.")
        with Image.open(stored) as im:
            w, h = im.size
        if w * h > MAX_PIXELS:
            raise UploadError("Image is too large (max 40 megapixels).")
        if w < 16 or h < 16:
            raise UploadError("Image is too small to analyse (minimum 16x16 px).")
    except UploadError:
        os.remove(stored)
        raise
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, SyntaxError):
        if os.path.exists(stored):
            os.remove(stored)
        raise UploadError("The file is not a valid or readable image.")
    return stored, original


def cleanup_old_files():
    """Delete uploads, outputs and result JSON older than the retention period."""
    cutoff = time.time() - RETENTION_SECONDS
    for folder in (UPLOAD_DIR, REPORT_DIR, DATA_DIR):
        for name in os.listdir(folder):
            if name.startswith(".") or name == "library.json":
                continue
            p = os.path.join(folder, name)
            try:
                if os.path.isfile(p) and os.path.getmtime(p) < cutoff:
                    os.remove(p)
            except OSError:
                pass


def load_library():
    path = os.path.join(DATA_DIR, "library.json")
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return []


def add_to_library(entry):
    with _lock:
        lib = load_library()
        if any(item["sha256"] == entry["sha256"] for item in lib):
            return                                # already catalogued
        lib.append(entry)
        lib = lib[-500:]                          # keep latest 500 entries
        with open(os.path.join(DATA_DIR, "library.json"), "w") as fh:
            json.dump(lib, fh)


def save_json(name, obj):
    with open(os.path.join(DATA_DIR, name), "w") as fh:
        json.dump(obj, fh, cls=json.JSONEncoder, default=lambda o: o.item() if hasattr(o, "item") else str(o))


def load_json(name):
    try:
        with open(os.path.join(DATA_DIR, name)) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def valid_id(value):
    """Case IDs are 12-char hex strings; reject anything else (path traversal safety)."""
    return isinstance(value, str) and len(value) == 12 and all(c in "0123456789abcdef" for c in value)


def analyze_image(path, original_name, case_id, expected_hash=""):
    """Run every forensic test on one image and return the combined result."""
    meta = extract_metadata(path, original_name)
    hashes = file_hashes(path)
    perceptual = perceptual_hashes(path)
    hash_check = check_expected_hash(hashes, expected_hash)
    duplicates = find_duplicates(perceptual["phash"], hashes["sha256"], load_library())

    ela = run_ela(path, UPLOAD_DIR, case_id)
    hist = analyze_histogram(path)
    noise = analyze_noise(path, UPLOAD_DIR, case_id)
    clone = detect_clones(path, UPLOAD_DIR, case_id)
    conclusion = build_conclusion(meta, ela, hist, noise, clone, duplicates)

    add_to_library({"name": original_name, "sha256": hashes["sha256"], "phash": perceptual["phash"]})

    return {
        "case_id": case_id,
        "prefix": case_id,
        "analyzed_at": datetime.now().strftime("%d %B %Y, %H:%M:%S"),
        "files": {"original": os.path.basename(path)},
        "metadata": meta,
        "hashes": hashes,
        "perceptual": perceptual,
        "hash_check": hash_check,
        "duplicates": duplicates,
        "ela": ela,
        "histogram": hist,
        "noise": noise,
        "clone": clone,
        "conclusion": conclusion,
    }


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.before_request
def block_direct_static_access():
    """Uploads/reports must only be reachable through the validated /files route."""
    if request.path.startswith(("/static/uploads/", "/static/reports/")):
        abort(404)


@app.route("/")
def index():
    return render_template("index.html", max_mb=MAX_UPLOAD_MB)


@app.route("/health")
def health():
    return jsonify(status="ok", time=datetime.now().isoformat())


@app.route("/files/<path:name>")
def serve_file(name):
    """Serve generated images from uploads dir (png/jpg/bmp only)."""
    name = os.path.basename(name)
    if not name.lower().endswith((".png", ".jpg", ".jpeg", ".bmp")):
        abort(404)
    return send_from_directory(UPLOAD_DIR, name, max_age=3600)


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    cleanup_old_files()
    case_id = uuid.uuid4().hex[:12]
    try:
        path, original = save_upload(request.files.get("image"), case_id)
        result = analyze_image(path, original, case_id, request.form.get("expected_hash", ""))
    except UploadError as exc:
        return jsonify(error=str(exc)), 400
    except Exception as exc:  # unexpected analysis failure
        app.logger.exception("Analysis failed")
        return jsonify(error=f"Analysis failed: {exc}"), 500
    save_json(f"{case_id}.json", result)
    return jsonify(result)


@app.route("/api/compare", methods=["POST"])
def api_compare():
    cleanup_old_files()
    cmp_id = uuid.uuid4().hex[:12]
    try:
        path_a, name_a = save_upload(request.files.get("image_a"), cmp_id, "_a")
        path_b, name_b = save_upload(request.files.get("image_b"), cmp_id, "_b")
        result = compare_images(path_a, path_b, name_a, name_b, UPLOAD_DIR, cmp_id)
    except UploadError as exc:
        return jsonify(error=str(exc)), 400
    except Exception as exc:
        app.logger.exception("Comparison failed")
        return jsonify(error=f"Comparison failed: {exc}"), 500
    result["comparison_id"] = cmp_id
    result["files"] = {"a": os.path.basename(path_a), "b": os.path.basename(path_b)}
    save_json(f"cmp_{cmp_id}.json", result)
    return jsonify(result)


@app.route("/api/report/<case_id>", methods=["POST"])
def api_report(case_id):
    if not valid_id(case_id):
        return jsonify(error="Invalid case id."), 400
    result = load_json(f"{case_id}.json")
    if not result:
        return jsonify(error="Case not found or expired. Please analyse the image again."), 404

    comparison = None
    cmp_id = (request.get_json(silent=True) or {}).get("comparison_id")
    if cmp_id:
        if not valid_id(cmp_id):
            return jsonify(error="Invalid comparison id."), 400
        comparison = load_json(f"cmp_{cmp_id}.json")

    out = os.path.join(REPORT_DIR, f"Forensic_Report_{case_id}.pdf")
    try:
        generate_report(result, UPLOAD_DIR, out, comparison)
    except Exception as exc:
        app.logger.exception("Report generation failed")
        return jsonify(error=f"Report generation failed: {exc}"), 500
    return jsonify(download=f"/api/report/{case_id}/download")


@app.route("/api/report/<case_id>/download")
def api_report_download(case_id):
    if not valid_id(case_id):
        abort(404)
    fname = f"Forensic_Report_{case_id}.pdf"
    if not os.path.exists(os.path.join(REPORT_DIR, fname)):
        abort(404)
    return send_from_directory(REPORT_DIR, fname, as_attachment=True)


# --------------------------------------------------------------------------
# Error handlers (always JSON for /api, friendly otherwise)
# --------------------------------------------------------------------------
@app.errorhandler(RequestEntityTooLarge)
def too_large(_):
    return jsonify(error=f"File too large. Maximum upload size is {MAX_UPLOAD_MB} MB."), 413


@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api"):
        return jsonify(error="Not found."), 404
    return render_template("index.html", max_mb=MAX_UPLOAD_MB), 404


@app.errorhandler(500)
def server_error(_):
    return jsonify(error="Internal server error."), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
