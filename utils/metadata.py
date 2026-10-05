"""
metadata.py - Metadata (EXIF) extraction and analysis.

Extracts file/image properties and camera EXIF data, then flags
indicators that commonly suggest editing (editing software tags,
missing EXIF, modified-after-captured timestamps, etc.).
"""
import os
from datetime import datetime

import exifread
from PIL import Image, ExifTags

# Keywords that indicate image-editing software in the "Software" tag.
EDITOR_KEYWORDS = [
    "photoshop", "gimp", "lightroom", "paint", "affinity", "pixlr",
    "canva", "snapseed", "picsart", "illustrator", "corel", "fotor",
    "photoscape", "paint.net", "krita", "capture one", "facetune",
]


def _to_degrees(values):
    """Convert exifread GPS rational triple (deg, min, sec) to float degrees."""
    d, m, s = [float(v.num) / float(v.den) if v.den else 0.0 for v in values]
    return d + m / 60.0 + s / 3600.0


def _extract_gps(tags):
    """Return GPS dict (lat/lon/maps link) from exifread tags, or None."""
    try:
        lat = tags.get("GPS GPSLatitude")
        lat_ref = tags.get("GPS GPSLatitudeRef")
        lon = tags.get("GPS GPSLongitude")
        lon_ref = tags.get("GPS GPSLongitudeRef")
        if not (lat and lon and lat_ref and lon_ref):
            return None
        latitude = _to_degrees(lat.values)
        longitude = _to_degrees(lon.values)
        if str(lat_ref.values) != "N":
            latitude = -latitude
        if str(lon_ref.values) != "E":
            longitude = -longitude
        return {
            "latitude": round(latitude, 6),
            "longitude": round(longitude, 6),
            "maps_url": f"https://www.google.com/maps?q={latitude:.6f},{longitude:.6f}",
        }
    except Exception:
        return None


def _compression_info(img):
    """Describe the compression scheme used by the image container."""
    fmt = (img.format or "UNKNOWN").upper()
    if fmt in ("JPEG", "JPG"):
        info = "JPEG (lossy, DCT-based)"
        # Estimate quality from first quantisation table if available.
        q = getattr(img, "quantization", None)
        if q:
            avg = sum(q[0]) / len(q[0])
            # Rough mapping: lower average quantisation value => higher quality.
            est = max(1, min(100, int(round(100 - avg * 1.1)))) if avg < 90 else 10
            info += f", est. quality ~{est}"
        return info
    if fmt == "PNG":
        return "PNG (lossless, DEFLATE)"
    if fmt == "BMP":
        return "BMP (uncompressed / RLE)"
    return fmt


def extract_metadata(path, original_name=None):
    """
    Extract metadata and return a dictionary with:
      basic       - file name, size, dimensions, etc.
      exif        - raw-ish EXIF key/value pairs (strings)
      gps         - dict or None
      flags       - list of suspicious indicators (strings)
      has_exif    - bool
    """
    original_name = original_name or os.path.basename(path)
    size_bytes = os.path.getsize(path)

    with Image.open(path) as img:
        width, height = img.size
        mode = img.mode
        fmt = img.format
        dpi = img.info.get("dpi")
        compression = _compression_info(img)

    if dpi:
        resolution = f"{round(float(dpi[0]))} x {round(float(dpi[1]))} DPI"
    else:
        resolution = "Not specified"

    # Parse EXIF using exifread (more complete than Pillow for MakerNotes).
    tags = {}
    try:
        with open(path, "rb") as fh:
            tags = exifread.process_file(fh, details=False)
    except Exception:
        tags = {}

    def get(tag):
        v = tags.get(tag)
        return str(v).strip() if v is not None else None

    camera_make = get("Image Make")
    camera_model = get("Image Model")
    software = get("Image Software")
    captured = get("EXIF DateTimeOriginal") or get("EXIF DateTimeDigitized")
    modified = get("Image DateTime")
    gps = _extract_gps(tags)

    # Pillow fallback when exifread finds nothing (e.g. some PNG eXIf chunks)
    if not tags:
        try:
            with Image.open(path) as img:
                exif = img.getexif()
                if exif:
                    named = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
                    camera_make = camera_make or str(named.get("Make", "")).strip() or None
                    camera_model = camera_model or str(named.get("Model", "")).strip() or None
                    software = software or str(named.get("Software", "")).strip() or None
                    modified = modified or str(named.get("DateTime", "")).strip() or None
        except Exception:
            pass

    # Build a readable EXIF table (skip huge binary blobs).
    exif_table = {}
    for k, v in tags.items():
        if k in ("JPEGThumbnail", "TIFFThumbnail", "Filename", "EXIF MakerNote"):
            continue
        s = str(v)
        exif_table[k] = s if len(s) <= 120 else s[:117] + "..."

    has_exif = bool(tags)

    # ---- Suspicious indicator analysis ----
    flags = []
    if not has_exif:
        flags.append("No EXIF metadata present - may have been stripped by editing software or social media.")
    if software:
        lowered = software.lower()
        if any(k in lowered for k in EDITOR_KEYWORDS):
            flags.append(f"Image-editing software detected in metadata: '{software}'.")
        else:
            flags.append(f"Software tag present: '{software}' (verify whether this is camera firmware).")
    if captured and modified and captured != modified:
        try:
            t1 = datetime.strptime(captured, "%Y:%m:%d %H:%M:%S")
            t2 = datetime.strptime(modified, "%Y:%m:%d %H:%M:%S")
            if abs((t2 - t1).total_seconds()) > 1:
                flags.append(f"Modification time ({modified}) differs from capture time ({captured}).")
        except ValueError:
            pass
    if has_exif and not (camera_make or camera_model):
        flags.append("EXIF present but camera make/model missing.")

    basic = {
        "File Name": original_name,
        "File Size": _human_size(size_bytes),
        "File Size (bytes)": size_bytes,
        "Format": fmt,
        "Dimensions": f"{width} x {height} px",
        "Width": width,
        "Height": height,
        "Megapixels": round(width * height / 1e6, 2),
        "Resolution": resolution,
        "Color Mode": mode,
        "Compression": compression,
        "Camera Manufacturer": camera_make or "Not available",
        "Camera Model": camera_model or "Not available",
        "Date/Time Captured": captured or "Not available",
        "Date/Time Modified": modified or "Not available",
        "Editing Software": software or "None detected",
        "GPS Location": (f"{gps['latitude']}, {gps['longitude']}" if gps else "Not available"),
    }
    return {
        "basic": basic,
        "exif": exif_table,
        "gps": gps,
        "flags": flags,
        "has_exif": has_exif,
        "software": software,
    }


def _human_size(n):
    """Format bytes as a human readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n:.1f} TB"
