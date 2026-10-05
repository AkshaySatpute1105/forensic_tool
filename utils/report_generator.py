"""
report_generator.py - Build a professional PDF forensic report (ReportLab).

The report embeds the analysis images, a matplotlib histogram chart,
metadata tables, hashes, conclusion and (optionally) a comparison section.
"""
import os
from datetime import datetime

import matplotlib
matplotlib.use("Agg")  # headless backend
import matplotlib.pyplot as plt
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (Image, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle, KeepTogether)

NAVY = colors.HexColor("#0b1220")
BLUE = colors.HexColor("#2f81f7")
GREY = colors.HexColor("#e6edf3")
RISK_COLORS = {"Low": colors.HexColor("#2ea043"), "Medium": colors.HexColor("#d29922"),
               "High": colors.HexColor("#f85149")}


def _styles():
    ss = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=ss["Title"], textColor=BLUE, fontSize=24, spaceAfter=4),
        "sub": ParagraphStyle("s", parent=ss["Normal"], textColor=colors.grey, fontSize=10),
        "h1": ParagraphStyle("h1", parent=ss["Heading2"], textColor=BLUE, spaceBefore=12, spaceAfter=6),
        "body": ParagraphStyle("b", parent=ss["Normal"], fontSize=9.5, leading=13),
        "small": ParagraphStyle("sm", parent=ss["Normal"], fontSize=8, leading=10, textColor=colors.grey),
        "cell": ParagraphStyle("c", parent=ss["Normal"], fontSize=8.5, leading=10.5),
    }


def _kv_table(rows, st, col_widths=(55 * mm, 115 * mm)):
    data = [[Paragraph(f"<b>{k}</b>", st["cell"]), Paragraph(str(v), st["cell"])] for k, v in rows]
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d1d9")),
        ("BACKGROUND", (0, 0), (0, -1), GREY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _img(path, max_w=82 * mm, max_h=70 * mm):
    """Return a ReportLab Image scaled to fit, or a placeholder paragraph."""
    if not path or not os.path.exists(path):
        return ""
    from PIL import Image as PILImage
    with PILImage.open(path) as im:
        w, h = im.size
    ratio = min(max_w / w, max_h / h)
    return Image(path, width=w * ratio, height=h * ratio)


def _histogram_png(hist, out_path):
    """Render RGB + brightness histograms to a PNG using matplotlib."""
    fig, axes = plt.subplots(1, 2, figsize=(9, 3), dpi=120)
    x = range(256)
    for name, c in (("red", "#f85149"), ("green", "#3fb950"), ("blue", "#2f81f7")):
        axes[0].plot(x, hist["histograms"][name], color=c, linewidth=1, label=name.title())
    axes[0].set_title("RGB Histogram"); axes[0].legend(fontsize=7)
    axes[1].fill_between(x, hist["histograms"]["brightness"], color="#8b949e")
    axes[1].set_title("Brightness (Luma) Distribution")
    for ax in axes:
        ax.set_xlim(0, 255); ax.tick_params(labelsize=7)
        ax.set_xlabel("Pixel value", fontsize=8)
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.grey)
    canvas.drawString(15 * mm, 8 * mm, "Digital Image Forensics Tool - CSDF Mini Project | Confidential forensic report")
    canvas.drawRightString(195 * mm, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


def generate_report(result, img_dir, out_path, comparison=None):
    """
    result     : dict produced by app.analyze_image()
    img_dir    : folder that contains the generated analysis images
    out_path   : destination PDF path
    comparison : optional dict from comparison.compare_images()
    """
    st = _styles()
    doc = SimpleDocTemplate(out_path, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=16 * mm,
                            title="Digital Image Forensic Report", author="Digital Image Forensics Tool")
    S = []
    now = datetime.now().strftime("%d %B %Y, %H:%M:%S")
    meta, hashes = result["metadata"], result["hashes"]
    concl = result["conclusion"]

    # ---------- Cover / summary ----------
    S += [Paragraph("DIGITAL IMAGE FORENSIC REPORT", st["title"]),
          Paragraph(f"Date and time of analysis: <b>{now}</b> &nbsp;|&nbsp; Case ID: <b>{result['case_id']}</b>", st["sub"]),
          Spacer(1, 8)]

    lvl_col = RISK_COLORS[concl["level"]]
    banner = Table([[Paragraph(f"<font color='white'><b>{concl['verdict']}</b><br/>"
                               f"Manipulation risk score: {concl['risk_score']} / 100 ({concl['level']})</font>",
                               ParagraphStyle("bn", parent=st["body"], fontSize=11, leading=15))]],
                   colWidths=[180 * mm])
    banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), lvl_col),
                                ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 8),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    S += [banner, Spacer(1, 8)]

    S.append(Paragraph("1. Image Information", st["h1"]))
    basic = meta["basic"]
    keys = ["File Name", "File Size", "Format", "Dimensions", "Resolution", "Color Mode", "Compression"]
    S.append(_kv_table([(k, basic[k]) for k in keys], st))
    prev = _img(os.path.join(img_dir, result["files"]["original"]), 100 * mm, 75 * mm)
    if prev:
        S += [Spacer(1, 6), prev, Paragraph("Figure 1: Submitted image", st["small"])]

    S.append(Paragraph("2. Metadata Analysis", st["h1"]))
    mkeys = ["Camera Manufacturer", "Camera Model", "Date/Time Captured", "Date/Time Modified",
             "GPS Location", "Editing Software"]
    S.append(_kv_table([(k, basic[k]) for k in mkeys], st))
    if meta["flags"]:
        S.append(Spacer(1, 4))
        for f in meta["flags"]:
            S.append(Paragraph("&bull; " + f, st["body"]))
    else:
        S.append(Paragraph("No suspicious metadata indicators found.", st["body"]))

    S.append(Paragraph("3. Integrity - Hash Values", st["h1"]))
    rows = [("MD5", hashes["md5"]), ("SHA-256", hashes["sha256"]),
            ("Perceptual (pHash)", result["perceptual"]["phash"]),
            ("Perceptual (aHash)", result["perceptual"]["ahash"]),
            ("Perceptual (dHash)", result["perceptual"]["dhash"])]
    if result.get("hash_check"):
        rows.append(("Reference check", result["hash_check"]["message"]))
    S.append(_kv_table(rows, st))
    if result.get("duplicates"):
        for d in result["duplicates"]:
            S.append(Paragraph(f"&bull; Duplicate: {d['name']} - {d['type']} ({d['similarity']}%)", st["body"]))

    # ---------- ELA ----------
    ela = result["ela"]
    S.append(PageBreak())
    S.append(Paragraph("4. Error Level Analysis (ELA)", st["h1"]))
    S.append(Paragraph(
        "ELA re-saves the image at a known JPEG quality and amplifies the difference. Regions edited or "
        "pasted from another source have a different compression history and appear brighter.", st["body"]))
    S.append(Spacer(1, 4))
    pair = Table([[_img(os.path.join(img_dir, ela["ela_image"])), _img(os.path.join(img_dir, ela["overlay_image"]))],
                  [Paragraph("ELA map", st["small"]), Paragraph("Suspicious regions outlined", st["small"])]],
                 colWidths=[88 * mm, 88 * mm])
    S.append(pair)
    S.append(_kv_table([("ELA score", f"{ela['score']} / 100 ({ela['level']})"),
                        ("Mean / Max error", f"{ela['mean_error']} / {ela['max_error']}"),
                        ("Suspicious blocks", f"{ela['suspicious_percent']}% in {ela['suspicious_regions']} region(s)"),
                        ("Interpretation", ela["summary"])], st))

    # ---------- Histogram ----------
    hist = result["histogram"]
    hist_png = os.path.join(img_dir, f"{result['prefix']}_hist.png")
    _histogram_png(hist, hist_png)
    S.append(Paragraph("5. Histogram Analysis", st["h1"]))
    S.append(Image(hist_png, width=175 * mm, height=58 * mm))
    hs = hist["stats"]
    S.append(_kv_table([("Mean / Std brightness", f"{hs['mean_brightness']} / {hs['std_brightness']}"),
                        ("Tonal range", f"{hs['min']} - {hs['max']}"),
                        ("Clipping (black / white)", f"{hs['clip_black_pct']}% / {hs['clip_white_pct']}%"),
                        ("Status", hist["status"])], st))
    for f in hist["findings"]:
        S.append(Paragraph("&bull; " + f, st["body"]))

    # ---------- Noise ----------
    noise = result["noise"]
    S.append(PageBreak())
    S.append(Paragraph("6. Noise &amp; Compression Analysis", st["h1"]))
    S.append(_img(os.path.join(img_dir, noise["noise_image"]), 100 * mm, 75 * mm))
    S.append(Paragraph("Figure: local noise heat-map (red = high noise, blue = low noise)", st["small"]))
    S.append(_kv_table([("Estimated noise sigma", noise["sigma"]),
                        ("Noise variation (CV)", noise["coef_variation"]),
                        ("Outlier blocks", f"{noise['outlier_percent']}%"),
                        ("Compression artifacts", f"{noise['compression_artifacts']} (blockiness {noise['blockiness']})"),
                        ("Status", noise["status"])], st))
    for f in noise["findings"]:
        S.append(Paragraph("&bull; " + f, st["body"]))

    # ---------- Clone ----------
    clone = result["clone"]
    S.append(Paragraph("7. Clone (Copy-Move) Detection", st["h1"]))
    S.append(Paragraph(clone["summary"], st["body"]))
    S.append(_img(os.path.join(img_dir, clone["image"] or ""), 100 * mm, 75 * mm))

    # ---------- Comparison ----------
    if comparison:
        S.append(PageBreak())
        S.append(Paragraph("8. Image Comparison", st["h1"]))
        S.append(_kv_table([
            ("Images", f"{comparison['name_a']}  vs  {comparison['name_b']}"),
            ("Resolution", f"{comparison['resolution']['a']}  vs  {comparison['resolution']['b']}"),
            ("SHA-256 identical", "Yes" if comparison["hashes"]["identical"] else "No"),
            ("Similarity", f"{comparison['similarity_percent']}% (SSIM {comparison['ssim']})"),
            ("Pixels changed", f"{comparison['pixel']['changed_percent']}%"),
            ("Metadata differences", comparison["metadata_diff_count"]),
            ("Verdict", comparison["verdict"])], st))

    # ---------- Conclusion ----------
    S.append(PageBreak() if not comparison else Spacer(1, 8))
    S.append(Paragraph("Overall Forensic Conclusion", st["h1"]))
    S.append(Paragraph(f"<b>{concl['verdict']}</b> (risk {concl['risk_score']}/100)", st["body"]))
    S.append(Spacer(1, 4))
    S.append(Paragraph("<b>Supporting observations</b>", st["body"]))
    for r in concl["reasons"]:
        S.append(Paragraph("&bull; " + r, st["body"]))
    S.append(Spacer(1, 4))
    S.append(Paragraph("<b>Recommendations</b>", st["body"]))
    for r in concl["recommendations"]:
        S.append(Paragraph("&bull; " + r, st["body"]))
    S.append(Spacer(1, 10))
    S.append(Paragraph("Disclaimer: automated image forensics provides probabilistic indicators only. "
                       "Findings must be validated by a qualified examiner before being used as evidence.", st["small"]))

    doc.build(S, onFirstPage=_footer, onLaterPages=_footer)
    return out_path
