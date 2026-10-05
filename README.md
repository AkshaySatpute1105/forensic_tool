# Design and Develop a Tool for Digital Forensics of Images

**Cyber Security & Digital Forensics (CSDF) – Mini Project**

A web-based application that analyses digital images to detect possible manipulation, verify authenticity and extract forensic evidence. It combines metadata analysis, cryptographic and perceptual hashing, Error Level Analysis (ELA), histogram analysis, noise/compression analysis, copy-move (clone) detection, image comparison and a downloadable PDF forensic report, all inside a dark, blue-accented dashboard.

---

## 1. Project Objective

Help an investigator decide whether an image is **original or edited** by:

1. Extracting file properties and EXIF evidence (camera, date, GPS, software).
2. Proving integrity with MD5 / SHA-256 and finding duplicates with perceptual hashes.
3. Revealing tampering traces with ELA, histogram, noise and clone analysis.
4. Comparing two images (hashes, similarity, metadata and pixel differences).
5. Producing a professional, timestamped PDF report with an overall conclusion.

## 2. Features

| Module | What it does |
|---|---|
| Upload | JPG / JPEG / PNG / BMP, drag-and-drop, preview, type + size + content validation |
| Metadata | File name/size, dimensions, DPI, colour mode, camera make/model, capture date, GPS (with map link), editing software, compression type, raw EXIF table, suspicious-indicator flags |
| Integrity | MD5, SHA-256, compare against a user-supplied reference hash, aHash/pHash/dHash/wHash, duplicate detection against previously analysed images |
| ELA | Re-save at Q=90, amplified error map, suspicious-region outlines, score and explanation |
| Histogram | RGB + brightness charts (Chart.js), clipping, comb-gap, narrow-range and spike detection |
| Noise | Block-wise residual noise heat-map, Immerkaer sigma, inconsistent-region %, JPEG 8×8 blocking estimate |
| Clone detection | ORB keypoints + self-matching + RANSAC; source/copy regions boxed |
| Comparison | Resolution, hashes, SSIM-based similarity %, PSNR/MSE, pixel-difference heat-map, metadata diff table |
| Report | PDF containing all results + conclusion + date/time (ReportLab + Matplotlib) |
| UI | Sidebar navigation, analysis cards, risk gauge, progress bar, responsive (desktop & mobile) |

## 3. Tech Stack

* **Frontend:** HTML5, CSS3, Bootstrap 5, JavaScript, Chart.js (all libraries are bundled in `static/vendor/`, so the app works **offline**).
* **Backend:** Python 3, Flask (served with Gunicorn in production).
* **Libraries:** OpenCV, Pillow, NumPy, Matplotlib, ExifRead, ImageHash, scikit-image, ReportLab.

## 4. Installation Guide

### Prerequisites
* Python 3.9 or newer, `pip`

### Steps (Windows / Linux / macOS)

```bash
# 1. Enter the project folder
cd forensic_tool

# 2. (recommended) create a virtual environment
python -m venv venv
#   Windows:  venv\Scripts\activate
#   Linux/Mac: source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

To try it immediately, generate demo images (one authentic-looking, one tampered):

```bash
python tests/make_samples.py     # creates tests/samples/original.jpg, tampered.jpg, tampered.png
python tests/test_app.py         # optional end-to-end smoke test
```

### Environment variables (all optional)

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | 5000 | Port to listen on |
| `MAX_UPLOAD_MB` | 16 | Max upload size |
| `RETENTION_HOURS` | 24 | Uploads/reports older than this are auto-deleted |
| `SECRET_KEY` | random | Flask secret key |
| `FLASK_DEBUG` | 0 | Set to `1` for debug mode (never in production) |

## 5. Deployment

**Production server (Linux VPS, any host):**
```bash
pip install -r requirements.txt
gunicorn app:app --workers 2 --threads 4 --timeout 120 --bind 0.0.0.0:8000
```

**Render / Railway / Heroku-style platforms:** push the folder to GitHub and create a Python web service.
* Build command: `pip install -r requirements.txt`
* Start command: the included `Procfile` (`gunicorn app:app ...`) is detected automatically.

**Docker:**
```bash
docker build -t image-forensics .
docker run -p 8000:8000 image-forensics
```
Open http://localhost:8000.

> Uploaded files are stored on local disk and auto-purged after `RETENTION_HOURS`. On platforms with an ephemeral filesystem this is fine for a demo; use persistent storage if reports must survive restarts.

## 6. System Architecture

```
┌──────────────────────── Browser (Bootstrap 5 + JS + Chart.js) ────────────────────────┐
│  Sidebar │ Upload/Preview │ Analysis cards │ Charts │ Compare │ Report download        │
└───────────────┬──────────────────────────────────────────────────────▲─────────────────┘
          multipart / JSON (fetch, XHR)                          JSON + images + PDF
┌───────────────▼──────────────────────────────────────────────────────┴─────────────────┐
│                               Flask application (app.py)                               │
│  routing · validation · secure storage · error handling · cleanup · result cache       │
└──┬──────────┬──────────┬───────────┬───────────┬───────────┬──────────┬────────────────┘
   ▼          ▼          ▼           ▼           ▼           ▼          ▼
metadata.py hashing.py  ela.py   histogram.py  noise.py  comparison.py  conclusion.py
 (EXIF)    (MD5/SHA/    (ELA)    (RGB+luma)   (noise +    (SSIM, diff,  (weighted risk
            pHash)                             clones)      metadata)     score)
                                                    │
                                            report_generator.py  →  PDF (static/reports)
```

## 7. Workflow

1. User drops an image → client validates type/size → preview shown.
2. `POST /api/analyze` → server validates extension **and** real image content (Pillow), stores it under a random UUID name.
3. Modules run in sequence: metadata → hashes → duplicates → ELA → histogram → noise → clone → conclusion.
4. JSON result (and generated images) returned; dashboard cards, charts and tables are rendered.
5. Optional: upload two images in **Image Comparison**.
6. **Forensic Report** → `POST /api/report/<case>` builds the PDF → download.

## 8. Algorithms

**ELA** – Re-save the image as JPEG (Q=90), compute `|original − resaved|`, scale to 0-255. Split into 16×16 blocks, compute the mean error per block, flag blocks above `median + 6·MAD` (robust threshold) and outline connected flagged areas. Score = flagged-area % and region count.

**Histogram** – 256-bin histograms for R, G, B and luminance. Detect: clipping (≥5 % pixels at 0-2 or 253-255), comb pattern (>25 % empty bins inside the occupied range → Levels/Curves), narrow tonal range, local spikes, colour-channel imbalance.

**Noise** – `residual = gray − median_blur(gray)`; standard deviation in 32×32 blocks gives a noise map. Coefficient of variation and robust outlier blocks measure inconsistency; Immerkaer's method estimates σ; ratio of gradient at 8-px boundaries vs. interior estimates JPEG blocking.

**Clone detection** – ORB keypoints/descriptors → brute-force Hamming k-NN of the descriptor set **against itself** → Lowe ratio test on the 2nd/3rd neighbours, ignore pairs closer than 40 px → RANSAC (`estimateAffinePartial2D`) keeps geometrically consistent pairs → k-means separates source and copy, bounding boxes drawn.

**Hashing** – streamed MD5 + SHA-256; aHash, pHash, dHash, wHash via ImageHash; similarity = `1 − Hamming/64`.

**Comparison** – SHA-256 equality, perceptual similarity, SSIM on greyscale, MSE/PSNR, absolute-difference heat-map, field-by-field metadata diff. Similarity % = `0.6·SSIM + 0.4·perceptual`.

**Overall conclusion** – weighted risk: ELA 35 %, Noise 20 %, Metadata 20 %, Clone 15 %, Histogram 10 %. A positive clone detection forces risk ≥ 60; an editor signature (e.g. Photoshop) forces risk ≥ 45.
< 25 Low (likely authentic) · 25-50 Medium (inconclusive) · ≥ 50 High (likely manipulated).

## 9. Folder Structure

```
forensic_tool/
├── app.py                  Flask app: routes, validation, pipeline
├── requirements.txt
├── Procfile / Dockerfile / runtime.txt     deployment files
├── README.md
├── templates/
│   └── index.html          single-page dashboard
├── static/
│   ├── css/style.css       dark cyber theme
│   ├── js/app.js           UI logic, charts, upload, compare, report
│   ├── vendor/             Bootstrap, Bootstrap Icons, Chart.js (offline)
│   ├── uploads/            uploaded + generated images (not directly served)
│   └── reports/            generated PDF reports
├── utils/
│   ├── metadata.py         EXIF + file properties + red flags
│   ├── hashing.py          MD5/SHA-256/perceptual hashes/duplicates
│   ├── ela.py              Error Level Analysis
│   ├── histogram.py        RGB + brightness analysis
│   ├── noise.py            noise analysis + clone detection
│   ├── comparison.py       two-image comparison
│   ├── conclusion.py       weighted overall verdict
│   └── report_generator.py PDF generation
├── data/                   JSON case results + hash library (created at runtime)
└── tests/                  make_samples.py, test_app.py
```

## 10. Security Measures

* Extension whitelist **and** content verification with Pillow (renamed non-images rejected).
* Files stored under random UUID names; user file names are never used on disk (`secure_filename` for display only).
* 16 MB upload limit, 40-megapixel limit (decompression-bomb protection).
* `/static/uploads` and `/static/reports` are blocked; files are served only through a validated route.
* Case IDs validated as 12-char hex (path-traversal safe); all dynamic HTML is escaped (XSS safe).
* Automatic deletion of old files.

## 11. Advantages

* One integrated tool covering the major image-forensics techniques.
* Explainable, transparent scoring – every finding is listed with the reason.
* Works offline, no external services, no data leaves the server.
* Clean modular code, easy to extend with new tests.
* Professional PDF output suitable for documentation/chain of custody.

## 12. Limitations

* Results are **heuristic indicators**, not legal proof.
* ELA is most meaningful for JPEG; PNG/BMP give limited results. Heavy social-media recompression, resizing or screenshots reduce reliability.
* Clone detection needs textured regions; flat areas (sky, walls) yield few keypoints; rotated/scaled clones are handled but heavily blurred ones may be missed.
* Missing EXIF is common for legitimate images (WhatsApp, social media strip it).
* Does not detect fully AI-generated images or deepfakes.
* Duplicate detection only compares against images analysed on the same server.

## 13. Future Scope

* Machine-learning classifier (scikit-learn / CNN) trained on CASIA / Columbia datasets.
* Double-JPEG quantisation and JPEG-ghost detection; PRNU camera fingerprinting.
* AI-generated image / deepfake detection.
* Video forensics and batch/case management with a database and user login.
* Blockchain-based chain-of-custody timestamps.
* Digitally signed PDF reports.

## 14. References

1. N. Krawetz, "A Picture's Worth… Digital Image Analysis and Forensics," Black Hat, 2007 (Error Level Analysis).
2. H. Farid, *Photo Forensics*, MIT Press, 2016.
3. J. Fridrich, D. Soukal, J. Lukáš, "Detection of Copy-Move Forgery in Digital Images," DFRWS, 2003.
4. J. Immerkaer, "Fast Noise Variance Estimation," *Computer Vision and Image Understanding*, 1996.
5. E. Rublee et al., "ORB: An efficient alternative to SIFT or SURF," ICCV, 2011.
6. Z. Wang et al., "Image quality assessment: from error visibility to structural similarity," *IEEE TIP*, 2004.
7. JEITA CP-3451, *Exchangeable image file format for digital still cameras (Exif 2.3)*.
8. NIST, *Guide to Integrating Forensic Techniques into Incident Response* (SP 800-86).
9. Documentation: Flask, OpenCV, Pillow, scikit-image, ImageHash, ExifRead, ReportLab, Chart.js, Bootstrap 5.

---
*Disclaimer: for educational and investigative-assistance use. Findings must be validated by a qualified examiner.*
