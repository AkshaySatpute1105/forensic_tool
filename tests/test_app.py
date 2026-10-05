"""End-to-end smoke tests: python tests/test_app.py"""
import io, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import app

S = os.path.join(os.path.dirname(__file__), "samples")
c = app.test_client()
op = lambda n: (open(os.path.join(S, n), "rb"), n)

def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond: sys.exit(1)

check("index 200", c.get("/").status_code == 200)
check("health", c.get("/health").json["status"] == "ok")

r = c.post("/api/analyze", data={"image": op("tampered.jpg"), "expected_hash": "abc"}, content_type="multipart/form-data")
check("analyze 200", r.status_code == 200)
j = r.json
check("tampered flagged", j["conclusion"]["level"] in ("Medium", "High"))
check("bad hash length handled", j["hash_check"]["algorithm"] == "Unknown")
cid = j["case_id"]
check("ela image served", c.get("/files/" + j["ela"]["ela_image"]).status_code == 200)
check("static uploads blocked", c.get("/static/uploads/" + j["files"]["original"]).status_code == 404)

r = c.post("/api/analyze", data={"image": op("original.jpg"), "expected_hash": j["hashes"]["md5"]}, content_type="multipart/form-data")
check("original low/medium", r.json["conclusion"]["risk_score"] < j["conclusion"]["risk_score"])

r = c.post("/api/analyze", data={"image": (io.BytesIO(b"not an image"), "evil.jpg")}, content_type="multipart/form-data")
check("fake image rejected", r.status_code == 400)
r = c.post("/api/analyze", data={"image": (io.BytesIO(b"GIF89a"), "x.gif")}, content_type="multipart/form-data")
check("gif rejected", r.status_code == 400)
check("no file rejected", c.post("/api/analyze", data={}, content_type="multipart/form-data").status_code == 400)

r = c.post("/api/compare", data={"image_a": op("original.jpg"), "image_b": op("tampered.jpg")}, content_type="multipart/form-data")
check("compare 200", r.status_code == 200 and r.json["similarity_percent"] > 50)
cmp_id = r.json["comparison_id"]

r = c.post(f"/api/report/{cid}", json={"comparison_id": cmp_id})
check("report built", r.status_code == 200)
d = c.get(r.json["download"])
check("pdf download", d.status_code == 200 and d.data[:4] == b"%PDF")
open("/tmp/report_test.pdf", "wb").write(d.data)
check("bad case id", c.post("/api/report/../etc", json={}).status_code in (400, 404))
check("traversal blocked", c.post("/api/report/zzzzzzzzzzzz", json={}).status_code == 400)
check("unknown case 404", c.post("/api/report/aaaaaaaaaaaa", json={}).status_code == 404)
print("ALL OK")
