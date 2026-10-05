"""Generate sample images (authentic-looking + tampered) for testing/demo."""
import io
import os
import cv2
import numpy as np
from PIL import Image

out = os.path.join(os.path.dirname(__file__), "samples")
os.makedirs(out, exist_ok=True)
rng = np.random.default_rng(7)
h, w = 480, 640


def make_scene(seed):
    """Synthetic textured 'photo' with shapes and sensor-like noise."""
    r = np.random.default_rng(seed)
    y, x = np.mgrid[0:h, 0:w]
    base = np.stack([100 + 80 * np.sin(x / 90.0), 110 + 70 * np.cos(y / 70.0),
                     140 + 50 * np.sin((x + y) / 120.0)], -1)
    for _ in range(25):
        cx, cy, rad = r.integers(0, w), r.integers(0, h), r.integers(15, 60)
        base[(x - cx) ** 2 + (y - cy) ** 2 < rad * rad] = r.integers(30, 230, 3)
    for sc, amp in ((5, 16), (11, 14), (23, 10)):
        small = r.normal(0, amp, (h // sc + 2, w // sc + 2, 3)).astype(np.float32)
        base += cv2.resize(small, (w, h), interpolation=cv2.INTER_CUBIC)
    return np.clip(base + r.normal(0, 4, base.shape), 0, 255).astype(np.uint8)


scene = make_scene(1)
Image.fromarray(scene).save(os.path.join(out, "original.jpg"), quality=75, dpi=(72, 72))

# --- tampered: decode the q75 JPEG, then paste raw (never-compressed) content, save q95
t = np.array(Image.open(os.path.join(out, "original.jpg")))
donor = make_scene(2)
t[40:150, 300:440] = donor[200:310, 100:240]                # foreign splice
t[300:400, 400:520] = t[200:300, 60:180]                    # copy-move clone
Image.fromarray(t).save(os.path.join(out, "tampered.jpg"), quality=95)
Image.fromarray(t).save(os.path.join(out, "tampered.png"))
print("samples written to", out)
