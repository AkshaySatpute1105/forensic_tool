/* ==========================================================
   Digital Image Forensics Tool - front-end logic
   ========================================================== */
(() => {
  'use strict';

  const ALLOWED = ['jpg', 'jpeg', 'png', 'bmp'];
  const MAX_MB = 16;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const state = { file: null, result: null, cmpId: null, charts: {} };

  /* ---------- helpers ---------- */
  // Escape anything that originates from files (names, EXIF) to prevent XSS.
  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fileUrl = name => `/files/${encodeURIComponent(name)}?t=${Date.now() % 100000}`;
  const levelClass = s => (s < 20 ? 'ok' : s < 45 ? 'warn' : 'bad');
  const levelName = s => (s < 20 ? 'Low' : s < 45 ? 'Medium' : 'High');

  function showAlert(box, msg, type = 'danger') {
    box.innerHTML = `<div class="alert alert-${type} alert-dismissible fade show" role="alert">
      <i class="bi bi-exclamation-octagon me-2"></i>${esc(msg)}
      <button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>`;
  }

  function validateFile(f) {
    const ext = (f.name.split('.').pop() || '').toLowerCase();
    if (!ALLOWED.includes(ext)) return 'Unsupported file type. Please upload JPG, JPEG, PNG or BMP.';
    if (f.size > MAX_MB * 1024 * 1024) return `File is too large (max ${MAX_MB} MB).`;
    if (f.size === 0) return 'The selected file is empty.';
    return null;
  }

  const kvRows = (obj, skip = []) => Object.entries(obj)
    .filter(([k]) => !skip.includes(k))
    .map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('');

  const list = (items, okText) => items && items.length
    ? items.map(i => `<li>${esc(i)}</li>`).join('')
    : `<li class="ok">${esc(okText)}</li>`;

  /* ---------- navigation ---------- */
  function go(view) {
    $$('.view').forEach(v => v.classList.toggle('active', v.id === `view-${view}`));
    $$('#nav .nav-link').forEach(a => a.classList.toggle('active', a.dataset.view === view));
    const off = window.bootstrap && bootstrap.Offcanvas.getInstance($('#sidebar'));
    if (off) off.hide();
    window.scrollTo({ top: 0 });
    if (view === 'histogram' && state.result) renderHistogram(state.result); // fix chart size when shown
  }
  $$('#nav .nav-link').forEach(a => a.addEventListener('click', () => go(a.dataset.view)));

  /* ---------- generic dropzone wiring ---------- */
  function wireDropzone(zone, input, onFile) {
    zone.addEventListener('click', () => input.click());
    zone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
    ['dragenter', 'dragover'].forEach(ev => zone.addEventListener(ev, e => { e.preventDefault(); zone.classList.add('drag'); }));
    ['dragleave', 'drop'].forEach(ev => zone.addEventListener(ev, e => { e.preventDefault(); zone.classList.remove('drag'); }));
    zone.addEventListener('drop', e => { if (e.dataTransfer.files.length) onFile(e.dataTransfer.files[0]); });
    input.addEventListener('change', () => { if (input.files.length) onFile(input.files[0]); });
  }

  /* ======================================================
     SINGLE IMAGE ANALYSIS
     ====================================================== */
  const alertBox = $('#alertBox');
  function setFile(f) {
    alertBox.innerHTML = '';
    const err = validateFile(f);
    if (err) { showAlert(alertBox, err); return; }
    state.file = f;
    const url = URL.createObjectURL(f);
    $('#previewBox').innerHTML = `<img src="${url}" alt="Preview of selected image">`;
    $('#previewInfo').textContent = `${f.name} · ${(f.size / 1024).toFixed(1)} KB · ${f.type || 'image'}`;
    $('#analyzeBtn').disabled = false;
  }
  wireDropzone($('#dropzone'), $('#fileInput'), setFile);

  $('#resetBtn').addEventListener('click', () => {
    state.file = null; state.result = null;
    $('#fileInput').value = ''; $('#expectedHash').value = '';
    $('#previewBox').innerHTML = '<div class="empty-state"><i class="bi bi-card-image"></i><span>No image selected</span></div>';
    $('#previewInfo').textContent = '';
    $('#analyzeBtn').disabled = true;
    $('#overview').classList.add('d-none');
    alertBox.innerHTML = '';
    $$('.needs-result').forEach(e => e.classList.remove('d-none'));
    $$('.result-only').forEach(e => e.classList.add('d-none'));
  });

  // Upload with XHR so we can show upload progress.
  function postForm(url, form, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', url);
      xhr.responseType = 'json';
      xhr.upload.onprogress = e => e.lengthComputable && onProgress && onProgress(e.loaded / e.total);
      xhr.onload = () => {
        let data = xhr.response;
        if (!data) data = { error: xhr.status === 413 ? `File too large (max ${MAX_MB} MB).` : 'Unexpected server response.' };
        xhr.status >= 200 && xhr.status < 300 ? resolve(data) : reject(new Error(data.error || `Server error (${xhr.status})`));
      };
      xhr.onerror = () => reject(new Error('Network error. Is the server running?'));
      xhr.send(form);
    });
  }

  const STEPS = ['Reading metadata...', 'Computing hashes...', 'Running Error Level Analysis...', 'Analysing histogram...', 'Measuring noise...', 'Scanning for cloned regions...', 'Building conclusion...'];

  $('#analyzeBtn').addEventListener('click', async () => {
    if (!state.file) return;
    const btn = $('#analyzeBtn'), wrap = $('#progressWrap'), bar = $('#progressBar'), txt = $('#progressText');
    btn.disabled = true; wrap.classList.remove('d-none'); alertBox.innerHTML = '';
    bar.style.width = '2%'; txt.textContent = 'Uploading...';
    let step = 0, timer = null;
    const form = new FormData();
    form.append('image', state.file);
    form.append('expected_hash', $('#expectedHash').value.trim());
    try {
      const p = postForm('/api/analyze', form, frac => {
        bar.style.width = Math.round(frac * 25) + '%';
        if (frac >= 1) {   // upload done -> animate fake analysis steps
          timer = setInterval(() => {
            step = Math.min(step + 1, STEPS.length - 1);
            txt.textContent = STEPS[step];
            bar.style.width = Math.min(95, 25 + (step + 1) * 10) + '%';
          }, 600);
          txt.textContent = STEPS[0];
        }
      });
      state.result = await p;
      bar.style.width = '100%'; txt.textContent = 'Analysis complete';
      renderAll(state.result);
    } catch (e) {
      showAlert(alertBox, e.message);
    } finally {
      clearInterval(timer);
      btn.disabled = false;
      setTimeout(() => wrap.classList.add('d-none'), 800);
    }
  });

  /* ---------- rendering ---------- */
  function renderAll(r) {
    $$('.needs-result').forEach(e => e.classList.add('d-none'));
    $$('.result-only').forEach(e => e.classList.remove('d-none'));
    renderOverview(r); renderMetadata(r); renderIntegrity(r); renderEla(r);
    renderHistogram(r); renderNoise(r); renderReportTab(r);
    $('#overview').classList.remove('d-none');
    $('#overview').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function renderOverview(r) {
    const c = r.conclusion;
    const fg = $('#gaugeFg'), circ = 326.7;
    fg.style.strokeDashoffset = circ - (circ * c.risk_score / 100);
    fg.style.stroke = `var(--${levelClass(c.risk_score) === 'ok' ? 'ok' : levelClass(c.risk_score) === 'warn' ? 'warn' : 'bad'})`;
    $('#gaugeVal').textContent = Math.round(c.risk_score);
    const badge = $('#riskBadge'); badge.textContent = `${c.level} risk`; badge.className = `badge-risk ${c.level}`;
    $('#verdictText').textContent = c.verdict;
    $('#reasonList').innerHTML = list(c.reasons, 'No anomalies detected.');
    $('#recList').innerHTML = list(c.recommendations, '');
    $('#analysedAt').textContent = r.analyzed_at; $('#caseId').textContent = r.case_id;

    const cards = [
      ['ela', 'bi-layers-half', 'ELA', r.ela.score, `${r.ela.suspicious_regions} region(s) flagged`],
      ['noise', 'bi-soundwave', 'Noise', r.noise.score, r.noise.status],
      ['histogram', 'bi-bar-chart-line', 'Histogram', r.histogram.score, r.histogram.status],
      ['metadata', 'bi-card-list', 'Metadata', Math.min(100, r.metadata.flags.length * 30 + (r.metadata.has_exif ? 0 : 20)), r.metadata.has_exif ? 'EXIF present' : 'No EXIF data'],
      ['noise', 'bi-files', 'Clone detection', r.clone.detected ? 90 : 0, r.clone.detected ? `${r.clone.matches} matches` : 'None found'],
      ['integrity', 'bi-fingerprint', 'Duplicates', r.duplicates.length ? 60 : 0, r.duplicates.length ? `${r.duplicates.length} match(es)` : 'Unique image'],
    ];
    $('#scoreCards').innerHTML = cards.map(([view, icon, label, s, sub]) => `
      <div class="col-sm-6 col-xl-4"><div class="score-card" data-go="${view}" tabindex="0">
        <div class="label"><i class="bi ${icon}"></i>${label}</div>
        <div class="val c-${levelClass(s)}">${levelName(s)}</div>
        <div class="sub">${esc(sub)}</div>
        <div class="bar"><span class="bg-${levelClass(s)}" style="width:${Math.max(4, s)}%"></span></div>
      </div></div>`).join('');
    $$('.score-card').forEach(c => { c.onclick = () => go(c.dataset.go); c.onkeydown = e => e.key === 'Enter' && go(c.dataset.go); });
  }

  function renderMetadata(r) {
    const m = r.metadata;
    $('#metaFlags').innerHTML = list(m.flags, 'No suspicious metadata indicators found.');
    $('#metaTable').innerHTML = kvRows(m.basic, ['File Size (bytes)', 'Width', 'Height']);
    const keys = Object.keys(m.exif);
    $('#exifCount').textContent = `${keys.length} tags`;
    $('#exifTable').innerHTML = keys.length ? kvRows(m.exif) : '<tr><td colspan="2" class="text-muted">No EXIF tags found in this file.</td></tr>';
    const g = $('#gpsLink');
    if (m.gps) { g.href = m.gps.maps_url; g.classList.remove('d-none'); } else g.classList.add('d-none');
  }

  const hashRow = (label, val) => `<div class="hash-row"><div class="h-label">${esc(label)}</div>
    <div class="hash-val"><span>${esc(val)}</span><button type="button" data-copy="${esc(val)}" title="Copy"><i class="bi bi-clipboard"></i></button></div></div>`;

  function renderIntegrity(r) {
    $('#hashBlock').innerHTML = hashRow('MD5', r.hashes.md5) + hashRow('SHA-256', r.hashes.sha256);
    const hc = r.hash_check;
    $('#hashCheck').innerHTML = hc
      ? `<div class="callout ${hc.matched ? 'ok' : 'bad'}"><i class="bi ${hc.matched ? 'bi-check-circle' : 'bi-x-circle'} me-1"></i>${esc(hc.message)}</div>`
      : '<div class="small text-muted">No reference hash supplied. Paste the hash of the original on the Upload page to verify integrity.</div>';
    $('#phashBlock').innerHTML = [['Average hash (aHash)', 'ahash'], ['Perceptual hash (pHash)', 'phash'], ['Difference hash (dHash)', 'dhash'], ['Wavelet hash (wHash)', 'whash']]
      .map(([l, k]) => hashRow(l, r.perceptual[k])).join('');
    $('#dupBlock').innerHTML = r.duplicates.length
      ? r.duplicates.map(d => `<div class="callout warn mb-2"><b>${esc(d.name)}</b> &mdash; ${esc(d.type)} (${d.similarity}% similar, distance ${d.distance})</div>`).join('')
      : '<div class="callout ok">No duplicate or near-duplicate found in the analysed-images library.</div>';
    $$('[data-copy]').forEach(b => b.onclick = () => navigator.clipboard?.writeText(b.dataset.copy).then(() => { b.innerHTML = '<i class="bi bi-check2"></i>'; setTimeout(() => b.innerHTML = '<i class="bi bi-clipboard"></i>', 1200); }));
  }

  function renderEla(r) {
    $('#elaOrig').src = fileUrl(r.files.original);
    $('#elaImg').src = fileUrl(r.ela.ela_image);
    $('#elaOverlay').src = fileUrl(r.ela.overlay_image);
    const e = r.ela;
    $('#elaTable').innerHTML = kvRows({
      'ELA score': `${e.score} / 100 (${e.level})`, 'Mean error': e.mean_error, 'Std. deviation': e.std_error,
      'Max error': e.max_error, 'Blocks flagged': `${e.suspicious_percent}%`, 'Suspicious regions': e.suspicious_regions });
    const cls = e.level === 'Low' ? 'ok' : e.level === 'Medium' ? 'warn' : 'bad';
    $('#elaVerdict').className = `callout mt-2 ${cls}`;
    $('#elaVerdict').innerHTML = esc(e.summary) + (e.note ? `<div class="small mt-2 text-muted">${esc(e.note)}</div>` : '');
  }

  function chart(id, cfg) {
    if (state.charts[id]) state.charts[id].destroy();
    state.charts[id] = new Chart($('#' + id), cfg);
  }

  function renderHistogram(r) {
    if (typeof Chart === 'undefined') return;
    const h = r.histogram, labels = [...Array(256).keys()];
    Chart.defaults.color = '#8a9bb8'; Chart.defaults.borderColor = '#1f2e4a';
    const ds = (label, data, color) => ({ label, data, borderColor: color, backgroundColor: color + '33', borderWidth: 1.4, pointRadius: 0, fill: true, tension: .25 });
    const opts = { responsive: true, maintainAspectRatio: false, animation: { duration: 500 },
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { labels: { boxWidth: 12 } } },
      scales: { x: { ticks: { maxTicksLimit: 9 }, title: { display: true, text: 'Pixel value (0-255)' } }, y: { title: { display: true, text: 'Pixel count' } } } };
    chart('rgbChart', { type: 'line', data: { labels, datasets: [ds('Red', h.histograms.red, '#f85149'), ds('Green', h.histograms.green, '#3fb950'), ds('Blue', h.histograms.blue, '#2f81f7')] }, options: opts });
    chart('lumChart', { type: 'bar', data: { labels, datasets: [{ label: 'Brightness', data: h.histograms.brightness, backgroundColor: h.histograms.brightness.map((_, i) => (i < 3 || i > 252) ? '#f85149' : '#58a6ff'), barPercentage: 1, categoryPercentage: 1 }] }, options: { ...opts, plugins: { legend: { display: false } } } });
    const s = h.stats;
    $('#histTable').innerHTML = kvRows({
      'Mean brightness': s.mean_brightness, 'Std. deviation': s.std_brightness, 'Tonal range': `${s.min} - ${s.max}`,
      'Mean R / G / B': s.mean_rgb.join(' / '), 'Clipped black': `${s.clip_black_pct}%`, 'Clipped white': `${s.clip_white_pct}%`,
      'Empty bins in range': `${(s.empty_bin_ratio * 100).toFixed(1)}%` });
    $('#histStatus').textContent = h.status;
    $('#histFindings').innerHTML = list(h.findings, 'Pixel distribution looks natural - no unusual spikes, gaps or clipping.');
  }

  function renderNoise(r) {
    const n = r.noise, c = r.clone;
    $('#noiseImg').src = fileUrl(n.noise_image);
    $('#noiseStatus').textContent = n.status;
    $('#noiseTable').innerHTML = kvRows({
      'Estimated noise (sigma)': n.sigma, 'Mean block noise': n.mean_block_noise, 'Variation (CV)': n.coef_variation,
      'Inconsistent blocks': `${n.outlier_percent}%`, 'Compression artifacts': `${n.compression_artifacts} (blockiness ${n.blockiness})` });
    $('#noiseFindings').innerHTML = list(n.findings, 'Noise level is consistent across the image.');
    $('#cloneImg').src = fileUrl(c.image);
    $('#cloneStatus').textContent = c.detected ? 'Clones found' : 'Clean';
    $('#cloneTable').innerHTML = kvRows({ 'Keypoints analysed': c.keypoints, 'Consistent matches': c.matches, 'Regions marked': c.regions });
    $('#cloneSummary').className = `callout ${c.detected ? 'bad' : 'ok'}`;
    $('#cloneSummary').textContent = c.summary;
  }

  function renderReportTab() {
    $('#reportMsg').innerHTML = '';
    $('#includeCmpWrap').classList.toggle('d-none', !state.cmpId);
  }

  /* ======================================================
     REPORT
     ====================================================== */
  $('#reportBtn').addEventListener('click', async () => {
    if (!state.result) return;
    const btn = $('#reportBtn'), msg = $('#reportMsg');
    btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Generating...';
    msg.innerHTML = '';
    try {
      const body = {};
      if (state.cmpId && $('#includeCmp').checked) body.comparison_id = state.cmpId;
      const res = await fetch(`/api/report/${state.result.case_id}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Report failed');
      msg.innerHTML = `<div class="callout ok">Report ready. <a href="${esc(data.download)}" class="fw-semibold">Download PDF</a></div>`;
      window.location.href = data.download;
    } catch (e) {
      showAlert(msg, e.message);
    } finally {
      btn.disabled = false; btn.innerHTML = '<i class="bi bi-download"></i> Generate &amp; download PDF';
    }
  });

  /* ======================================================
     COMPARISON
     ====================================================== */
  const cmp = { a: null, b: null };
  function setCmp(which, f) {
    const box = $('#cmpAlert'); box.innerHTML = '';
    const err = validateFile(f);
    if (err) { showAlert(box, err); return; }
    cmp[which] = f;
    const img = $(which === 'a' ? '#cmpPrevA' : '#cmpPrevB');
    img.src = URL.createObjectURL(f); img.classList.remove('d-none');
    $('#compareBtn').disabled = !(cmp.a && cmp.b);
  }
  $$('.small-dz').forEach(z => {
    const input = $('#' + z.dataset.target);
    wireDropzone(z, input, f => setCmp(z.dataset.target === 'cmpA' ? 'a' : 'b', f));
  });

  $('#compareBtn').addEventListener('click', async () => {
    const btn = $('#compareBtn'), box = $('#cmpAlert');
    btn.disabled = true; box.innerHTML = ''; $('#cmpProgress').classList.remove('d-none');
    const form = new FormData(); form.append('image_a', cmp.a); form.append('image_b', cmp.b);
    try {
      const r = await postForm('/api/compare', form);
      state.cmpId = r.comparison_id;
      renderCompare(r);
      if (state.result) renderReportTab();
    } catch (e) { showAlert(box, e.message); }
    finally { btn.disabled = false; $('#cmpProgress').classList.add('d-none'); }
  });

  function renderCompare(r) {
    $('#cmpResult').classList.remove('d-none');
    const sim = r.similarity_percent, simCls = sim >= 90 ? 'ok' : sim >= 70 ? 'warn' : 'bad';
    const card = (label, val, sub, cls = '') => `<div class="col-6 col-lg-3"><div class="score-card" style="cursor:default"><div class="label">${label}</div><div class="val ${cls}">${val}</div><div class="sub">${esc(sub)}</div></div></div>`;
    $('#cmpCards').innerHTML =
      card('Similarity', sim + '%', `SSIM ${r.ssim}`, 'c-' + simCls) +
      card('Resolution', r.resolution.same ? 'Same' : 'Different', `${r.resolution.a} vs ${r.resolution.b}`, r.resolution.same ? 'c-ok' : 'c-warn') +
      card('File hash', r.hashes.identical ? 'Identical' : 'Different', 'SHA-256 comparison', r.hashes.identical ? 'c-ok' : 'c-warn') +
      card('Pixels changed', r.pixel.changed_percent + '%', `Max diff ${r.pixel.max_difference}/255`, r.pixel.changed_percent < 2 ? 'c-ok' : 'c-warn');
    const v = $('#cmpVerdict'); v.className = `callout mb-4 ${simCls}`; v.innerHTML = `<b>Verdict:</b> ${esc(r.verdict)}`;
    $('#cmpDiff').src = fileUrl(r.diff_image);
    const p = r.perceptual;
    $('#cmpHashTable').innerHTML = kvRows({
      'MD5 (A)': r.hashes.md5_a, 'MD5 (B)': r.hashes.md5_b,
      'SHA-256 (A)': r.hashes.sha256_a, 'SHA-256 (B)': r.hashes.sha256_b,
      'Perceptual similarity': `${r.perceptual_similarity}% (pHash distance ${p.phash.distance})`,
      'MSE / PSNR': `${r.pixel.mse} / ${r.pixel.psnr ?? '∞'} dB`,
      'Resized for pixel diff': r.pixel.resized_for_comparison ? 'Yes (B scaled to A)' : 'No' });
    $('#cmpMetaCount').textContent = `${r.metadata_diff_count} different`;
    $('#cmpMetaTable').innerHTML = r.metadata_diff.map(d =>
      `<tr class="${d.different ? 'diff-row' : ''}"><td>${esc(d.field)}</td><td>${esc(d.a)}</td><td>${esc(d.b)}</td></tr>`).join('');
    $('#cmpResult').scrollIntoView({ behavior: 'smooth' });
  }
})();
