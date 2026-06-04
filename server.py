#!/usr/bin/env python3
"""
server.py — web frontend for the Claude Audit Log Visualizer

Serves a CSV upload form on http://localhost:3000.
The generated dashboard HTML is returned directly in the browser.

Usage:
    python server.py
"""

import os
import sys
import tempfile

from flask import Flask, Response, request

# Import core logic from visualize.py in the same directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from visualize import build_stats, generate_html, parse_csv

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Upload form HTML
# ---------------------------------------------------------------------------

_FORM_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Claude Audit Log Visualizer</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                   'Helvetica Neue', sans-serif;
      background: #f0f2f8;
      color: #1a1a2e;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background: #1a1a2e;
      color: #fff;
      padding: 16px 32px;
      display: flex;
      align-items: center;
      gap: 14px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    }
    header h1 { font-size: 17px; font-weight: 600; letter-spacing: -0.01em; }
    main {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 48px 24px;
    }
    .card {
      background: #fff;
      border-radius: 16px;
      padding: 40px 48px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.08);
      width: 100%;
      max-width: 520px;
    }
    .card h2 {
      font-size: 20px;
      font-weight: 700;
      color: #111827;
      margin-bottom: 8px;
    }
    .card .subtitle {
      font-size: 13px;
      color: #6b7280;
      margin-bottom: 32px;
    }
    .field { margin-bottom: 24px; }
    label.field-label {
      display: block;
      font-size: 12px;
      font-weight: 700;
      color: #374151;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      margin-bottom: 8px;
    }
    .drop-zone {
      border: 2px dashed #d1d5db;
      border-radius: 10px;
      padding: 32px 24px;
      text-align: center;
      cursor: pointer;
      transition: border-color 0.15s, background 0.15s;
      background: #fafafa;
      position: relative;
    }
    .drop-zone:hover, .drop-zone.drag-over {
      border-color: #7c3aed;
      background: #f5f3ff;
    }
    .drop-zone input[type="file"] {
      position: absolute;
      inset: 0;
      opacity: 0;
      cursor: pointer;
      width: 100%;
      height: 100%;
    }
    .drop-zone .dz-icon { font-size: 32px; margin-bottom: 8px; }
    .drop-zone .dz-text { font-size: 13px; color: #6b7280; }
    .drop-zone .dz-text strong { color: #7c3aed; }
    .drop-zone .dz-hint { font-size: 11px; color: #9ca3af; margin-top: 4px; }
    .drop-zone .dz-filename {
      display: none;
      font-size: 13px;
      font-weight: 600;
      color: #111827;
      margin-top: 6px;
      word-break: break-all;
    }
    .toggle-row {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .toggle {
      position: relative;
      display: inline-block;
      width: 40px;
      height: 22px;
      flex-shrink: 0;
    }
    .toggle input { opacity: 0; width: 0; height: 0; }
    .toggle-slider {
      position: absolute;
      inset: 0;
      background: #d1d5db;
      border-radius: 22px;
      cursor: pointer;
      transition: background 0.2s;
    }
    .toggle-slider::before {
      content: '';
      position: absolute;
      width: 16px; height: 16px;
      left: 3px; top: 3px;
      background: #fff;
      border-radius: 50%;
      transition: transform 0.2s;
      box-shadow: 0 1px 3px rgba(0,0,0,0.2);
    }
    .toggle input:checked + .toggle-slider { background: #7c3aed; }
    .toggle input:checked + .toggle-slider::before { transform: translateX(18px); }
    .toggle-label { font-size: 13px; color: #374151; }
    .toggle-label small { display: block; font-size: 11px; color: #9ca3af; margin-top: 1px; }
    .submit-btn {
      width: 100%;
      padding: 13px;
      background: #7c3aed;
      color: #fff;
      font-size: 14px;
      font-weight: 700;
      border: none;
      border-radius: 10px;
      cursor: pointer;
      transition: background 0.15s, transform 0.1s;
      letter-spacing: 0.01em;
    }
    .submit-btn:hover { background: #6d28d9; }
    .submit-btn:active { transform: scale(0.99); }
    .submit-btn:disabled { background: #d1d5db; cursor: not-allowed; }
    .error-banner {
      background: #fef2f2;
      border: 1px solid #fca5a5;
      border-radius: 8px;
      padding: 12px 16px;
      font-size: 13px;
      color: #b91c1c;
      margin-bottom: 20px;
    }
    .spinner-overlay {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(240,242,248,0.8);
      z-index: 999;
      align-items: center;
      justify-content: center;
      flex-direction: column;
      gap: 16px;
    }
    .spinner-overlay.active { display: flex; }
    .spinner {
      width: 40px; height: 40px;
      border: 4px solid #e5e7eb;
      border-top-color: #7c3aed;
      border-radius: 50%;
      animation: spin 0.7s linear infinite;
    }
    .spinner-text { font-size: 14px; font-weight: 600; color: #374151; }
    @keyframes spin { to { transform: rotate(360deg); } }
    footer {
      text-align: center;
      padding: 20px;
      font-size: 11px;
      color: #9ca3af;
    }
    footer a { color: #9ca3af; text-decoration: none; }
    footer a:hover { color: #374151; text-decoration: underline; }
  </style>
</head>
<body>

<header>
  <h1>Claude Audit Log Visualizer</h1>
</header>

<div class="spinner-overlay" id="spinner">
  <div class="spinner"></div>
  <div class="spinner-text">Generating dashboard&hellip;</div>
</div>

<main>
  <div class="card">
    <h2>Generate Dashboard</h2>
    <p class="subtitle">Upload a claude.ai audit log CSV to generate a self-contained HTML dashboard.</p>

    {% if error %}
    <div class="error-banner">{{ error }}</div>
    {% endif %}

    <form method="POST" action="/generate" enctype="multipart/form-data" id="uploadForm">

      <div class="field">
        <label class="field-label">Audit Log CSV</label>
        <div class="drop-zone" id="dropZone">
          <input type="file" name="csv_file" id="csvInput" accept=".csv" required>
          <div class="dz-icon">&#128196;</div>
          <div class="dz-text"><strong>Click to browse</strong> or drag &amp; drop</div>
          <div class="dz-hint">Only .csv files accepted</div>
          <div class="dz-filename" id="dzFilename"></div>
        </div>
      </div>

      <div class="field">
        <label class="field-label">Privacy Options</label>
        <div class="toggle-row">
          <label class="toggle">
            <input type="checkbox" name="reveal" id="revealToggle">
            <span class="toggle-slider"></span>
          </label>
          <span class="toggle-label">
            Reveal PII
            <small>Embed real names &amp; email addresses in the output</small>
          </span>
        </div>
      </div>

      <button type="submit" class="submit-btn" id="submitBtn" disabled>
        Generate Dashboard
      </button>
    </form>
  </div>
</main>

<footer>
  <a href="https://github.com/q-johnson/claude-auditlog-visualizer" target="_blank" rel="noopener">GitHub</a>
</footer>

<script>
  const input    = document.getElementById('csvInput');
  const dropZone = document.getElementById('dropZone');
  const filename = document.getElementById('dzFilename');
  const submitBtn = document.getElementById('submitBtn');
  const form     = document.getElementById('uploadForm');
  const spinner  = document.getElementById('spinner');

  function updateFile(file) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.csv')) {
      alert('Please select a .csv file.');
      input.value = '';
      return;
    }
    filename.textContent = file.name;
    filename.style.display = 'block';
    submitBtn.disabled = false;
  }

  input.addEventListener('change', () => updateFile(input.files[0]));

  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) {
      // Assign to the file input via DataTransfer
      const dt = new DataTransfer();
      dt.items.add(file);
      input.files = dt.files;
      updateFile(file);
    }
  });

  form.addEventListener('submit', () => {
    submitBtn.disabled = true;
    spinner.classList.add('active');
  });
</script>

</body>
</html>
"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    from flask import render_template_string
    return render_template_string(_FORM_HTML, error=None)


@app.route("/generate", methods=["POST"])
def generate():
    from flask import render_template_string

    csv_file = request.files.get("csv_file")
    if not csv_file or csv_file.filename == "":
        return render_template_string(_FORM_HTML, error="No file selected."), 400

    if not csv_file.filename.lower().endswith(".csv"):
        return render_template_string(_FORM_HTML, error="Only .csv files are accepted."), 400

    reveal = "reveal" in request.form

    # Write upload to a temp file so parse_csv (which uses open()) can read it
    suffix = ".csv"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp_path = tmp.name
        csv_file.save(tmp_path)

    try:
        rows, warnings = parse_csv(tmp_path, reveal)
        source_filename = csv_file.filename
        stats = build_stats(rows, source_filename)
        html_out = generate_html(rows, stats, reveal, warnings)
    finally:
        os.unlink(tmp_path)

    return Response(html_out, mimetype="text/html; charset=utf-8")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = 3000
    print(f"Starting Claude Audit Log Visualizer on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
