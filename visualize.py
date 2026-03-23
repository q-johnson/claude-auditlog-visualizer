#!/usr/bin/env python3
"""
visualize.py claude.ai audit log visualizer

Author: q-johnson

Parses a claude.ai audit log CSV and generates a self-contained HTML dashboard.
To get the CSV: Claude.ai Admin Settings > Data and Privacy > Export audit logs

Usage:
    python visualize.py <csv_file> [--reveal] [--output output.html]
"""

import argparse
import ast
import csv
import hashlib
import hmac
import html
import json
import secrets
import sys

# ---------------------------------------------------------------------------
# Event categorization
# ---------------------------------------------------------------------------

CATEGORY_MAP = {
    # auth
    "user_signed_in_sso": "auth",
    "user_signed_out": "auth",
    "user_requested_magic_link": "auth",
    "user_verified_phone_code": "auth",
    "user_sent_phone_code": "auth",
    # usage
    "conversation_created": "usage",
    "conversation_deleted": "usage",
    "file_uploaded": "usage",
    "project_created": "usage",
    "project_renamed": "usage",
    "project_deleted": "usage",
    "project_document_created": "usage",
    "project_document_deleted": "usage",
    "integration_user_connected": "usage",
    "user_name_changed": "usage",
    # permissions
    "role_assignment_granted": "permissions",
    "role_assignment_revoked": "permissions",
    "org_user_updated": "permissions",
    "org_user_invite_sent": "permissions",
    "org_user_invite_re_sent": "permissions",
    "org_user_invite_accepted": "permissions",
    "org_user_invite_deleted": "permissions",
    "org_user_deleted": "permissions",
}


def categorize(event: str) -> str:
    if event in CATEGORY_MAP:
        return CATEGORY_MAP[event]
    if event.startswith("org_"):
        return "admin"
    return "other"


# ---------------------------------------------------------------------------
# PII hashing
# ---------------------------------------------------------------------------

# Ephemeral per-run key — makes hash tokens unpredictable without the key.
_HASH_KEY = secrets.token_bytes(32)


def hash_pii(value: str) -> str:
    """Return a 16-char hex HMAC-SHA-256 digest of value, keyed by _HASH_KEY."""
    return hmac.new(_HASH_KEY, value.encode("utf-8"), "sha256").hexdigest()[:16]


def anonymize_actor(actor: dict, reveal: bool) -> dict:
    """Replace name and email in an actor dict with hashed equivalents."""
    if reveal or not actor:
        return actor
    result = dict(actor)
    if isinstance(result.get("metadata"), dict):
        meta = dict(result["metadata"])
        if meta.get("email_address"):
            meta["email_address"] = f"user-{hash_pii(meta['email_address'])}"
        result["metadata"] = meta
    if result.get("name"):
        result["name"] = f"user-{hash_pii(result['name'])}"
    return result


# ---------------------------------------------------------------------------
# Python-dict string parsing
# ---------------------------------------------------------------------------

def parse_pydict(raw: str) -> tuple:
    """
    Safely parse a Python-dict-formatted string as produced by claude.ai exports.
    These use single quotes, Python booleans (True/False), and None -- not valid JSON.
    Returns (dict, failed: bool). Failed is True when the field had content but
    couldn't be parsed, which the caller should surface as a warning.
    """
    if not raw or raw.strip() in ("", "{}"):
        return {}, False
    if len(raw) > 64_000:
        return {}, True
    try:
        value = ast.literal_eval(raw)
        if isinstance(value, dict):
            return value, False
    except (ValueError, SyntaxError):
        pass
    return {}, True


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------

def parse_csv(path: str, reveal: bool) -> tuple:
    """
    Returns (rows, warnings) where warnings is a list of dicts describing
    anything that could not be parsed or categorized.
    """
    rows = []
    warnings = []
    # Track unseen event types so we only warn once per type
    unknown_event_types: set = set()
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row_num, raw in enumerate(reader, start=2):  # row 1 = header
                actor_raw = raw.get("actor_info", "")
                actor_parsed, actor_failed = parse_pydict(actor_raw)
                if actor_failed:
                    warnings.append({
                        "severity": "warn",
                        "message": f"Row {row_num}: could not parse actor_info field — actor details will be blank.",
                        "detail": actor_raw[:120],
                    })
                actor = anonymize_actor(actor_parsed, reveal)

                event_info_raw = raw.get("event_info", "")
                event_info, ei_failed = parse_pydict(event_info_raw)
                if ei_failed:
                    warnings.append({
                        "severity": "warn",
                        "message": f"Row {row_num}: could not parse event_info field — event details will be blank.",
                        "detail": event_info_raw[:120],
                    })

                entity_info_raw = raw.get("entity_info", "")
                entity_info, eni_failed = parse_pydict(entity_info_raw)
                if eni_failed:
                    warnings.append({
                        "severity": "warn",
                        "message": f"Row {row_num}: could not parse entity_info field — entity details will be blank.",
                        "detail": entity_info_raw[:120],
                    })

                event = raw.get("event", "").strip()
                if not event:
                    warnings.append({
                        "severity": "warn",
                        "message": f"Row {row_num}: missing event name — row included but not categorized.",
                        "detail": "",
                    })
                elif categorize(event) == "other" and event not in unknown_event_types:
                    unknown_event_types.add(event)
                    warnings.append({
                        "severity": "info",
                        "message": f"Unknown event type '{event}' — categorized as 'other'. It will appear in the Raw Log but not in Admin or specialized views.",
                        "detail": "",
                    })

                # Extract and optionally hash filename from event_info
                raw_filename = event_info.get("filename", "")
                if raw_filename and not reveal:
                    filename = f"file-{hash_pii(raw_filename)}"
                    # Also scrub from the embedded event_info dict
                    event_info = dict(event_info)
                    event_info["filename"] = filename
                else:
                    filename = raw_filename

                # Pull display name / email out of actor dict
                name = actor.get("name", "")
                email = ""
                if isinstance(actor.get("metadata"), dict):
                    email = actor["metadata"].get("email_address", "")

                # Normalise platform: empty means API/scripted access
                platform = raw.get("client_platform", "").strip()
                if not platform:
                    platform = "api"

                rows.append({
                    "ts": raw.get("created_at", "").strip(),
                    "event": event,
                    "category": categorize(event),
                    "actor_name": name,
                    "actor_email": email,
                    "actor_uuid": actor.get("uuid", ""),
                    "event_info": event_info,
                    "entity_info": entity_info,
                    "filename": filename,
                    "ip": raw.get("ip_address", "").strip(),
                    "device_id": raw.get("device_id", "").strip(),
                    "user_agent": raw.get("user_agent", "").strip(),
                    "platform": platform,
                })
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: permission denied reading: {path}", file=sys.stderr)
        sys.exit(1)

    rows.sort(key=lambda r: r["ts"])
    return rows, warnings


# ---------------------------------------------------------------------------
# Stats computation
# ---------------------------------------------------------------------------

def build_stats(rows: list, source_filename: str) -> dict:
    from datetime import datetime

    total = len(rows)

    user_keys: set = set()
    for r in rows:
        key = r["actor_email"] or r["actor_uuid"]
        if key:
            user_keys.add(key)

    timestamps = sorted(r["ts"] for r in rows if r["ts"])
    if timestamps:
        try:
            dt_first = datetime.fromisoformat(timestamps[0].replace("Z", "+00:00"))
            dt_last = datetime.fromisoformat(timestamps[-1].replace("Z", "+00:00"))
            days = max((dt_last - dt_first).days, 1)
            date_range = (
                f"{dt_first.strftime('%b %d')} – {dt_last.strftime('%b %d, %Y')}"
            )
        except ValueError:
            date_range = f"{timestamps[0][:10]} – {timestamps[-1][:10]}"
            days = 1
    else:
        date_range, days = "N/A", 0

    event_types = len({r["event"] for r in rows})

    user_counts: dict = {}
    for r in rows:
        key = r["actor_email"] or r["actor_uuid"] or "unknown"
        user_counts[key] = user_counts.get(key, 0) + 1

    if user_counts:
        top_key = max(user_counts, key=user_counts.get)
        top_name = top_key
        for r in rows:
            if (
                r["actor_email"] == top_key or r["actor_uuid"] == top_key
            ) and r["actor_name"]:
                top_name = r["actor_name"]
                break
        top_count = user_counts[top_key]
    else:
        top_name, top_count = "—", 0

    return {
        "total": total,
        "unique_users": len(user_keys),
        "date_range": date_range,
        "days": days,
        "event_types": event_types,
        "top_user": top_name,
        "top_user_count": top_count,
        "source_filename": source_filename,
    }


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Claude Audit Log — __SOURCE_FILENAME__</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                   'Helvetica Neue', sans-serif;
      background: #f0f2f8;
      color: #1a1a2e;
      font-size: 14px;
      line-height: 1.5;
    }

    /* ---- Nav bar ---- */
    .site-nav {
      background: #16172a;
      padding: 0 32px;
      display: flex;
      gap: 4px;
      overflow-x: auto;
    }
    .site-nav a {
      color: #8899bb;
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      padding: 10px 12px;
      border-bottom: 2px solid transparent;
      white-space: nowrap;
      transition: color 0.15s, border-color 0.15s;
    }
    .site-nav a:hover { color: #fff; border-bottom-color: #7c3aed; }

    /* ---- Parse warnings banner ---- */
    .warnings-banner {
      background: #fffbeb;
      border-bottom: 2px solid #f59e0b;
      padding: 12px 32px;
    }
    .warnings-banner summary {
      cursor: pointer;
      font-size: 13px;
      font-weight: 700;
      color: #92400e;
      user-select: none;
      list-style: none;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .warnings-banner summary::-webkit-details-marker { display: none; }
    .warnings-banner summary::before {
      content: '';
      display: inline-block;
      width: 0; height: 0;
      border-left: 6px solid #92400e;
      border-top: 4px solid transparent;
      border-bottom: 4px solid transparent;
      transition: transform 0.15s;
    }
    .warnings-banner[open] summary::before { transform: rotate(90deg); }
    .wb-list {
      margin: 10px 0 4px 22px;
      padding: 0;
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .wb-item {
      font-size: 12px;
      color: #78350f;
      background: #fef3c7;
      border-left: 3px solid #f59e0b;
      padding: 6px 10px;
      border-radius: 0 4px 4px 0;
    }
    .wb-item.wb-info {
      color: #1e40af;
      background: #eff6ff;
      border-left-color: #3b82f6;
    }
    .wb-detail {
      font-family: monospace;
      font-size: 11px;
      color: #9ca3af;
      margin-top: 2px;
      word-break: break-all;
    }
    .wb-dismiss {
      margin-left: auto;
      background: none;
      border: 1px solid #f59e0b;
      border-radius: 4px;
      color: #92400e;
      font-size: 11px;
      padding: 2px 8px;
      cursor: pointer;
    }
    .wb-dismiss:hover { background: #fef3c7; }

    /* ---- Header ---- */
    .site-header {
      background: #1a1a2e;
      color: #fff;
      padding: 16px 32px;
      display: flex;
      align-items: center;
      gap: 14px;
      position: sticky;
      top: 0;
      z-index: 100;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    }
    .site-header h1 {
      font-size: 17px;
      font-weight: 600;
      flex: 1;
      letter-spacing: -0.01em;
    }
    .site-header .hdr-meta {
      font-size: 12px;
      color: #8899bb;
      white-space: nowrap;
    }
    .pii-badge {
      font-size: 11px;
      font-weight: 700;
      padding: 4px 12px;
      border-radius: 100px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      white-space: nowrap;
    }
    .pii-badge.protected { background: #1b4332; color: #95d5b2; border: 1px solid #2d6a4f; }
    .pii-badge.revealed  { background: #4a040a; color: #ffb3ba; border: 1px solid #9b1b28; }

    /* ---- Layout ---- */
    main { max-width: 1440px; margin: 0 auto; padding: 28px 32px 60px; }
    .dashboard-section { margin-bottom: 40px; }
    .section-title {
      font-size: 11px;
      font-weight: 700;
      color: #6b7280;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 14px;
    }

    /* ---- Stat cards ---- */
    .stat-cards {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 16px;
    }
    @media (max-width: 1100px) { .stat-cards { grid-template-columns: repeat(3, 1fr); } }
    @media (max-width: 700px)  { .stat-cards { grid-template-columns: repeat(2, 1fr); } }
    .stat-card {
      background: #fff;
      border-radius: 12px;
      padding: 22px 24px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.07), 0 1px 2px rgba(0,0,0,0.04);
      border-top: 4px solid #d1d5db;
      transition: box-shadow 0.15s;
    }
    .stat-card:hover { box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
    .stat-card.c-purple { border-top-color: #7c3aed; }
    .stat-card.c-blue   { border-top-color: #0369a1; }
    .stat-card.c-teal   { border-top-color: #0d9488; }
    .stat-card.c-orange { border-top-color: #ea580c; }
    .stat-card.c-green  { border-top-color: #16a34a; }
    .stat-card .sc-label {
      font-size: 10px;
      font-weight: 700;
      color: #9ca3af;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      margin-bottom: 10px;
    }
    .stat-card .sc-value {
      font-size: 30px;
      font-weight: 800;
      color: #111827;
      line-height: 1;
      margin-bottom: 6px;
    }
    .stat-card .sc-value-sm { font-size: 16px; padding-top: 4px; font-weight: 700; }
    .stat-card .sc-sub { font-size: 11px; color: #9ca3af; }

    /* ---- Charts ---- */
    .chart-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 900px) { .chart-grid { grid-template-columns: 1fr; } }
    .chart-card {
      background: #fff;
      border-radius: 12px;
      padding: 20px 24px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.07);
    }
    .chart-card h3 {
      font-size: 12px;
      font-weight: 700;
      color: #374151;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      margin-bottom: 16px;
    }
    .chart-wrap { position: relative; }
    .chart-wrap.tall  { height: 320px; }
    .chart-wrap.short { height: 240px; }

    /* ---- Admin highlight cards ---- */
    .admin-cards {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
      gap: 14px;
    }
    .admin-card {
      background: #fff;
      border-radius: 10px;
      padding: 16px 18px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.07);
      border-left: 4px solid #ea580c;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .admin-card .ac-event {
      font-size: 12px;
      font-weight: 700;
      color: #ea580c;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .admin-card .ac-actor {
      font-size: 13px;
      font-weight: 600;
      color: #111827;
    }
    .admin-card .ac-ts {
      font-size: 11px;
      color: #9ca3af;
    }
    .admin-card .ac-detail {
      font-size: 11px;
      color: #6b7280;
      word-break: break-all;
    }

    /* ---- Activity timeline ---- */
    .timeline-wrap {
      background: #fff;
      border-radius: 12px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.07);
      overflow: hidden;
    }
    .tl-row {
      display: grid;
      grid-template-columns: 170px 110px 1fr 180px;
      align-items: start;
      padding: 10px 18px;
      border-bottom: 1px solid #f3f4f6;
      cursor: pointer;
      transition: background 0.1s;
      gap: 10px;
    }
    .tl-row:hover { background: #f9fafb; }
    .tl-row.tl-header {
      background: #f3f4f6;
      cursor: default;
      font-size: 10px;
      font-weight: 700;
      color: #9ca3af;
      text-transform: uppercase;
      letter-spacing: 0.07em;
    }
    .tl-row.tl-header:hover { background: #f3f4f6; }
    .tl-ts { font-size: 12px; color: #6b7280; white-space: nowrap; }
    .cat-badge {
      display: inline-block;
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 2px 8px;
      border-radius: 100px;
      white-space: nowrap;
    }
    .cat-auth        { background: #dbeafe; color: #1d4ed8; }
    .cat-usage       { background: #dcfce7; color: #166534; }
    .cat-admin       { background: #ffedd5; color: #9a3412; }
    .cat-permissions { background: #ede9fe; color: #5b21b6; }
    .cat-other       { background: #f3f4f6; color: #374151; }
    .tl-event { font-size: 13px; font-weight: 500; color: #111827; }
    .tl-actor { font-size: 12px; color: #6b7280; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .tl-detail {
      display: none;
      grid-column: 1 / -1;
      background: #f9fafb;
      border-top: 1px solid #e5e7eb;
      padding: 12px 18px;
      font-size: 12px;
      color: #374151;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .tl-row.expanded .tl-detail { display: block; }
    .tl-row.expanded { background: #f0f2f8; }
    @media (max-width: 700px) {
      .tl-row { grid-template-columns: 1fr 1fr; }
      .tl-actor { display: none; }
    }

    /* ---- Sortable tables ---- */
    .data-table-wrap {
      background: #fff;
      border-radius: 12px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.07);
      overflow: hidden;
    }
    .filter-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      padding: 14px 18px;
      border-bottom: 1px solid #f3f4f6;
      background: #fafafa;
    }
    .filter-bar input, .filter-bar select {
      font-size: 12px;
      padding: 6px 10px;
      border: 1px solid #d1d5db;
      border-radius: 6px;
      background: #fff;
      color: #111827;
      outline: none;
    }
    .filter-bar input { flex: 1; min-width: 160px; }
    .filter-bar input:focus, .filter-bar select:focus { border-color: #7c3aed; }
    table.dt {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }
    table.dt thead th {
      background: #f3f4f6;
      padding: 10px 14px;
      text-align: left;
      font-size: 10px;
      font-weight: 700;
      color: #6b7280;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      cursor: pointer;
      user-select: none;
      white-space: nowrap;
    }
    table.dt thead th:hover { background: #e5e7eb; }
    table.dt thead th.sort-asc::after  { content: ' \25B2'; }
    table.dt thead th.sort-desc::after { content: ' \25BC'; }
    table.dt tbody tr { border-bottom: 1px solid #f3f4f6; }
    table.dt tbody tr:hover { background: #f9fafb; }
    table.dt tbody td { padding: 9px 14px; color: #374151; vertical-align: top; }
    table.dt tbody td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; color: #6b7280; }
    .pagination {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 12px 18px;
      font-size: 12px;
      color: #6b7280;
      border-top: 1px solid #f3f4f6;
    }
    .pagination button {
      padding: 4px 12px;
      font-size: 12px;
      border: 1px solid #d1d5db;
      border-radius: 6px;
      background: #fff;
      cursor: pointer;
      color: #374151;
    }
    .pagination button:hover:not(:disabled) { background: #f3f4f6; }
    .pagination button:disabled { opacity: 0.4; cursor: default; }
    .pagination .pg-info { flex: 1; text-align: right; }

    /* ---- Footer ---- */
    .site-footer {
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px 32px;
      font-size: 11px;
      color: #9ca3af;
      border-top: 1px solid #e5e7eb;
      margin-top: 20px;
      position: relative;
    }
    .site-footer .footer-main { text-align: center; }
    .site-footer .footer-repo {
      position: absolute;
      right: 32px;
    }
    .site-footer .footer-repo a {
      color: #9ca3af;
      text-decoration: none;
      font-size: 11px;
    }
    .site-footer .footer-repo a:hover { color: #374151; text-decoration: underline; }

    /* ---- Placeholder ---- */
    .placeholder {
      background: #fff;
      border-radius: 12px;
      padding: 40px;
      text-align: center;
      color: #d1d5db;
      font-size: 13px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    }
  </style>
</head>
<body>

<header class="site-header">
  <h1>Claude Audit Log Dashboard</h1>
  <span class="hdr-meta">
    __SOURCE_FILENAME__ &nbsp;&middot;&nbsp;
    __TOTAL_EVENTS__ events &nbsp;&middot;&nbsp;
    __DATE_RANGE__
  </span>
  <span class="pii-badge __PII_BADGE_CLASS__">__PII_BADGE_TEXT__</span>
</header>

<nav class="site-nav">
  <a href="#section-charts">Charts</a>
  <a href="#section-admin">Admin Events</a>
  <a href="#section-timeline">Timeline</a>
  <a href="#section-users">Users</a>
  <a href="#section-log">Raw Log</a>
</nav>

__WARNINGS_BANNER__

<main>

  <!-- Stat cards -->
  <section class="dashboard-section">
    <div class="section-title">Overview</div>
    <div class="stat-cards">
      <div class="stat-card c-purple">
        <div class="sc-label">Total Events</div>
        <div class="sc-value">__TOTAL_EVENTS__</div>
        <div class="sc-sub">across all users</div>
      </div>
      <div class="stat-card c-blue">
        <div class="sc-label">Unique Users</div>
        <div class="sc-value">__UNIQUE_USERS__</div>
        <div class="sc-sub">active in this period</div>
      </div>
      <div class="stat-card c-teal">
        <div class="sc-label">Date Range</div>
        <div class="sc-value sc-value-sm">__DATE_RANGE__</div>
        <div class="sc-sub">__DAYS__ days</div>
      </div>
      <div class="stat-card c-orange">
        <div class="sc-label">Event Types</div>
        <div class="sc-value">__EVENT_TYPES__</div>
        <div class="sc-sub">distinct types</div>
      </div>
      <div class="stat-card c-green">
        <div class="sc-label">Most Active User</div>
        <div class="sc-value sc-value-sm">__TOP_USER__</div>
        <div class="sc-sub">__TOP_USER_COUNT__ events</div>
      </div>
    </div>
  </section>

  <!-- Charts -->
  <section class="dashboard-section" id="section-charts">
    <div class="section-title">Activity Charts</div>
    <div class="chart-grid">
      <div class="chart-card">
        <h3>Events Over Time</h3>
        <div class="chart-wrap tall"><canvas id="chartTimeline"></canvas></div>
      </div>
      <div class="chart-card">
        <h3>Events by Type</h3>
        <div class="chart-wrap tall"><canvas id="chartByType"></canvas></div>
      </div>
      <div class="chart-card">
        <h3>Events by User (Top 10)</h3>
        <div class="chart-wrap tall"><canvas id="chartByUser"></canvas></div>
      </div>
      <div class="chart-card">
        <h3>Platform Breakdown</h3>
        <div class="chart-wrap short" style="display:flex;align-items:center;justify-content:center;">
          <canvas id="chartPlatform" style="max-height:220px;max-width:220px;"></canvas>
        </div>
      </div>
    </div>
  </section>

  <!-- Admin highlights -->
  <section class="dashboard-section" id="section-admin">
    <div class="section-title">Admin &amp; Org Events <span id="badge-admin" style="font-weight:400;color:#9ca3af;"></span></div>
    <div class="admin-cards" id="adminCards"></div>
  </section>

  <!-- Activity timeline -->
  <section class="dashboard-section" id="section-timeline">
    <div class="section-title">Activity Timeline <span id="badge-timeline" style="font-weight:400;color:#9ca3af;"></span></div>
    <div class="timeline-wrap" id="timelineWrap"></div>
  </section>

  <!-- Per-user table -->
  <section class="dashboard-section" id="section-users">
    <div class="section-title">Per-User Summary <span id="badge-users" style="font-weight:400;color:#9ca3af;"></span></div>
    <div class="data-table-wrap" id="userTableWrap"></div>
  </section>

  <!-- Raw log table -->
  <section class="dashboard-section" id="section-log">
    <div class="section-title">Raw Event Log <span id="badge-log" style="font-weight:400;color:#9ca3af;"></span></div>
    <div class="data-table-wrap" id="logTableWrap"></div>
  </section>

</main>

<footer class="site-footer">
  <span class="footer-main">
    Generated __GENERATED_AT__ &nbsp;&middot;&nbsp; __SOURCE_FILENAME__ &nbsp;&middot;&nbsp; <span class="__PII_BADGE_CLASS__" style="font-weight:700;">__PII_BADGE_TEXT__</span>
  </span>
  <span class="footer-repo"><a href="https://github.com/q-johnson/claude-auditlog-visualizer" target="_blank" rel="noopener">GitHub</a></span>
</footer>

<script>
const DATA = __DATA_JSON__;
const PII_REVEALED = __PII_REVEALED__;

// ---- Colour palette -------------------------------------------------------
const CAT_COLORS = {
  auth:        '#0369a1',
  usage:       '#16a34a',
  admin:       '#ea580c',
  permissions: '#7c3aed',
  other:       '#6b7280',
};
const CAT_COLORS_ALPHA = Object.fromEntries(
  Object.entries(CAT_COLORS).map(([k,v]) => [k, v + '33'])
);
const PLATFORM_COLORS = [
  '#0369a1', '#16a34a', '#ea580c', '#7c3aed', '#0d9488', '#9ca3af'
];

// ---- Helpers ---------------------------------------------------------------
function groupBy(arr, keyFn) {
  return arr.reduce((acc, item) => {
    const k = keyFn(item);
    (acc[k] = acc[k] || []).push(item);
    return acc;
  }, {});
}
function countBy(arr, keyFn) {
  return arr.reduce((acc, item) => {
    const k = keyFn(item);
    acc[k] = (acc[k] || 0) + 1;
    return acc;
  }, {});
}
function isoToDate(ts) {
  return ts ? ts.slice(0, 10) : '';
}

// ---- Chart 1: Events over time (stacked bar by category) ------------------
(function() {
  const byDate = groupBy(DATA, r => isoToDate(r.ts));
  const dates = Object.keys(byDate).sort();
  const cats = ['auth', 'usage', 'admin', 'permissions', 'other'];

  const datasets = cats.map(cat => ({
    label: cat.charAt(0).toUpperCase() + cat.slice(1),
    data: dates.map(d => byDate[d].filter(r => r.category === cat).length),
    backgroundColor: CAT_COLORS[cat],
    borderRadius: 3,
    borderSkipped: false,
  }));

  new Chart(document.getElementById('chartTimeline'), {
    type: 'bar',
    data: { labels: dates, datasets },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } } },
      scales: {
        x: { stacked: true, ticks: { maxRotation: 45, font: { size: 11 } } },
        y: { stacked: true, beginAtZero: true, ticks: { precision: 0, font: { size: 11 } } },
      },
    },
  });
})();

// ---- Chart 2: Events by type (horizontal bar) -----------------------------
(function() {
  const counts = countBy(DATA, r => r.event);
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const labels = sorted.map(([k]) => k);
  const values = sorted.map(([, v]) => v);
  const colors = labels.map(l => {
    const cat = DATA.find(r => r.event === l)?.category || 'other';
    return CAT_COLORS[cat] || CAT_COLORS.other;
  });

  new Chart(document.getElementById('chartByType'), {
    type: 'bar',
    data: {
      labels,
      datasets: [{ data: values, backgroundColor: colors, borderRadius: 3 }],
    },
    options: {
      indexAxis: 'y',
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, ticks: { precision: 0, font: { size: 11 } } },
        y: { ticks: { font: { size: 11 } } },
      },
    },
  });
})();

// ---- Chart 3: Events by user (horizontal bar, top 10) ---------------------
(function() {
  const counts = countBy(
    DATA.filter(r => r.actor_email || r.actor_name),
    r => r.actor_name || r.actor_email
  );
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const labels = sorted.map(([k]) => k);
  const values = sorted.map(([, v]) => v);

  new Chart(document.getElementById('chartByUser'), {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: '#7c3aed',
        borderRadius: 3,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, ticks: { precision: 0, font: { size: 11 } } },
        y: { ticks: { font: { size: 11 } } },
      },
    },
  });
})();

// ---- Chart 4: Platform breakdown (doughnut) -------------------------------
(function() {
  const counts = countBy(DATA, r => r.platform || 'unknown');
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const labels = sorted.map(([k]) => k);
  const values = sorted.map(([, v]) => v);

  new Chart(document.getElementById('chartPlatform'), {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: PLATFORM_COLORS.slice(0, labels.length),
        borderWidth: 2,
        borderColor: '#f0f2f8',
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: true,
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } },
      },
    },
  });
})();

// ---- Admin highlights -----------------------------------------------------
(function() {
  const adminEvents = DATA
    .filter(r => r.category === 'admin' || r.category === 'permissions')
    .slice().reverse();
  const container = document.getElementById('adminCards');
  const badge = document.getElementById('badge-admin');
  if (badge) badge.textContent = `(${adminEvents.length})`;
  if (!adminEvents.length) {
    container.innerHTML = '<p style="color:#9ca3af;font-size:13px;">No admin events found.</p>';
    return;
  }
  adminEvents.forEach(r => {
    const ts = r.ts ? r.ts.replace('T', ' ').replace(/[.][0-9]+Z$/, ' UTC') : '';
    const actor = r.actor_name || r.actor_email || 'System';
    let detailParts = [];
    if (r.event_info && Object.keys(r.event_info).length)
      detailParts.push(JSON.stringify(r.event_info));
    if (r.entity_info && Object.keys(r.entity_info).length)
      detailParts.push(JSON.stringify(r.entity_info));
    const detail = detailParts.join(' | ') || '';
    const card = document.createElement('div');
    card.className = 'admin-card';
    card.innerHTML =
      `<div class="ac-event">${esc(r.event)}</div>` +
      `<div class="ac-actor">${esc(actor)}</div>` +
      `<div class="ac-ts">${esc(ts)}</div>` +
      (detail ? `<div class="ac-detail">${esc(detail)}</div>` : '');
    container.appendChild(card);
  });
})();

// ---- Activity timeline ----------------------------------------------------
(function() {
  const wrap = document.getElementById('timelineWrap');
  const sorted = DATA.slice().reverse();
  const badge = document.getElementById('badge-timeline');
  if (badge) badge.textContent = `(${sorted.length})`;

  const header = document.createElement('div');
  header.className = 'tl-row tl-header';
  header.innerHTML =
    '<span>Timestamp</span><span>Category</span>' +
    '<span>Event</span><span>Actor</span>';
  wrap.appendChild(header);

  sorted.forEach(r => {
    const ts = r.ts ? r.ts.replace('T', ' ').replace(/[.][0-9]+Z$/, ' UTC') : '';
    const actor = r.actor_name || r.actor_email || 'System';

    const detail = JSON.stringify({
      event_info:  r.event_info,
      entity_info: r.entity_info,
      ip:          r.ip,
      platform:    r.platform,
      device_id:   r.device_id,
      user_agent:  r.user_agent,
    }, null, 2);

    const row = document.createElement('div');
    row.className = 'tl-row';
    row.innerHTML =
      `<span class="tl-ts">${esc(ts)}</span>` +
      `<span><span class="cat-badge cat-${esc(r.category)}">${esc(r.category)}</span></span>` +
      `<span class="tl-event">${esc(r.event)}${r.filename ? '<span style="color:#9ca3af;font-weight:400;"> &mdash; ' + esc(r.filename) + '</span>' : ''}</span>` +
      `<span class="tl-actor">${esc(actor)}</span>` +
      `<div class="tl-detail">${esc(detail)}</div>`;

    row.addEventListener('click', () => row.classList.toggle('expanded'));
    wrap.appendChild(row);
  });
})();

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ---- Sortable table helper ------------------------------------------------
function makeSortableTable(container, columns, rows) {
  // columns: [{key, label, render?, mono?}]
  let sortKey = columns[0].key;
  let sortDir = 1;

  const table = document.createElement('table');
  table.className = 'dt';
  const thead = table.createTHead();
  const hrow = thead.insertRow();
  columns.forEach(col => {
    const th = document.createElement('th');
    th.textContent = col.label;
    th.dataset.key = col.key;
    th.addEventListener('click', () => {
      if (sortKey === col.key) sortDir *= -1;
      else { sortKey = col.key; sortDir = 1; }
      renderBody();
    });
    hrow.appendChild(th);
  });

  const tbody = table.createTBody();
  container.appendChild(table);

  function renderBody() {
    // update sort indicators
    hrow.querySelectorAll('th').forEach(th => {
      th.classList.remove('sort-asc', 'sort-desc');
      if (th.dataset.key === sortKey)
        th.classList.add(sortDir === 1 ? 'sort-asc' : 'sort-desc');
    });
    const sorted = rows.slice().sort((a, b) => {
      const av = a[sortKey] ?? '';
      const bv = b[sortKey] ?? '';
      if (av < bv) return -sortDir;
      if (av > bv) return  sortDir;
      return 0;
    });
    tbody.innerHTML = '';
    sorted.forEach(row => {
      const tr = tbody.insertRow();
      columns.forEach(col => {
        const td = tr.insertCell();
        if (col.mono) td.className = 'mono';
        td.innerHTML = col.render ? col.render(row) : esc(String(row[col.key] ?? ''));
      });
    });
  }

  renderBody();
}

// ---- Per-user summary table -----------------------------------------------
(function() {
  const byUser = {};
  DATA.forEach(r => {
    const key = r.actor_email || r.actor_uuid || 'system';
    if (!byUser[key]) byUser[key] = {
      name: r.actor_name || '',
      email: r.actor_email || '',
      total: 0,
      first: r.ts,
      last: r.ts,
      eventCounts: {},
      platforms: new Set(),
    };
    const u = byUser[key];
    u.total++;
    if (r.ts < u.first) u.first = r.ts;
    if (r.ts > u.last)  u.last  = r.ts;
    u.eventCounts[r.event] = (u.eventCounts[r.event] || 0) + 1;
    u.platforms.add(r.platform);
  });

  const rows = Object.values(byUser).map(u => ({
    name:      u.name || '(system)',
    email:     u.email,
    total:     u.total,
    first:     u.first ? u.first.slice(0, 10) : '',
    last:      u.last  ? u.last.slice(0, 10)  : '',
    top_event: Object.entries(u.eventCounts).sort((a,b) => b[1]-a[1])[0]?.[0] || '',
    platforms: [...u.platforms].filter(Boolean).join(', '),
  }));

  const columns = [
    { key: 'name',      label: 'Name' },
    { key: 'email',     label: 'Email', mono: true },
    { key: 'total',     label: 'Events' },
    { key: 'first',     label: 'First Seen', mono: true },
    { key: 'last',      label: 'Last Seen',  mono: true },
    { key: 'top_event', label: 'Top Event' },
    { key: 'platforms', label: 'Platforms' },
  ];

  makeSortableTable(document.getElementById('userTableWrap'), columns, rows);
  const ubadge = document.getElementById('badge-users');
  if (ubadge) ubadge.textContent = `(${rows.length})`;
})();

// ---- Raw log table with filters + pagination ------------------------------
(function() {
  const PAGE_SIZE = 50;
  let page = 0;
  let filtered = DATA.slice().reverse();

  const wrap = document.getElementById('logTableWrap');

  // Filter bar
  const bar = document.createElement('div');
  bar.className = 'filter-bar';

  const searchEl = document.createElement('input');
  searchEl.type = 'text';
  searchEl.placeholder = 'Search events, users, IPs...';

  const eventTypes = ['(all events)', ...new Set(DATA.map(r => r.event).sort())];
  const eventSel = document.createElement('select');
  eventTypes.forEach(e => { const o = document.createElement('option'); o.value = e; o.textContent = e; eventSel.appendChild(o); });

  const userKeys = ['(all users)', ...new Set(
    DATA.map(r => r.actor_name || r.actor_email).filter(Boolean).sort()
  )];
  const userSel = document.createElement('select');
  userKeys.forEach(u => { const o = document.createElement('option'); o.value = u; o.textContent = u; userSel.appendChild(o); });

  const platformKeys = ['(all platforms)', ...new Set(DATA.map(r => r.platform).filter(Boolean).sort())];
  const platformSel = document.createElement('select');
  platformKeys.forEach(p => { const o = document.createElement('option'); o.value = p; o.textContent = p; platformSel.appendChild(o); });

  const dateFromEl = document.createElement('input');
  dateFromEl.type = 'date';
  dateFromEl.title = 'From date';
  const dateToEl = document.createElement('input');
  dateToEl.type = 'date';
  dateToEl.title = 'To date';

  [searchEl, eventSel, userSel, platformSel, dateFromEl, dateToEl].forEach(el => {
    bar.appendChild(el);
    el.addEventListener('input', () => { page = 0; applyFilters(); });
    el.addEventListener('change', () => { page = 0; applyFilters(); });
  });
  wrap.appendChild(bar);

  // Table
  const tableWrap = document.createElement('div');
  wrap.appendChild(tableWrap);

  // Pagination bar
  const pgBar = document.createElement('div');
  pgBar.className = 'pagination';
  const prevBtn = document.createElement('button');
  prevBtn.textContent = 'Previous';
  const nextBtn = document.createElement('button');
  nextBtn.textContent = 'Next';
  const pgInfo = document.createElement('span');
  pgInfo.className = 'pg-info';
  prevBtn.addEventListener('click', () => { page--; render(); });
  nextBtn.addEventListener('click', () => { page++; render(); });
  pgBar.append(prevBtn, nextBtn, pgInfo);
  wrap.appendChild(pgBar);

  const columns = [
    { key: 'ts',         label: 'Timestamp',  mono: true,
      render: r => `<span style="white-space:nowrap">${esc(r.ts.replace('T',' ').replace(/[.][0-9]+Z$/,' UTC'))}</span>` },
    { key: 'category',  label: 'Category',
      render: r => `<span class="cat-badge cat-${esc(r.category)}">${esc(r.category)}</span>` },
    { key: 'event',     label: 'Event' },
    { key: 'filename',  label: 'Filename', mono: true,
      render: r => r.filename ? esc(r.filename) : '<span style="color:#d1d5db">—</span>' },
    { key: 'actor_name', label: 'User',
      render: r => esc(r.actor_name || r.actor_email || 'system') },
    { key: 'ip',        label: 'IP', mono: true },
    { key: 'platform',  label: 'Platform' },
  ];

  function applyFilters() {
    const q       = searchEl.value.toLowerCase();
    const evFilt  = eventSel.value;
    const usrFilt = userSel.value;
    const pltFilt = platformSel.value;
    const fromD   = dateFromEl.value;
    const toD     = dateToEl.value;

    filtered = DATA.filter(r => {
      if (evFilt  !== '(all events)'   && r.event    !== evFilt)  return false;
      if (usrFilt !== '(all users)'    && r.actor_name !== usrFilt && r.actor_email !== usrFilt) return false;
      if (pltFilt !== '(all platforms)'&& r.platform  !== pltFilt) return false;
      if (fromD && r.ts.slice(0,10) < fromD) return false;
      if (toD   && r.ts.slice(0,10) > toD)   return false;
      if (q) {
        const haystack = [r.event, r.actor_name, r.actor_email, r.ip, r.platform,
          JSON.stringify(r.event_info), JSON.stringify(r.entity_info)].join(' ').toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    }).reverse();
    const lbadge = document.getElementById('badge-log');
    if (lbadge) lbadge.textContent = filtered.length < DATA.length
      ? `(${filtered.length} of ${DATA.length})` : `(${DATA.length})`;
    render();
  }

  function render() {
    const total = filtered.length;
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    page = Math.min(page, pages - 1);
    const slice = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

    tableWrap.innerHTML = '';
    const table = document.createElement('table');
    table.className = 'dt';
    const thead = table.createTHead();
    const hrow = thead.insertRow();
    columns.forEach(col => {
      const th = document.createElement('th');
      th.textContent = col.label;
      hrow.appendChild(th);
    });
    const tbody = table.createTBody();
    slice.forEach(r => {
      const tr = tbody.insertRow();
      columns.forEach(col => {
        const td = tr.insertCell();
        if (col.mono) td.className = 'mono';
        td.innerHTML = col.render ? col.render(r) : esc(String(r[col.key] ?? ''));
      });
    });
    tableWrap.appendChild(table);

    prevBtn.disabled = page === 0;
    nextBtn.disabled = page >= pages - 1;
    pgInfo.textContent =
      total === 0 ? 'No results' :
      `${page * PAGE_SIZE + 1}\u2013${Math.min((page+1)*PAGE_SIZE, total)} of ${total}`;
  }

  applyFilters();
})();

</script>
</body>
</html>
"""


def _build_warnings_banner(warnings: list) -> str:
    """Return the HTML for the parse-warnings banner, or empty string if none."""
    if not warnings:
        return ""
    count = len(warnings)
    label = f"{count} parse warning{'s' if count != 1 else ''} — some events or fields could not be fully processed"
    items_html = ""
    for w in warnings:
        css_class = "wb-item wb-info" if w.get("severity") == "info" else "wb-item"
        detail_html = ""
        if w.get("detail"):
            esc_detail = w["detail"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            detail_html = f'<div class="wb-detail">{esc_detail}</div>'
        esc_msg = w["message"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        items_html += f'<li class="{css_class}">{esc_msg}{detail_html}</li>\n'
    return (
        f'<details class="warnings-banner" id="warnBanner">\n'
        f'  <summary>{label}'
        f'<button class="wb-dismiss" onclick="document.getElementById(\'warnBanner\').remove()" title="Dismiss">Dismiss</button>'
        f'</summary>\n'
        f'  <ul class="wb-list">\n{items_html}  </ul>\n'
        f'</details>'
    )


def generate_html(rows: list, stats: dict, reveal: bool, warnings: list = None) -> str:
    from datetime import datetime, timezone
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    data_json = json.dumps(rows, separators=(",", ":"), ensure_ascii=False)
    data_json = data_json.replace("&", r"\u0026").replace("<", r"\u003c").replace(">", r"\u003e")
    html_out = _HTML_TEMPLATE
    replacements = {
        "__SOURCE_FILENAME__": html.escape(stats["source_filename"]),
        "__TOTAL_EVENTS__":    str(stats["total"]),
        "__UNIQUE_USERS__":    str(stats["unique_users"]),
        "__DATE_RANGE__":      html.escape(stats["date_range"]),
        "__DAYS__":            str(stats["days"]),
        "__EVENT_TYPES__":     str(stats["event_types"]),
        "__TOP_USER__":        html.escape(stats["top_user"]),
        "__TOP_USER_COUNT__":  str(stats["top_user_count"]),
        "__PII_BADGE_CLASS__": "revealed" if reveal else "protected",
        "__PII_BADGE_TEXT__":  "PII Visible" if reveal else "PII Protected",
        "__GENERATED_AT__":    generated_at,
        "__WARNINGS_BANNER__": _build_warnings_banner(warnings or []),
        "__DATA_JSON__":       data_json,
        "__PII_REVEALED__":    "true" if reveal else "false",
    }
    for placeholder, value in replacements.items():
        html_out = html_out.replace(placeholder, value)
    return html_out


def write_and_open(html: str, output_path: str) -> None:
    import os
    import webbrowser

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    abs_path = os.path.abspath(output_path)
    webbrowser.open(f"file:///{abs_path.replace(chr(92), '/')}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Generate an HTML dashboard from a claude.ai audit log CSV."
    )
    p.add_argument("csv_file", help="Path to the audit log CSV file.")
    p.add_argument(
        "--reveal",
        action="store_true",
        help=(
            "Embed real names and email addresses in the output. "
            "By default all PII is SHA-256 hashed."
        ),
    )
    p.add_argument(
        "--output",
        default="output.html",
        metavar="FILE",
        help="Output file path (default: output.html).",
    )
    return p


def main() -> None:
    import os

    args = build_argparser().parse_args()
    source_filename = os.path.basename(args.csv_file)

    print(f"Parsing {args.csv_file} ...")
    rows, warnings = parse_csv(args.csv_file, args.reveal)
    stats = build_stats(rows, source_filename)

    pii_mode = "revealed" if args.reveal else "protected (--reveal to include real names/emails)"
    print(f"  {stats['total']} events  |  {stats['unique_users']} users  |  {stats['date_range']}")
    print(f"  PII: {pii_mode}")
    if args.reveal:
        print("  WARNING: output will contain real names and email addresses.")
    if warnings:
        warn_count = len(warnings)
        print(f"  {warn_count} parse warning{'s' if warn_count != 1 else ''} — see the banner at the top of the dashboard.")
        for w in warnings:
            print(f"    [{w['severity'].upper()}] {w['message']}")

    html = generate_html(rows, stats, args.reveal, warnings)
    write_and_open(html, args.output)
    print(f"  Output: {os.path.abspath(args.output)}")


if __name__ == "__main__":
    main()
