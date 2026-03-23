# claude-auditlog-visualizer

A command-line tool that turns a claude.ai audit log CSV into a self-contained HTML dashboard.

Generates a single `output.html` file and opens it in your default browser. No server required.

---

## Requirements

- Python 3.9+
- No third-party packages — uses stdlib only

---

## Setup

```bash
git clone https://github.com/your-org/claude-auditlog-visualizer.git
cd claude-auditlog-visualizer

python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate
```

---

## Usage

```bash
python visualize.py <path/to/audit_logs.csv>
```

This generates `output.html` in the current directory and opens it in your browser.

**Options**

| Flag | Description |
|------|-------------|
| `--reveal` | Embed real names and email addresses in the output. By default all PII is hashed with HMAC-SHA-256 using an ephemeral per-run key. |
| `--output <file>` | Write output to a specific file instead of `output.html`. |

**Examples**

```bash
# PII-safe output (default)
python visualize.py audit_logs.csv

# Include real names and emails
python visualize.py audit_logs.csv --reveal

# Custom output path
python visualize.py audit_logs.csv --output report.html
```

---

## Privacy

By default, names and email addresses are replaced with HMAC-SHA-256 tokens keyed by a random secret generated at startup (e.g. `user-a1b2c3d4e5f60718`). The key is ephemeral and never written to disk, so tokens from two separate runs of the tool are not linkable to each other. The raw CSV is never read by anything other than your local Python process and nothing is sent over the network.

Use `--reveal` only when the output will stay on a trusted, controlled machine.

---

## Dashboard views

- **Stat cards** — total events, unique users, date range, event type count, most active user
- **Charts** — events over time (by day), events by type, events by user (top 10), platform breakdown
- **Admin highlights** — all org-level events (SSO changes, user management, policy updates, compliance settings) surfaced as a dedicated panel
- **Activity timeline** — full chronological event list with expandable detail rows
- **Per-user table** — sortable summary of activity per user
- **Raw log table** — paginated, filterable table with search by user, event type, date range, and platform

---

## Event categories

| Category | Event types |
|----------|-------------|
| auth | `user_signed_in_sso`, `user_signed_out`, `user_requested_magic_link`, `user_verified_phone_code`, `user_sent_phone_code` |
| usage | `conversation_created/deleted`, `file_uploaded`, `project_created/renamed/deleted`, `project_document_created` |
| admin | All `org_*` events |
| permissions | `role_assignment_granted`, `org_user_updated`, `org_user_invite_*` |

---

## Expected CSV format

The tool expects the CSV format exported from the claude.ai admin audit log. Columns:

```
created_at, actor_info, event, event_info, entity_info, ip_address, device_id, user_agent, client_platform
```

The `actor_info`, `event_info`, and `entity_info` columns are Python dict-formatted strings as exported by the claude.ai platform. The tool handles parsing these automatically.

---

## Disclaimer - Use of Generative AI

Generative AI was helped in the visualization of the parsed data, particularly in the stylesheets and format of the HTML webpage. It was also used to create most of this README.