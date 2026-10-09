# VulnTrack — Vulnerability Management and Remediation

VulnTrack extends the original browser prototype into a Flask-backed application with database persistence, authentication, assets, imports, prioritization, remediation workflow, verification records, audit history, dashboard metrics, and CSV reporting.

## Current implementation

- Flask application and JSON API
- SQLAlchemy persistence; SQLite is the quick-start default, MySQL is supported through `DATABASE_URL`
- Login with password hashing and session cookies
- CSRF token checks for state-changing API requests
- Assets with environment and criticality
- Manual finding creation and JSON/CSV import preview/commit
- Duplicate detection and invalid-record handling
- Transparent remediation-priority heuristic (not official CVSS)
- Status-transition validation and verification gate before resolution
- Accepted-risk reason and review date
- Audit history and verification history
- Database-backed dashboard metrics and filtered CSV report
- Basic security headers, upload limit, CSV formula-injection mitigation
- pytest tests for core workflows

## Quick start on Windows PowerShell

Install Python 3.11 or newer. Open PowerShell in this folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
python run.py
```

Open `http://127.0.0.1:5000`.

Demo login (local demo only):
- Username: `analyst`
- Password: `DemoOnly!ChangeMe`

Change the demo password and `SECRET_KEY` before using real records. The demo database contains synthetic findings. Do not import production scan data into a publicly exposed development server.

## Database

The default configuration uses SQLite, which is easiest for local setup. To use MySQL:

1. Create a database and a dedicated database user in MySQL.
2. Copy `.env.example` to `.env` and set `DATABASE_URL` to a URL such as:

```text
mysql+pymysql://vulntrack_user:URL_ENCODED_PASSWORD@127.0.0.1:3306/vulntrack?charset=utf8mb4
```

3. Install dependencies and start the app. Tables are created on startup for this learning project. For a production system, use reviewed schema migrations and a managed secret store.

Do not commit `.env` or real credentials to GitHub. URL-encode special characters in database passwords.

## Run tests

```powershell
pytest -q
```

Tests use an isolated in-memory SQLite database and synthetic records. The test suite is provided in `tests/test_app.py`; run it locally and report the actual result rather than claiming it passed without execution.

## Supported import formats

- JSON: an array of objects with `title`, `asset`, `severity`; optional `cve`, `cvss`, `service`/`port`, `description`/`evidence`, `recommendation`, `owner`, `confirmed`.
- CSV: same fields in a header row.
- Maximum import request size: 1 MB; maximum 1,000 rows per import.
- Asset names must match an asset already registered in VulnTrack.

Nmap XML, Nessus CSV, PDF reports, email delivery, MFA, password reset, fine-grained role permissions, and automated live scanning are **not implemented**. Nmap port/service output should not be presented as a confirmed vulnerability by itself.

## Priority calculation

The app calculates a custom remediation-priority score from severity, asset criticality, a supplied CVSS score of 9.0 or higher, confirmation state, finding age, and overdue status. Thresholds are P1 >= 70, P2 >= 50, P3 >= 30, otherwise P4. Severity is kept separate from priority. This is an explainable portfolio heuristic, **not** an official CVSS calculation or an authoritative risk rating.

Default remediation target days: Critical 7, High 30, Medium 60, Low 90, Informational 180. A user-supplied due date overrides the default SLA date.

## Workflow

`Open -> Triaged -> In Progress -> Fix Submitted -> Pending Verification -> Resolved (only after verification passes)`

A failed verification returns the finding to `In Progress`. Accepted Risk requires a reason and review date. Resolved, accepted-risk, and false-positive findings can be reopened.

## Security and limitations

- This application manages scan results; it does not automatically scan targets.
- Use only assets and findings you are authorized to assess.
- The built-in demo credentials are public by design and must not be used for a real deployment.
- The Flask development server is bound to `127.0.0.1` and must not be exposed directly to the internet.
- The current user/role model is a learning baseline. Fine-grained authorization, password-reset controls, rate limiting, comprehensive security testing, production deployment hardening, and database migrations remain future work.
- The app is a student portfolio project, not a certified vulnerability management product.

## Project layout

```text
app/
  __init__.py             Flask routes, models, workflows, API
  templates/              Login and application shell
  static/                 Responsive UI and frontend API client
  vulntrack-prototype.html Original browser-only prototype (reference)
sample_data/               Synthetic JSON and CSV imports
tests/                     Automated workflow tests
docs/                      Architecture notes
run.py                      Local development entry point
requirements.txt            Python dependencies
.env.example                 Environment configuration template
```

## Resume description (only after you run and verify it)

**VulnTrack — Vulnerability Management and Remediation Platform** — Built a Flask and SQLAlchemy application with SQLite/MySQL configuration, JSON/CSV scan-result import preview, duplicate validation, explainable risk prioritization, remediation status transitions, verification history, audit logging, and database-backed CSV reporting. Added automated tests for core API workflows.
