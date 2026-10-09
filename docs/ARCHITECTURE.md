# VulnTrack architecture

## Request flow

Browser UI (HTML/CSS/JavaScript) -> Flask routes / JSON API -> SQLAlchemy models -> SQLite local database or MySQL via PyMySQL.

## Data model

- `User`: hashed password, username, role.
- `Asset`: name, type, environment, criticality, owner.
- `Vulnerability`: finding details, severity, optional CVE/CVSS, status, remediation owner, dates, evidence and recommendation.
- `ImportRecord`: filename, timestamp and saved/duplicate/invalid counts.
- `StatusHistory`: timestamped workflow and assignment events.
- `Verification`: verification method, evidence, outcome, reviewer and date.

## Security boundaries

- All mutating API calls require a session-bound CSRF token.
- API routes require an authenticated session.
- Passwords are hashed with Werkzeug's password hashing utilities.
- Upload/import body size and row counts are limited.
- XML is not accepted, avoiding unsafe XML parsing in the current version.
- CSV export neutralizes cells beginning with formula-triggering characters.
- The application does not perform network scans.

## Known limitations

This is a learning/portfolio application. It has basic login and role labels, but does not yet enforce granular role permissions. It has no MFA, password reset, rate limiting, email service, PDF report, scanner-specific Nmap/Nessus parser, production migrations, or deployment hardening. The custom priority score is a heuristic and must not be represented as CVSS.
