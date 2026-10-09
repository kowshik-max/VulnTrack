# Implementation status (honest checklist)

## Implemented in this codebase
- [x] Flask app factory and local run entry point
- [x] SQLite default persistence and MySQL URL configuration through SQLAlchemy/PyMySQL
- [x] Login with hashed password and session-based authentication
- [x] CSRF token checks on mutating requests
- [x] Basic security response headers and request-size cap
- [x] Asset creation and uniqueness checks
- [x] Manual finding creation
- [x] JSON/CSV import preview, validation, duplicate check, and commit
- [x] Severity/CVSS validation and transparent custom prioritization
- [x] Remediation status transition validation
- [x] Accepted-risk reason and review date fields
- [x] Verification pass/fail gate and audit history
- [x] Dashboard metrics calculated from database data
- [x] Filtered CSV report with spreadsheet formula-injection mitigation
- [x] Synthetic seed data and test source files
- [x] pytest test cases written for core API flows

## Not yet implemented or not yet verified
- [ ] Nmap XML import (host/service inventory must not be mislabelled as vulnerabilities)
- [ ] Nessus-specific CSV parser
- [ ] PDF reports
- [ ] Email notifications
- [ ] MFA and password reset
- [ ] Fine-grained authorization enforcement for administrator vs analyst
- [ ] Password rate limiting / lockout
- [ ] Production-grade database migrations
- [ ] Full browser end-to-end testing
- [ ] Dependency installation and pytest execution in this generation environment (network access was unavailable)
- [ ] Production deployment hardening and external security review

Do not mark unchecked items complete on a resume or in a demo.
