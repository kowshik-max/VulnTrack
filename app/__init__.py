import os
from datetime import date, datetime, timedelta
from pathlib import Path
from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_
from dotenv import load_dotenv

load_dotenv()
db = SQLAlchemy()

SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
STATUSES = ["Open", "Triaged", "In Progress", "Fix Submitted", "Pending Verification", "Resolved", "Accepted Risk", "False Positive"]
ASSET_CRITICALITY = ["Critical", "High", "Medium", "Low"]
SEVERITY_POINTS = {"Critical": 40, "High": 30, "Medium": 20, "Low": 10, "Informational": 0}
CRITICALITY_POINTS = {"Critical": 20, "High": 15, "Medium": 8, "Low": 3}
SLA_DAYS = {"Critical": 7, "High": 30, "Medium": 60, "Low": 90, "Informational": 180}
NEXT_STATUS = {"Open": ["Triaged", "In Progress"], "Triaged": ["In Progress"], "In Progress": ["Fix Submitted"], "Fix Submitted": ["Pending Verification"]}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="analyst")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    asset_type = db.Column(db.String(40), nullable=False, default="Web application")
    environment = db.Column(db.String(30), nullable=False, default="Development")
    criticality = db.Column(db.String(20), nullable=False, default="Medium")
    owner = db.Column(db.String(80), nullable=False, default="Unassigned")
    description = db.Column(db.String(500), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class ImportRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(180), nullable=False)
    imported_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    saved_count = db.Column(db.Integer, nullable=False, default=0)
    duplicate_count = db.Column(db.Integer, nullable=False, default=0)
    invalid_count = db.Column(db.Integer, nullable=False, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    asset_id = db.Column(db.Integer, db.ForeignKey("asset.id"), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    cve = db.Column(db.String(32), nullable=False, default="")
    cvss = db.Column(db.Float, nullable=True)
    service = db.Column(db.String(100), nullable=False, default="Unknown")
    status = db.Column(db.String(30), nullable=False, default="Open")
    owner = db.Column(db.String(80), nullable=False, default="Unassigned")
    discovered_on = db.Column(db.Date, nullable=False, default=date.today)
    due_date = db.Column(db.Date, nullable=True)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    source = db.Column(db.String(180), nullable=False, default="Manual")
    recommendation = db.Column(db.Text, nullable=False, default="Not provided")
    evidence = db.Column(db.Text, nullable=False, default="Not provided")
    accepted_risk_reason = db.Column(db.Text, nullable=False, default="")
    risk_review_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    asset = db.relationship("Asset", backref=db.backref("vulnerabilities", lazy=True))

class StatusHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerability.id"), nullable=False)
    changed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    changed_by = db.Column(db.String(80), nullable=False)
    message = db.Column(db.String(500), nullable=False)

class Verification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerability.id"), nullable=False)
    verified_at = db.Column(db.Date, nullable=False, default=date.today)
    verified_by = db.Column(db.String(80), nullable=False)
    method = db.Column(db.String(160), nullable=False)
    notes = db.Column(db.Text, nullable=False)
    passed = db.Column(db.Boolean, nullable=False)


def parse_date(value):
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None


def is_closed(v):
    return v.status in ("Resolved", "Accepted Risk", "False Positive")


def priority(v, today=None):
    today = today or date.today()
    score = SEVERITY_POINTS.get(v.severity, 0)
    reasons = [f"Severity {v.severity}: +{SEVERITY_POINTS.get(v.severity, 0)}"]
    cp = CRITICALITY_POINTS.get(v.asset.criticality)
    if cp is None:
        reasons.append("Asset criticality unknown: +0 fallback")
    else:
        score += cp
        reasons.append(f"Asset criticality {v.asset.criticality}: +{cp}")
    if v.cvss is not None and v.cvss >= 9:
        score += 5; reasons.append("CVSS 9.0 or higher: +5")
    elif v.cvss is None:
        reasons.append("CVSS not provided: no CVSS points added")
    if v.confirmed:
        score += 10; reasons.append("Confirmed finding: +10")
    age = max(0, (today - v.discovered_on).days)
    if age > 30:
        score += 10; reasons.append(f"Age {age} days, over 30: +10")
    elif age > 14:
        score += 5; reasons.append(f"Age {age} days, over 14: +5")
    due = v.due_date or (v.discovered_on + timedelta(days=SLA_DAYS.get(v.severity, 90)))
    overdue = today > due and not is_closed(v)
    if overdue:
        score += 15; reasons.append(f"Overdue since {due.isoformat()}: +15")
    label = "P1" if score >= 70 else "P2" if score >= 50 else "P3" if score >= 30 else "P4"
    return {"score": score, "label": label, "reasons": reasons, "overdue": overdue, "due_date": due.isoformat()}


def log_change(v, message, username=None):
    db.session.add(StatusHistory(vulnerability_id=v.id, changed_by=username or session.get("username", "system"), message=message))


def serialize_vuln(v):
    p = priority(v)
    return {"id": v.id, "title": v.title, "description": v.description, "asset_id": v.asset_id,
            "asset_name": v.asset.name, "asset_criticality": v.asset.criticality, "severity": v.severity,
            "cve": v.cve, "cvss": v.cvss, "service": v.service, "status": v.status, "owner": v.owner,
            "discovered_on": v.discovered_on.isoformat(), "due_date": p["due_date"], "confirmed": v.confirmed,
            "source": v.source, "recommendation": v.recommendation, "evidence": v.evidence,
            "accepted_risk_reason": v.accepted_risk_reason, "risk_review_date": v.risk_review_date.isoformat() if v.risk_review_date else None,
            "priority": p, "history": [{"date": h.changed_at.isoformat(timespec="seconds"), "by": h.changed_by, "message": h.message} for h in StatusHistory.query.filter_by(vulnerability_id=v.id).order_by(StatusHistory.changed_at.desc()).all()],
            "verifications": [{"date": x.verified_at.isoformat(), "by": x.verified_by, "method": x.method, "notes": x.notes, "passed": x.passed} for x in Verification.query.filter_by(vulnerability_id=v.id).order_by(Verification.id.desc()).all()]}


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(SECRET_KEY=os.getenv("SECRET_KEY", "dev-only-change-this-secret"),
                      SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///vulntrack.db"),
                      SQLALCHEMY_TRACK_MODIFICATIONS=False,
                      MAX_CONTENT_LENGTH=1 * 1024 * 1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
    if test_config:
        app.config.update(test_config)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    db.init_app(app)

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'")
        return response

    @app.before_request
    def csrf_guard():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.endpoint not in {"login", "static"}:
            token = session.get("csrf_token")
            supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
            if not token or not supplied or token != supplied:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "CSRF token missing or invalid"}), 400
                return "CSRF token missing or invalid", 400

    @app.get("/login")
    def login_page():
        if session.get("user_id"):
            return redirect(url_for("index"))
        return render_template("login.html")

    @app.post("/login")
    def login():
        username = request.form.get("username", "").strip()[:80]
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid username or password.", "error")
            return redirect(url_for("login_page"))
        session.clear()
        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = user.role
        import secrets
        session["csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("index"))

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login_page"))

    @app.before_request
    def require_login():
        if request.endpoint in {"login_page", "login", "static", "health"}:
            return None
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login_page"))

    @app.get("/sample_data/<path:filename>")
    def sample_data(filename):
        # Only serve the small, synthetic sample files shipped with this project.
        if filename not in {"sample_findings.json", "sample_findings.csv"}:
            return "Not found", 404
        return send_from_directory(str(Path(app.root_path).parent / "sample_data"), filename, as_attachment=False)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/")
    def index():
        return render_template("index.html", username=session.get("username"), role=session.get("role"), csrf_token=session.get("csrf_token", ""))

    @app.get("/api/bootstrap")
    def bootstrap():
        return jsonify({"csrf": session.get("csrf_token"), "username": session.get("username"), "role": session.get("role"),
                        "assets": [{"id": a.id, "name": a.name, "type": a.asset_type, "environment": a.environment, "criticality": a.criticality, "owner": a.owner} for a in Asset.query.order_by(Asset.name).all()],
                        "findings": [serialize_vuln(v) for v in Vulnerability.query.order_by(Vulnerability.id.desc()).all()],
                        "imports": [{"id": i.id, "filename": i.filename, "date": i.imported_at.isoformat(timespec="seconds"), "saved": i.saved_count, "duplicates": i.duplicate_count, "invalid": i.invalid_count} for i in ImportRecord.query.order_by(ImportRecord.id.desc()).limit(20).all()]})

    @app.post("/api/assets")
    def add_asset():
        d = request.get_json(silent=True) or {}
        name = str(d.get("name", "")).strip()[:120]
        typ = str(d.get("type", "Web application"))
        env = str(d.get("environment", "Development"))
        crit = str(d.get("criticality", "Medium"))
        owner = str(d.get("owner", "Unassigned")).strip()[:80] or "Unassigned"
        if not name: return jsonify({"error": "Asset name is required"}), 400
        if Asset.query.filter(db.func.lower(Asset.name) == name.lower()).first(): return jsonify({"error": "Asset already exists"}), 409
        if typ not in {"Web application", "Server", "Internal service", "Other"} or env not in {"Production", "Staging", "Development", "Test"} or crit not in ASSET_CRITICALITY:
            return jsonify({"error": "Invalid asset type, environment, or criticality"}), 400
        a = Asset(name=name, asset_type=typ, environment=env, criticality=crit, owner=owner)
        db.session.add(a); db.session.commit()
        return jsonify({"id": a.id, "name": a.name}), 201

    @app.post("/api/findings")
    def add_finding():
        d = request.get_json(silent=True) or {}
        try:
            v = build_finding(d, d.get("source", "Manual"))
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        db.session.add(v); db.session.flush(); log_change(v, "Finding created", session.get("username")); db.session.commit()
        return jsonify(serialize_vuln(v)), 201

    def build_finding(d, source):
        title = str(d.get("title", "")).strip()[:200]
        if not title: raise ValueError("Finding title is required")
        severity = str(d.get("severity", d.get("sev", ""))).title()
        if severity not in SEVERITIES: raise ValueError("Severity must be Critical, High, Medium, Low, or Informational")
        asset_name = str(d.get("asset", d.get("asset_name", ""))).strip()
        asset = Asset.query.filter(db.func.lower(Asset.name) == asset_name.lower()).first() if asset_name else Asset.query.get(d.get("asset_id"))
        if not asset: raise ValueError("Asset does not exist; create or select a known asset")
        cvss_raw = d.get("cvss")
        if cvss_raw in (None, ""): cvss = None
        else:
            try: cvss = float(cvss_raw)
            except (TypeError, ValueError): raise ValueError("CVSS must be a number from 0 to 10")
            if not 0 <= cvss <= 10: raise ValueError("CVSS must be between 0 and 10")
        discovered = parse_date(d.get("discovered_on")) or date.today()
        due = parse_date(d.get("due_date"))
        cve = str(d.get("cve", "")).strip().upper()[:32]
        if cve and not (cve.startswith("CVE-") and len(cve) <= 32): raise ValueError("CVE identifier format should start with CVE-")
        return Vulnerability(title=title, description=str(d.get("description", ""))[:4000], asset_id=asset.id,
            severity=severity, cve=cve, cvss=cvss, service=str(d.get("service", d.get("port", "Unknown")))[:100] or "Unknown",
            status="Open", owner=str(d.get("owner", "Unassigned")).strip()[:80] or "Unassigned", discovered_on=discovered,
            due_date=due, confirmed=bool(d.get("confirmed", False)), source=str(source)[:180],
            recommendation=str(d.get("recommendation", "Not provided"))[:4000], evidence=str(d.get("evidence", d.get("description", "Not provided")))[:4000])

    @app.post("/api/import/preview")
    def import_preview():
        filename = str(request.form.get("filename", "pasted.json"))[:180]
        raw = request.form.get("content", "")
        if len(raw.encode("utf-8")) > app.config["MAX_CONTENT_LENGTH"]: return jsonify({"error": "Import exceeds 1 MB limit"}), 413
        try:
            if filename.lower().endswith(".csv"):
                import csv, io
                rows = list(csv.DictReader(io.StringIO(raw)))
            else:
                import json
                rows = json.loads(raw)
            if not isinstance(rows, list): raise ValueError("JSON import must be an array of records")
            if len(rows) > 1000: return jsonify({"error": "Maximum 1000 records per import"}), 400
        except Exception as e:
            return jsonify({"error": f"Cannot parse file: {str(e)[:200]}"}), 400
        seen = set()
        for v in Vulnerability.query.all(): seen.add(duplicate_key(v.asset_id, v.cve, v.title, v.service))
        preview = []
        for idx, row in enumerate(rows):
            if not isinstance(row, dict):
                preview.append({"index": idx + 1, "result": "Invalid", "title": "", "note": "Each record must be an object"}); continue
            title = str(row.get("title", "")).strip()
            asset_name = str(row.get("asset", row.get("asset_name", ""))).strip()
            asset = Asset.query.filter(db.func.lower(Asset.name) == asset_name.lower()).first() if asset_name else None
            sev = str(row.get("severity", row.get("sev", ""))).title()
            note = ""
            if not title: note = "Title missing"
            elif not asset: note = "Unknown asset"
            elif sev not in SEVERITIES: note = "Invalid severity"
            elif row.get("cvss") not in (None, ""):
                try:
                    if not 0 <= float(row["cvss"]) <= 10: note = "CVSS must be 0-10"
                except (ValueError, TypeError): note = "CVSS must be numeric"
            if note:
                preview.append({"index": idx + 1, "result": "Invalid", "title": title, "asset": asset_name, "severity": sev, "note": note}); continue
            cve = str(row.get("cve", "")).strip().upper()
            service = str(row.get("service", row.get("port", "Unknown")))[:100]
            key = duplicate_key(asset.id, cve, title, service)
            result = "Duplicate" if key in seen else "New"
            seen.add(key)
            preview.append({"index": idx + 1, "result": result, "title": title, "asset": asset.name, "severity": sev, "note": "Already tracked" if result == "Duplicate" else "Ready to import", "record": row if result == "New" else None})
        session["import_preview"] = {"filename": filename, "records": [x for x in preview if x["result"] == "New"]}
        return jsonify({"filename": filename, "rows": preview, "counts": {s: sum(1 for x in preview if x["result"] == s) for s in ["New", "Duplicate", "Invalid"]}})

    def duplicate_key(asset_id, cve, title, service):
        return f"{asset_id}|{(cve or title).strip().lower()}|{(service or 'Unknown').strip().lower()}"

    @app.post("/api/import/commit")
    def import_commit():
        preview = session.pop("import_preview", None)
        if not preview: return jsonify({"error": "No valid preview found. Preview the file again."}), 400
        saved = dup = bad = 0
        try:
            for row in preview["records"]:
                try:
                    v = build_finding(row, preview["filename"])
                    key = duplicate_key(v.asset_id, v.cve, v.title, v.service)
                    existing = False
                    for old in Vulnerability.query.filter_by(asset_id=v.asset_id).all():
                        if duplicate_key(old.asset_id, old.cve, old.title, old.service) == key: existing = True; break
                    if existing: dup += 1; continue
                    db.session.add(v); db.session.flush(); log_change(v, f"Imported from {preview['filename']}"); saved += 1
                except ValueError:
                    bad += 1
            db.session.add(ImportRecord(filename=preview["filename"], saved_count=saved, duplicate_count=dup, invalid_count=bad, user_id=session.get("user_id")))
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"error": "Import failed; database transaction rolled back"}), 500
        return jsonify({"saved": saved, "duplicates": dup, "invalid": bad})

    @app.patch("/api/findings/<int:vid>")
    def update_finding(vid):
        v = db.session.get(Vulnerability, vid)
        if not v: return jsonify({"error": "Finding not found"}), 404
        d = request.get_json(silent=True) or {}
        if "owner" in d:
            owner = str(d["owner"]).strip()[:80] or "Unassigned"
            if owner != v.owner: log_change(v, f"Owner changed from {v.owner} to {owner}")
            v.owner = owner
        if "due_date" in d:
            dt = parse_date(d["due_date"])
            if d["due_date"] and not dt: return jsonify({"error": "Due date must be YYYY-MM-DD"}), 400
            v.due_date = dt; log_change(v, f"Due date updated to {dt.isoformat() if dt else 'SLA default'}")
        if "confirmed" in d: v.confirmed = bool(d["confirmed"]); log_change(v, f"Confirmed set to {v.confirmed}")
        db.session.commit()
        return jsonify(serialize_vuln(v))

    @app.post("/api/findings/<int:vid>/status")
    def change_status(vid):
        v = db.session.get(Vulnerability, vid)
        if not v: return jsonify({"error": "Finding not found"}), 404
        d = request.get_json(silent=True) or {}; target = str(d.get("status", ""))
        allowed = NEXT_STATUS.get(v.status, [])
        if v.status in {"Resolved", "Accepted Risk", "False Positive"}: allowed = ["Open"]
        if target == "False Positive" and v.status in {"Open", "Triaged", "In Progress"}: allowed.append("False Positive")
        if target == "Accepted Risk" and v.status not in {"Resolved", "False Positive"}:
            reason = str(d.get("reason", "")).strip(); review = parse_date(d.get("review_date"))
            if not reason or not review: return jsonify({"error": "Accepted risk requires a reason and review date"}), 400
            v.accepted_risk_reason = reason[:2000]; v.risk_review_date = review
            allowed.append("Accepted Risk")
        if target not in allowed: return jsonify({"error": f"Invalid status transition from {v.status} to {target}"}), 400
        old = v.status; v.status = target; log_change(v, f"Status changed from {old} to {target}"); db.session.commit()
        return jsonify(serialize_vuln(v))

    @app.post("/api/findings/<int:vid>/verify")
    def verify_finding(vid):
        v = db.session.get(Vulnerability, vid)
        if not v: return jsonify({"error": "Finding not found"}), 404
        if v.status != "Pending Verification": return jsonify({"error": "Only findings Pending Verification can be verified"}), 400
        d = request.get_json(silent=True) or {}; method = str(d.get("method", "")).strip(); notes = str(d.get("notes", "")).strip(); passed = d.get("passed")
        if not method or not notes or not isinstance(passed, bool): return jsonify({"error": "Method, evidence notes, and pass/fail result are required"}), 400
        db.session.add(Verification(vulnerability_id=v.id, verified_by=session.get("username", "analyst"), method=method[:160], notes=notes[:4000], passed=passed))
        old = v.status; v.status = "Resolved" if passed else "In Progress"
        log_change(v, f"Verification {'passed' if passed else 'failed'}; status changed from {old} to {v.status}")
        db.session.commit()
        return jsonify(serialize_vuln(v))

    @app.get("/api/reports.csv")
    def report_csv():
        import csv, io
        sev = request.args.get("severity", ""); status = request.args.get("status", ""); asset_id = request.args.get("asset_id", "")
        query = Vulnerability.query
        if sev in SEVERITIES: query = query.filter_by(severity=sev)
        if status in STATUSES: query = query.filter_by(status=status)
        if asset_id.isdigit(): query = query.filter_by(asset_id=int(asset_id))
        out = io.StringIO(newline=""); writer = csv.writer(out)
        writer.writerow(["Title", "CVE", "Asset", "Severity", "CVSS", "Status", "Priority", "Owner", "Recommendation", "Due Date", "Verification"])
        for v in query.order_by(Vulnerability.id).all():
            ver = Verification.query.filter_by(vulnerability_id=v.id).order_by(Verification.id.desc()).first()
            p = priority(v)
            cells = [v.title, v.cve or "Not provided", v.asset.name, v.severity, v.cvss if v.cvss is not None else "Not provided", v.status, p["label"], v.owner, v.recommendation, p["due_date"], ("Pass" if ver.passed else "Fail") if ver else "None"]
            writer.writerow([("'" + str(c) if isinstance(c, str) and c.startswith(("=", "+", "-", "@", "\t", "\r")) else c) for c in cells])
        from flask import Response
        return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=vulntrack-report.csv"})

    @app.get("/api/dashboard")
    def dashboard():
        findings = Vulnerability.query.all(); by_sev = {s: 0 for s in SEVERITIES}; by_status = {s: 0 for s in STATUSES}
        overdue = 0
        for v in findings:
            by_sev[v.severity] = by_sev.get(v.severity, 0) + 1; by_status[v.status] = by_status.get(v.status, 0) + 1
            if priority(v)["overdue"]: overdue += 1
        resolved = sum(1 for v in findings if v.status == "Resolved")
        return jsonify({"total": len(findings), "open": sum(1 for v in findings if not is_closed(v)), "overdue": overdue,
                        "resolved": resolved, "resolution_percent": round(resolved / len(findings) * 100) if findings else 0,
                        "by_severity": by_sev, "by_status": by_status})

    @app.cli.command("seed-demo")
    def seed_demo():
        seed_data()
        print("Demo data ready. Login: analyst / DemoOnly!ChangeMe")

    with app.app_context():
        db.create_all()
        if not User.query.first():
            db.session.add(User(username="analyst", password_hash=generate_password_hash(os.getenv("DEMO_PASSWORD", "DemoOnly!ChangeMe")), role="analyst"))
            db.session.commit()
        if os.getenv("SEED_DEMO_DATA", "true").lower() == "true" and not Asset.query.first():
            seed_data()
    return app


def seed_data():
    if Asset.query.first(): return
    assets = [Asset(name="Customer Portal (demo)", asset_type="Web application", environment="Production", criticality="Critical", owner="IT Ops"),
              Asset(name="Payments API (demo)", asset_type="Internal service", environment="Production", criticality="High", owner="Platform Team"),
              Asset(name="Staging Server (demo)", asset_type="Server", environment="Staging", criticality="Medium", owner="DevOps"),
              Asset(name="Dev Wiki (demo)", asset_type="Web application", environment="Development", criticality="Low", owner="Engineering")]
    db.session.add_all(assets); db.session.flush()
    rows = [("Outdated TLS configuration", assets[0], "High", 7.4, "443/tcp", "Upgrade TLS configuration to the organization's approved baseline."),
            ("SQL injection in search (demo)", assets[0], "Critical", 9.8, "443/tcp", "Use parameterized queries and verify with an authorized retest."),
            ("Missing security headers", assets[0], "Low", None, "443/tcp", "Configure appropriate security response headers."),
            ("Weak admin password policy", assets[1], "High", None, "443/tcp", "Enforce a documented password and authentication policy."),
            ("Directory listing enabled", assets[3], "Low", 3.1, "80/tcp", "Disable directory listing where not required.")]
    for title, asset, severity, cvss, service, rec in rows:
        v = Vulnerability(title=title, asset=asset, severity=severity, cvss=cvss, service=service, status="Open", owner="Unassigned", discovered_on=date.today()-timedelta(days=10), recommendation=rec, evidence="Synthetic demonstration record; not a real scan result.", source="Synthetic demo seed")
        db.session.add(v); db.session.flush(); log_change(v, "Created from synthetic demo seed", "system")
    db.session.commit()
