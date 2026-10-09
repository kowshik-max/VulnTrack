import io
import json
import pytest
from app import create_app, db, Asset, Vulnerability, User

@pytest.fixture()
def app():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite://", "SECRET_KEY": "test-secret", "WTF_CSRF_ENABLED": False})
    with app.app_context():
        db.drop_all(); db.create_all()
        from werkzeug.security import generate_password_hash
        db.session.add(User(username="analyst", password_hash=generate_password_hash("test-password"), role="analyst"))
        db.session.add(Asset(name="Test Portal", asset_type="Web application", environment="Test", criticality="High", owner="Test Owner"))
        db.session.commit()
    yield app
    with app.app_context(): db.session.remove(); db.drop_all()

@pytest.fixture()
def client(app):
    client = app.test_client()
    client.post('/login', data={"username":"analyst", "password":"test-password"}, follow_redirects=True)
    with client.session_transaction() as sess: token = sess['csrf_token']
    client.csrf_token = token
    return client

def post_json(client, url, data):
    return client.post(url, json=data, headers={"X-CSRF-Token": client.csrf_token})

def test_login_required_for_api(app):
    response = app.test_client().get('/api/bootstrap')
    assert response.status_code == 401

def test_add_finding_and_dashboard(client):
    response = post_json(client, '/api/findings', {"title":"Missing headers", "asset":"Test Portal", "severity":"Low", "cvss":"4.0"})
    assert response.status_code == 201
    assert response.json['title'] == 'Missing headers'
    dash = client.get('/api/dashboard').json
    assert dash['total'] == 1
    assert dash['by_severity']['Low'] == 1

def test_reject_invalid_cvss(client):
    response = post_json(client, '/api/findings', {"title":"Invalid score", "asset":"Test Portal", "severity":"High", "cvss":12})
    assert response.status_code == 400
    assert 'CVSS' in response.json['error']

def test_import_preview_rejects_unknown_asset(client):
    response = client.post('/api/import/preview', data={"filename":"findings.json", "content":json.dumps([{"title":"Bad asset", "asset":"Not registered", "severity":"High"}])}, headers={"X-CSRF-Token":client.csrf_token})
    assert response.status_code == 200
    assert response.json['counts']['Invalid'] == 1

def test_verification_gate(client):
    r = post_json(client, '/api/findings', {"title":"Weak TLS", "asset":"Test Portal", "severity":"High"})
    vid = r.json['id']
    # Cannot verify until it reaches Pending Verification.
    denied = post_json(client, f'/api/findings/{vid}/verify', {"method":"retest", "notes":"checked", "passed":True})
    assert denied.status_code == 400
    for status in ['Triaged', 'In Progress', 'Fix Submitted', 'Pending Verification']:
        r = post_json(client, f'/api/findings/{vid}/status', {"status":status})
        assert r.status_code == 200
    verified = post_json(client, f'/api/findings/{vid}/verify', {"method":"authorized retest", "notes":"Synthetic test passed", "passed":True})
    assert verified.status_code == 200
    assert verified.json['status'] == 'Resolved'
    assert verified.json['verifications'][0]['passed'] is True

def test_invalid_status_transition_is_rejected(client):
    r = post_json(client, '/api/findings', {"title":"Weak TLS", "asset":"Test Portal", "severity":"High"})
    response = post_json(client, f"/api/findings/{r.json['id']}/status", {"status":"Resolved"})
    assert response.status_code == 400

def test_csv_report_download(client):
    post_json(client, '/api/findings', {"title":"=HYPERLINK(\"https://example.invalid\")", "asset":"Test Portal", "severity":"Low"})
    response = client.get('/api/reports.csv')
    assert response.status_code == 200
    assert response.mimetype == 'text/csv'
    assert "'=HYPERLINK" in response.get_data(as_text=True)
