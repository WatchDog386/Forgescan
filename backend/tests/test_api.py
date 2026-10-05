import pyotp

from app import runtime
from app.models import FlowWindow, User

from .conftest import ATTACKER, PASSWORD, traffic

API = "/api/v1"


def test_sign_in_needs_password_and_code(client, db):
    good_code = pyotp.TOTP(db.totp["analyst"]).now()
    assert client.post(f"{API}/auth/login", json={"email": "ann@example.com", "password": PASSWORD, "code": "000000"}).status_code == 401
    assert client.post(f"{API}/auth/login", json={"email": "ann@example.com", "password": "wrong-password", "code": good_code}).status_code == 401
    reply = client.post(f"{API}/auth/login", json={"email": "ann@example.com", "password": PASSWORD, "code": good_code})
    assert reply.status_code == 200 and reply.json()["role"] == "analyst"
    assert client.post(f"{API}/auth/refresh").status_code == 200  # the session cookie renews the token


def test_account_locks_after_five_failures(client, db):
    for _ in range(5):
        client.post(f"{API}/auth/login", json={"email": "ann@example.com", "password": "wrong-password", "code": "123456"})
    reply = client.post(f"{API}/auth/login", json={"email": "ann@example.com", "password": PASSWORD, "code": pyotp.TOTP(db.totp["analyst"]).now()})
    assert reply.status_code == 423
    db.expire_all()
    assert db.query(User).filter(User.email == "ann@example.com").one().locked_until is not None


def test_nothing_is_served_without_signing_in(client):
    for path in ("/alerts", "/incidents", "/stats/summary", "/settings", "/audit"):
        assert client.get(API + path).status_code == 401


def test_the_sensor_key_can_only_submit_records(client):
    assert client.post(f"{API}/ingest/connections", json={"records": []}).status_code == 401
    assert client.post(f"{API}/ingest/connections", json={"records": []}, headers={"X-Sensor-Key": "wrong"}).status_code == 401
    assert client.get(f"{API}/alerts", headers={"X-Sensor-Key": "test-sensor-key"}).status_code == 401


def test_roles_are_enforced(client, token, send):
    send(traffic("port_scan"))
    viewer, analyst, administrator = token("viewer"), token("analyst"), token("administrator")
    assert client.get(f"{API}/incidents", headers=viewer).status_code == 200
    assert client.patch(f"{API}/incidents/1", json={"take": True}, headers=viewer).status_code == 403
    assert client.post(f"{API}/responses/block", json={"ip": ATTACKER}, headers=viewer).status_code == 403
    assert client.get(f"{API}/settings", headers=analyst).status_code == 403
    assert client.get(f"{API}/settings", headers=administrator).status_code == 200
    assert client.patch(f"{API}/incidents/1", json={"take": True}, headers=administrator).status_code == 200


def test_an_analyst_works_an_incident_to_its_close(client, token, send):
    send(traffic("brute_force"))
    analyst = token("analyst")
    incident = client.get(f"{API}/incidents", headers=analyst).json()[0]
    assert incident["attack_type"] == "brute_force" and incident["status"] == "new"
    taken = client.patch(f"{API}/incidents/{incident['incident_id']}", json={"take": True}, headers=analyst).json()
    assert taken["status"] == "investigating" and taken["assigned_to"] is not None
    noted = client.post(f"{API}/incidents/{incident['incident_id']}/notes", json={"body": "Password guessing against SSH."}, headers=analyst)
    assert noted.status_code == 201 and len(noted.json()["notes"]) == 1
    assert client.patch(f"{API}/incidents/{incident['incident_id']}", json={"status": "resolved"}, headers=analyst).json()["status"] == "resolved"
    assert client.patch(f"{API}/incidents/{incident['incident_id']}", json={"status": "investigating"}, headers=analyst).status_code == 409


def test_a_false_positive_releases_the_block_and_labels_the_traffic_normal(client, token, send, db, firewall):
    runtime.put(db, "auto_response", True)
    db.commit()
    send(traffic("dos"))
    assert ATTACKER in firewall.blocked
    reply = client.patch(f"{API}/incidents/1", json={"status": "false_positive"}, headers=token("analyst"))
    assert reply.status_code == 200 and ATTACKER not in firewall.blocked
    db.expire_all()
    assert db.query(FlowWindow).filter(FlowWindow.label == "normal").count() > 0


def test_manual_block_and_release_respect_the_safeguards(client, token, firewall):
    analyst = token("analyst")
    assert client.post(f"{API}/responses/block", json={"ip": "8.8.8.8"}, headers=analyst).status_code == 409
    assert client.post(f"{API}/responses/block", json={"ip": "not-an-address"}, headers=analyst).status_code == 422
    assert client.post(f"{API}/responses/block", json={"ip": ATTACKER}, headers=analyst).json()["status"] == "applied"
    assert len(client.get(f"{API}/responses/active", headers=analyst).json()) == 1
    assert client.post(f"{API}/responses/release", json={"ip": ATTACKER}, headers=analyst).json()["status"] == "applied"
    assert firewall.blocked == {} and client.get(f"{API}/responses/active", headers=analyst).json() == []


def test_administrator_changes_settings_within_limits(client, token):
    administrator = token("administrator")
    assert client.put(f"{API}/settings", json={"detection_threshold": 0.9, "auto_response": True}, headers=administrator).json()["detection_threshold"] == 0.9
    assert client.put(f"{API}/settings", json={"detection_threshold": 5}, headers=administrator).status_code == 400
    assert client.put(f"{API}/settings", json={"no_such_setting": 1}, headers=administrator).status_code == 400
    assert client.post(f"{API}/allowlist", json={"ip_range": "192.168.56.1", "reason": "gateway"}, headers=administrator).status_code == 201
    assert any(entry["action"] == "settings.change" for entry in client.get(f"{API}/audit", headers=administrator).json())


def test_dashboard_gets_live_events_and_a_summary(client, token, send):
    analyst = token("analyst")
    access = analyst["Authorization"].split()[1]
    with client.websocket_connect(f"{API}/ws/events?token={access}") as live:
        send(traffic("port_scan"))
        event = live.receive_json()
    assert event["type"] == "alert" and event["attack_type"] == "port_scan" and event["source_ip"] == ATTACKER
    summary = client.get(f"{API}/stats/summary", headers=analyst).json()
    assert summary["open_incidents"] == 1 and summary["sensors"][0]["name"] == "lab"
