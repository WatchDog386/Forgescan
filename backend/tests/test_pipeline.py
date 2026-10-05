from app import runtime
from app.models import Alert, AllowlistEntry, FlowWindow, Incident, Response

from .conftest import ATTACKER, traffic


def test_normal_traffic_raises_no_alert(send, db):
    result = send(traffic("normal", seconds=90))
    assert result["windows"] > 0 and result["alerts"] == 0
    assert db.query(FlowWindow).count() == result["windows"]


def test_each_attack_is_detected_and_named(send, db):
    for number, kind in enumerate(("port_scan", "brute_force", "dos")):
        source = f"192.168.56.{40 + number}"
        send(traffic(kind, source=source, start=2_000_000.0 + 200 * number))   # one attack after another
        named = {a.attack_type for a in db.query(Alert).filter(Alert.source_ip == source)} - {"anomaly"}
        assert named == {kind}
        assert [i.attack_type for i in db.query(Incident).filter(Incident.source_ip == source)] == [kind]   # one incident, correctly named


def test_alerts_from_one_attack_join_one_incident(send, db):
    send(traffic("port_scan"))
    assert db.query(Alert).count() > 1 and db.query(Incident).count() == 1
    incident = db.query(Incident).one()
    assert incident.source_ip == ATTACKER and incident.status == "new" and incident.risk_score == max(a.risk_score for a in incident.alerts)


def test_critical_attack_is_only_recorded_while_automatic_response_is_off(send, db, firewall):
    send(traffic("dos"))
    responses = db.query(Response).all()
    assert [r.status for r in responses] == ["dry_run"] and firewall.blocked == {}


def test_critical_attack_is_blocked_once_when_automatic_response_is_on(send, db, firewall):
    runtime.put(db, "auto_response", True)
    db.commit()
    send(traffic("dos"))
    assert firewall.blocked == {ATTACKER: 30}
    assert [r.status for r in db.query(Response).all()] == ["applied"]   # one block for the incident, not one per alert


def test_a_trusted_address_is_never_blocked(send, db, firewall):
    runtime.put(db, "auto_response", True)
    db.add(AllowlistEntry(ip_range="192.168.56.10/32", reason="administrator workstation"))
    db.commit()
    send(traffic("dos"))
    assert firewall.blocked == {} and db.query(Alert).count() > 0
    assert db.query(Response).one().detail == "on the allowlist"


def test_an_address_outside_the_monitored_network_is_never_blocked(send, db, firewall):
    runtime.put(db, "auto_response", True)
    db.commit()
    send(traffic("dos", source="203.0.113.9"))
    assert firewall.blocked == {} and db.query(Response).one().detail == "outside the monitored network"


def test_automatic_blocking_stops_at_the_limit(send, db, firewall):
    runtime.put(db, "auto_response", True)
    runtime.put(db, "max_active_blocks", 1)
    db.commit()
    send(traffic("dos", source="192.168.56.31"))
    send(traffic("dos", source="192.168.56.32", start=2_000_100.0))
    assert list(firewall.blocked) == ["192.168.56.31"]
    assert db.query(Response).filter(Response.target_ip == "192.168.56.32").one().detail == "limit on active blocks reached"


def test_a_failed_firewall_is_reported_and_nothing_is_assumed(send, db, firewall):
    runtime.put(db, "auto_response", True)
    db.commit()
    firewall.fail = True
    send(traffic("dos"))
    assert db.query(Response).one().status == "failed"


def test_unreadable_records_are_skipped(send):
    result = send([{"nonsense": True}] + traffic("normal", seconds=30))
    assert result["skipped"] == 1 and result["received"] > 0
