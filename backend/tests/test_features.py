from app.engine.features import ConnRecord, FeatureExtractor

from .conftest import traffic


def _last_window(kind: str):
    return FeatureExtractor().add([ConnRecord.from_zeek(r) for r in traffic(kind)])[-1]


def test_a_port_scan_touches_many_ports_and_mostly_fails():
    f = _last_window("port_scan").features
    assert f["unique_ports"] > 50 and f["failed_ratio"] > 0.8 and f["unique_destinations"] == 1


def test_brute_force_hits_one_login_service_again_and_again():
    f = _last_window("brute_force").features
    assert f["unique_ports"] == 1 and f["ssh_count"] + f["ftp_count"] == f["connection_count"] and f["failed_ratio"] < 0.2


def test_windows_follow_the_time_in_the_records_and_old_records_drop_out():
    extractor = FeatureExtractor()
    first = extractor.add([ConnRecord.from_zeek(r) for r in traffic("dos", seconds=20)])
    assert len(first) == 1                                    # one window per 10-second step
    later = extractor.add([ConnRecord.from_zeek(r) for r in traffic("normal", source="192.168.56.77", start=2_000_300.0, seconds=30)])
    assert all(w.source_ip == "192.168.56.77" for w in later)  # the flood is more than 60 seconds old


def test_a_source_with_almost_no_traffic_is_not_judged():
    records = [ConnRecord.from_zeek(r) for r in traffic("normal", seconds=40)][:3]
    records.append(ConnRecord(records[-1].ts + 15, "192.168.56.99", "192.168.56.20", 80, "tcp", "http", 1, 10, 10, "SF"))
    assert FeatureExtractor().add(records) == []
