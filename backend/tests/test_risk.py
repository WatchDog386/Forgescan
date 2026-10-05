from app import runtime
from app.engine import risk

W = runtime.DEFAULTS


def test_severity_bands():
    assert [risk.severity_for(s) for s in (0, 24, 25, 49, 50, 74, 75, 100)] == ["low", "low", "medium", "medium", "high", "high", "critical", "critical"]


def test_score_follows_the_design_formula():
    # 0.50 * 0.97 + 0.35 * 0.8 + 0.075 * (1 / 5) + 0.075 * 0 = 0.78
    assert risk.score(0.97, "brute_force", 1, 0, W) == 78


def test_repeat_offenders_and_wide_attacks_score_higher():
    once = risk.score(0.9, "port_scan", 1, 0, W)
    assert risk.score(0.9, "port_scan", 5, 0, W) > once
    assert risk.score(0.9, "port_scan", 1, 3, W) > once
    assert risk.score(1.0, "dos", 9, 9, W) in (96, 97)   # 0.50 + 0.315 + 0.075 + 0.075 = 0.965


def test_a_first_scan_is_high_and_a_first_flood_is_critical():
    assert risk.severity_for(risk.score(0.98, "port_scan", 1, 0, W)) == "high"
    assert risk.severity_for(risk.score(0.95, "dos", 1, 0, W)) == "critical"
