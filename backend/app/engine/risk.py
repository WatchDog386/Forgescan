"""Risk score from 0 to 100 and its severity (SDS 6.5)."""
SEVERITY_ORDER = ["low", "medium", "high", "critical"]
ATTACK_WEIGHT = {"dos": 0.9, "brute_force": 0.8, "port_scan": 0.5, "anomaly": 0.3}


def severity_for(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    return "medium" if score >= 25 else "low"


def score(confidence: float, attack_type: str, hosts_targeted: int, earlier_incidents: int, weights: dict) -> int:
    spread = min(hosts_targeted / 5, 1.0)
    repeat = min(earlier_incidents / 3, 1.0)
    value = (weights["weight_confidence"] * confidence + weights["weight_attack"] * ATTACK_WEIGHT.get(attack_type, 0.3)
             + weights["weight_spread"] * spread + weights["weight_repeat"] * repeat)
    total = sum(weights[k] for k in ("weight_confidence", "weight_attack", "weight_spread", "weight_repeat")) or 1.0
    return max(0, min(100, round(100 * value / total)))
