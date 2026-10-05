"""Turns connection records into one feature window per source address (SDS 6.2).

The extractor keeps the last 60 seconds of records for each source and produces a
window every 10 seconds. It runs on the time inside the records, not the clock, so
live traffic and a replayed capture are handled the same way.
"""
from collections import Counter, defaultdict, deque
from dataclasses import dataclass

FEATURES = [
    "connection_count", "unique_destinations", "unique_ports", "failed_ratio", "syn_only_count", "mean_duration",
    "bytes_sent", "bytes_received", "mean_bytes", "max_per_port", "ssh_count", "ftp_count", "http_count",
    "tcp_share", "udp_share", "icmp_share", "mean_gap",
]
FAILED_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"}  # Zeek states for connections that never completed
SERVICE_PORTS = {"ssh": {22}, "ftp": {21}, "http": {80, 443, 8080}}


@dataclass(slots=True)
class ConnRecord:
    ts: float
    src: str
    dst: str
    dport: int
    proto: str
    service: str
    duration: float
    orig_bytes: int
    resp_bytes: int
    state: str

    @classmethod
    def from_zeek(cls, r: dict) -> "ConnRecord":
        """Read one line of Zeek's conn.log in JSON form. Missing values are treated as zero."""
        return cls(
            ts=float(r["ts"]), src=str(r["id.orig_h"]), dst=str(r["id.resp_h"]), dport=int(r.get("id.resp_p") or 0),
            proto=str(r.get("proto") or "tcp"), service=str(r.get("service") or ""), duration=float(r.get("duration") or 0.0),
            orig_bytes=int(r.get("orig_bytes") or 0), resp_bytes=int(r.get("resp_bytes") or 0), state=str(r.get("conn_state") or ""),
        )


@dataclass
class FeatureWindow:
    source_ip: str
    window_end: float
    window_seconds: int
    features: dict[str, float]
    target_ip: str | None

    def vector(self) -> list[float]:
        return [self.features[name] for name in FEATURES]


def compute(records: list[ConnRecord]) -> tuple[dict[str, float], str | None]:
    n = len(records)
    ports, dests = Counter(r.dport for r in records), Counter(r.dst for r in records)
    times = sorted(r.ts for r in records)
    gaps = [b - a for a, b in zip(times, times[1:])]
    sent, received = sum(r.orig_bytes for r in records), sum(r.resp_bytes for r in records)

    def service(name: str) -> int:
        return sum(1 for r in records if r.service == name or (not r.service and r.dport in SERVICE_PORTS[name]))

    features = {
        "connection_count": n,
        "unique_destinations": len(dests),
        "unique_ports": len(ports),
        "failed_ratio": sum(1 for r in records if r.state in FAILED_STATES) / n,
        "syn_only_count": sum(1 for r in records if r.state == "S0"),
        "mean_duration": sum(r.duration for r in records) / n,
        "bytes_sent": sent,
        "bytes_received": received,
        "mean_bytes": (sent + received) / n,
        "max_per_port": max(ports.values()),
        "ssh_count": service("ssh"),
        "ftp_count": service("ftp"),
        "http_count": service("http"),
        "tcp_share": sum(1 for r in records if r.proto == "tcp") / n,
        "udp_share": sum(1 for r in records if r.proto == "udp") / n,
        "icmp_share": sum(1 for r in records if r.proto == "icmp") / n,
        "mean_gap": sum(gaps) / len(gaps) if gaps else float(0),
    }
    return {k: round(float(v), 4) for k, v in features.items()}, dests.most_common(1)[0][0]


class FeatureExtractor:
    def __init__(self, window_seconds: int = 60, step_seconds: int = 10, min_connections: int = 5) -> None:
        self.window_seconds, self.step_seconds, self.min_connections = window_seconds, step_seconds, min_connections
        self.records: dict[str, deque[ConnRecord]] = defaultdict(deque)
        self.next_eval: float | None = None
        self.latest = 0.0

    def add(self, records: list[ConnRecord]) -> list[FeatureWindow]:
        """Add records and return the windows that have closed since the last call."""
        for record in records:
            self.records[record.src].append(record)
            self.latest = max(self.latest, record.ts)
        if not records:
            return []
        if self.next_eval is None:
            self.next_eval = min(r.ts for r in records) + self.step_seconds
        # After a long silence there is nothing to gain from evaluating every empty step.
        if self.latest - self.next_eval > self.window_seconds:
            self.next_eval = self.latest - self.window_seconds
        windows: list[FeatureWindow] = []
        while self.next_eval <= self.latest:
            windows.extend(self._close(self.next_eval))
            self.next_eval += self.step_seconds
        return windows

    def _close(self, end: float) -> list[FeatureWindow]:
        start, windows = end - self.window_seconds, []
        for source in list(self.records):
            queue = self.records[source]
            while queue and queue[0].ts <= start:
                queue.popleft()
            if not queue:
                del self.records[source]
                continue
            inside = [r for r in queue if r.ts <= end]
            if len(inside) >= self.min_connections:  # too little traffic says nothing either way
                features, target = compute(inside)
                windows.append(FeatureWindow(source, end, self.window_seconds, features, target))
        return windows
