"""Generates Zeek-style connection records for normal traffic and three attack types.

SIMULATED DATA. It exists so the pipeline can be run and tested before the
laboratory and the CIC-IDS2017 captures are ready. Results on it say nothing
about how well the system detects real attacks.
"""
import random

SERVERS = ["192.168.56.20", "192.168.56.21", "192.168.56.22"]


def _record(ts, src, dst, dport, state="SF", proto="tcp", service="", duration=0.0, sent=0, received=0) -> dict:
    return {"ts": round(ts, 4), "id.orig_h": src, "id.resp_h": dst, "id.resp_p": dport, "proto": proto, "service": service,
            "duration": round(duration, 4), "orig_bytes": int(sent), "resp_bytes": int(received), "conn_state": state}


def normal(src: str, start: float, seconds: float, rng: random.Random) -> list[dict]:
    """Ordinary use: a few web, DNS and occasional SSH connections that complete."""
    out, t = [], start
    rate = rng.uniform(0.15, 1.2)
    while t < start + seconds:
        kind = rng.random()
        if kind < 0.25:
            out.append(_record(t, src, rng.choice(SERVERS), 53, proto="udp", service="dns", duration=rng.uniform(0.001, 0.05), sent=rng.randint(40, 90), received=rng.randint(80, 300)))
        elif kind < 0.93:
            out.append(_record(t, src, rng.choice(SERVERS), rng.choice([80, 443]), service="http", duration=rng.expovariate(1 / 4), sent=rng.randint(300, 4000), received=rng.randint(1000, 120000)))
        elif kind < 0.97:
            out.append(_record(t, src, SERVERS[0], 22, service="ssh", duration=rng.uniform(5, 300), sent=rng.randint(2000, 30000), received=rng.randint(2000, 60000)))
        else:
            out.append(_record(t, src, rng.choice(SERVERS), rng.choice([80, 443]), state="REJ"))
        t += rng.expovariate(rate)
    return out


def port_scan(src: str, dst: str, start: float, seconds: float, rng: random.Random) -> list[dict]:
    """Many ports on one host, almost all refused or unanswered."""
    out, t = [], start
    rate, port = rng.uniform(5, 40), rng.randint(1, 200)
    while t < start + seconds:
        open_port = rng.random() < 0.03
        out.append(_record(t, src, dst, port, state="SF" if open_port else rng.choice(["S0", "REJ", "REJ"]), duration=0.001 if open_port else 0))
        port = port + 1 if rng.random() < 0.8 else rng.randint(1, 65535)
        t += rng.expovariate(rate)
    return out


def brute_force(src: str, dst: str, start: float, seconds: float, rng: random.Random) -> list[dict]:
    """Repeated logins to one service. The connections complete; the passwords fail."""
    out, t = [], start
    service, port = rng.choice([("ssh", 22), ("ssh", 22), ("ftp", 21)])
    rate = rng.uniform(1, 6)
    while t < start + seconds:
        out.append(_record(t, src, dst, port, state=rng.choice(["SF", "SF", "SF", "RSTO"]), service=service,
                           duration=rng.uniform(0.8, 3.5), sent=rng.randint(900, 2600), received=rng.randint(1500, 4200)))
        t += rng.expovariate(rate)
    return out


def dos(src: str, dst: str, start: float, seconds: float, rng: random.Random) -> list[dict]:
    """A flood of connections to one service, either half-open or tiny requests."""
    out, t = [], start
    rate, syn_flood = rng.uniform(30, 120), rng.random() < 0.5
    while t < start + seconds:
        if syn_flood:
            out.append(_record(t, src, dst, 80, state="S0"))
        else:
            out.append(_record(t, src, dst, 80, state=rng.choice(["SF", "SF", "RSTO"]), service="http", duration=rng.uniform(0.001, 0.2), sent=rng.randint(60, 400), received=rng.randint(0, 600)))
        t += rng.expovariate(rate)
    return out


GENERATORS = {"normal": lambda s, d, t, n, r: normal(s, t, n, r), "port_scan": port_scan, "brute_force": brute_force, "dos": dos}
