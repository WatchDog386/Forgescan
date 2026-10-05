"""Sends SIMULATED traffic to a running backend, to try the system before the laboratory exists.

    python sensor/simulate_traffic.py --key <sensor key> --attack port_scan
    python sensor/simulate_traffic.py --key <sensor key> --attack normal --seconds 120

Run it from the repository root. The records carry the current time, as live traffic would.
"""
import argparse
import random
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.engine import simulate  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--key", required=True)
    parser.add_argument("--attack", choices=list(simulate.GENERATORS), default="port_scan")
    parser.add_argument("--source", default="192.168.56.10")
    parser.add_argument("--target", default="192.168.56.20")
    parser.add_argument("--seconds", type=float, default=45)
    args = parser.parse_args()

    records = simulate.GENERATORS[args.attack](args.source, args.target, time.time() - args.seconds, args.seconds, random.Random())
    reply = httpx.post(f"{args.url}/api/v1/ingest/connections", json={"records": records}, headers={"X-Sensor-Key": args.key}, timeout=30)
    reply.raise_for_status()
    print(f"Sent {len(records)} simulated {args.attack} records from {args.source}: {reply.json()}")


if __name__ == "__main__":
    main()
