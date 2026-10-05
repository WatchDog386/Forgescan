"""Log collector: follows Zeek's conn.log (JSON) and sends new records to the backend.

    python sensor/collector.py --log /opt/zeek/logs/current/conn.log --url http://127.0.0.1:8000 --key <sensor key>

Records are sent in batches every few seconds. If the backend cannot be reached the
batch is kept and sent again, up to a limit, so a short outage loses nothing.
"""
import argparse
import json
import time
from pathlib import Path

import httpx

MAX_HELD = 50000


def follow(path: Path):
    """Yield new lines as Zeek writes them, and start again from the top when the log is rotated."""
    position, inode = 0, None
    while True:
        try:
            stat = path.stat()
        except FileNotFoundError:
            yield None
            continue
        if inode != stat.st_ino or stat.st_size < position:
            position, inode = 0, stat.st_ino
        with path.open() as handle:
            handle.seek(position)
            for line in handle:
                if line.endswith("\n"):
                    yield line
                    position += len(line.encode())
        yield None  # nothing new for now


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--key", required=True, help="the sensor key from: python -m app.cli create-sensor")
    parser.add_argument("--every", type=float, default=3.0, help="seconds between batches")
    args = parser.parse_args()

    held: list[dict] = []
    last_sent = time.monotonic()
    with httpx.Client(timeout=10) as client:
        for line in follow(args.log):
            if line is not None:
                try:
                    held.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # a half-written or non-JSON line
                continue
            if held and time.monotonic() - last_sent >= args.every:
                try:
                    reply = client.post(f"{args.url}/api/v1/ingest/connections", json={"records": held[:20000]}, headers={"X-Sensor-Key": args.key})
                    reply.raise_for_status()
                    print(f"sent {len(held[:20000])} records: {reply.json()}")
                    del held[:20000]
                except httpx.HTTPError as error:
                    print(f"backend not reachable, holding {len(held)} records: {error}")
                    del held[:-MAX_HELD]
                last_sent = time.monotonic()
            time.sleep(0.5)


if __name__ == "__main__":
    main()
