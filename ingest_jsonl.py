"""Ingest a JSON-lines probe log (from the Heltec firmware) into probes.db.

Usage:
    python ingest_jsonl.py probes.log
    python ingest_jsonl.py probes.log --db ./probes.db

The Heltec firmware outputs one JSON object per probe request over USB
serial. Point Android's "Serial USB Terminal" at a log file, walk around,
then copy the file to this machine and run this script. Clustering runs
automatically after ingest.
"""
import argparse
import json
import sys
import time
from pathlib import Path

import database
import fingerprint


def _ts_from_boot_ms(boot_ms, wall_offset):
    return wall_offset + (boot_ms / 1000.0)


def ingest(path, db_path=None):
    db_path = Path(db_path) if db_path else database.DB_PATH
    database.init_db(db_path)

    # We anchor the firmware's millis() timeline to the *first* line's
    # wall-clock — ingest time. Absolute times will be off by the
    # capture-to-ingest gap, but relative ordering is exact.
    wall_offset = None
    total = 0
    skipped = 0

    with database.connect(db_path) as conn, open(path, "r", encoding="utf-8",
                                                 errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            try:
                if wall_offset is None:
                    wall_offset = time.time() - (o["t"] / 1000.0)

                probe = {
                    "ts": _ts_from_boot_ms(o["t"], wall_offset),
                    "mac": str(o["mac"]).lower(),
                    "mac_random": bool(o.get("rand", 0)),
                    "ssid": o.get("ssid", "") or "",
                    "rssi": int(o.get("rssi", 0)),
                    "channel": int(o.get("ch", 0)),
                    "seq": int(o.get("seq", 0)),
                    "fingerprint": str(o.get("fp", ""))[:16],
                    "ies_raw": None,
                }
                database.insert_probe(conn, probe)
                total += 1
            except (KeyError, ValueError, TypeError):
                skipped += 1
                continue

        print(f"[ingest] inserted {total} probes, skipped {skipped} lines")
        groups = fingerprint.group_devices(conn)
        stats = database.stats(conn)
        print(f"[ingest] stats: {stats}")
        print(f"[ingest] grouped into {groups} person-clusters")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log", help="path to JSON-lines capture file")
    ap.add_argument("--db", default=None, help="sqlite db path")
    args = ap.parse_args()

    if not Path(args.log).exists():
        print(f"error: {args.log} not found", file=sys.stderr)
        sys.exit(1)

    ingest(args.log, args.db)


if __name__ == "__main__":
    main()
