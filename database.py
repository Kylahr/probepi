"""SQLite storage for probe requests, fingerprints, and device groups."""
import sqlite3
import time
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path(__file__).parent / "probes.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS probes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    mac         TEXT NOT NULL,
    mac_random  INTEGER NOT NULL,
    ssid        TEXT,
    rssi        INTEGER,
    channel     INTEGER,
    seq         INTEGER,
    fingerprint TEXT NOT NULL,
    ies_raw     BLOB
);
CREATE INDEX IF NOT EXISTS idx_probes_mac  ON probes(mac);
CREATE INDEX IF NOT EXISTS idx_probes_ssid ON probes(ssid);
CREATE INDEX IF NOT EXISTS idx_probes_fp   ON probes(fingerprint);
CREATE INDEX IF NOT EXISTS idx_probes_ts   ON probes(ts);

CREATE TABLE IF NOT EXISTS devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint  TEXT UNIQUE NOT NULL,
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    probe_count  INTEGER NOT NULL DEFAULT 0,
    mac_sample   TEXT,
    group_id     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_devices_group ON devices(group_id);

CREATE TABLE IF NOT EXISTS groups (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    label        TEXT,
    confidence   REAL NOT NULL DEFAULT 0,
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL
);
"""


@contextmanager
def connect(db_path=DB_PATH):
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path=DB_PATH):
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


def insert_probe(conn, probe):
    conn.execute(
        """INSERT INTO probes
           (ts, mac, mac_random, ssid, rssi, channel, seq, fingerprint, ies_raw)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            probe["ts"],
            probe["mac"],
            int(probe["mac_random"]),
            probe["ssid"],
            probe["rssi"],
            probe["channel"],
            probe["seq"],
            probe["fingerprint"],
            probe["ies_raw"],
        ),
    )
    conn.execute(
        """INSERT INTO devices (fingerprint, first_seen, last_seen, probe_count, mac_sample)
           VALUES (?, ?, ?, 1, ?)
           ON CONFLICT(fingerprint) DO UPDATE SET
             last_seen = excluded.last_seen,
             probe_count = probe_count + 1""",
        (probe["fingerprint"], probe["ts"], probe["ts"], probe["mac"]),
    )


def stats(conn):
    row = conn.execute(
        """SELECT
             (SELECT COUNT(*) FROM probes)                AS probes,
             (SELECT COUNT(DISTINCT mac) FROM probes)     AS macs,
             (SELECT COUNT(*) FROM devices)               AS devices,
             (SELECT COUNT(DISTINCT group_id) FROM devices WHERE group_id IS NOT NULL) AS groups,
             (SELECT COUNT(DISTINCT ssid) FROM probes WHERE ssid != '') AS ssids
        """
    ).fetchone()
    return dict(row)


def recent_ssids(conn, limit=5):
    rows = conn.execute(
        """SELECT ssid, MAX(ts) AS last_ts, COUNT(*) AS n
           FROM probes
           WHERE ssid IS NOT NULL AND ssid != ''
           GROUP BY ssid
           ORDER BY last_ts DESC
           LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    init_db()
    with connect() as c:
        print(stats(c))
