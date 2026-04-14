"""Device fingerprinting and grouping.

Goal: given a history of probe requests, cluster them into likely real
devices (undoing MAC randomization) and then group devices that probably
belong to the same person based on shared SSID preferences.

Two stages:
  1. device clustering — uses the IE fingerprint stored in the `devices`
     table. Rows already share a fingerprint, so this is effectively
     "one fingerprint = one device". Randomized MACs that share a
     fingerprint collapse into the same device.
  2. person grouping — two devices are likely the same person if their
     SSID probe sets overlap meaningfully (Jaccard similarity above
     threshold). This is the "link SSIDs to a person" step.

Both stages produce confidence scores so you can filter later.
"""
from collections import defaultdict
from itertools import combinations
import time


def _jaccard(a, b):
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def _device_ssids(conn):
    """Return {device_id: set(ssids)} for all devices."""
    rows = conn.execute(
        """SELECT d.id AS did, p.ssid
           FROM devices d
           JOIN probes p ON p.fingerprint = d.fingerprint
           WHERE p.ssid IS NOT NULL AND p.ssid != ''"""
    ).fetchall()
    out = defaultdict(set)
    for r in rows:
        out[r["did"]].add(r["ssid"])
    return out


def _union_find(n):
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    return find, union, parent


def group_devices(conn, threshold=0.35, min_shared=2):
    """Cluster devices into 'people' based on SSID-set similarity.

    threshold:   minimum Jaccard similarity to link two devices
    min_shared:  require at least this many shared SSIDs (kills noise
                 from single-SSID overlap like 'eduroam')
    """
    device_to_ssids = _device_ssids(conn)
    device_ids = sorted(device_to_ssids.keys())
    if not device_ids:
        return 0

    idx = {did: i for i, did in enumerate(device_ids)}
    find, union, _ = _union_find(len(device_ids))
    edge_conf = defaultdict(list)

    for a, b in combinations(device_ids, 2):
        sa, sb = device_to_ssids[a], device_to_ssids[b]
        shared = sa & sb
        if len(shared) < min_shared:
            continue
        sim = _jaccard(sa, sb)
        if sim >= threshold:
            union(idx[a], idx[b])
            ra = find(idx[a])
            edge_conf[ra].append(sim)

    clusters = defaultdict(list)
    for did in device_ids:
        clusters[find(idx[did])].append(did)

    now = time.time()
    # Wipe old group assignments so re-runs are idempotent.
    conn.execute("UPDATE devices SET group_id = NULL")
    conn.execute("DELETE FROM groups")

    group_count = 0
    for root, members in clusters.items():
        if len(members) < 2:
            continue  # singletons aren't a 'group'
        confidences = edge_conf.get(root, [0.0])
        avg_conf = sum(confidences) / len(confidences)
        cur = conn.execute(
            """INSERT INTO groups (label, confidence, first_seen, last_seen)
               VALUES (?, ?, ?, ?)""",
            (f"person_{root}", avg_conf, now, now),
        )
        gid = cur.lastrowid
        conn.executemany(
            "UPDATE devices SET group_id = ? WHERE id = ?",
            [(gid, did) for did in members],
        )
        group_count += 1

    return group_count


def top_groups(conn, limit=5):
    rows = conn.execute(
        """SELECT g.id, g.label, g.confidence,
                  COUNT(d.id) AS device_count,
                  GROUP_CONCAT(DISTINCT p.ssid) AS ssids
           FROM groups g
           JOIN devices d ON d.group_id = g.id
           JOIN probes p  ON p.fingerprint = d.fingerprint
           WHERE p.ssid != ''
           GROUP BY g.id
           ORDER BY device_count DESC, g.confidence DESC
           LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]
