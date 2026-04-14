# probepi

Captures WiFi probe requests, fingerprints devices, and groups them into
likely "people" by SSID overlap. Shows live stats on a Waveshare 2.13" B/W
e-ink display. Runs on a Raspberry Pi Zero 2 W.

## What it does

- Puts `wlan0` in monitor mode and channel-hops across 2.4 GHz
- Parses probe requests with scapy, stores them in SQLite
- Builds a stable device fingerprint from Information Elements
  (capability-level fields, not the SSID) so MAC-randomized probes from
  the same device collapse into one "device"
- Every minute, clusters devices into groups based on overlapping SSID
  preferences (Jaccard similarity) — two devices that probe for the same
  rare networks are likely the same person
- Every 10 seconds, renders live stats to the e-ink display

## Files

- `database.py`      — SQLite schema + helpers
- `collector.py`     — scapy sniffer, channel hopper, IE fingerprint
- `fingerprint.py`   — device clustering + person grouping
- `display.py`       — Waveshare 2.13" renderer
- `main.py`          — entrypoint
- `probepi.service`  — systemd unit

## Install (on the Pi)

Prerequisites already installed per the setup session (scapy, Pillow,
waveshare_epd, SPI enabled).

```bash
# Copy files into ~/probepi on the Pi, then:
cd ~/probepi
source venv/bin/activate

# Test run (foreground)
sudo ./venv/bin/python main.py --iface wlan0

# Or install as a service
sudo cp probepi.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now probepi
sudo journalctl -u probepi -f
```

## Copying from your laptop

From Git Bash / WSL on Windows:

```bash
scp -r /c/Users/RTX5070/Desktop/Projekte/Raspi/* pi@<pi-ip>:~/probepi/
```

## Important caveat

The Pi Zero 2 W has **one** WiFi interface. Putting `wlan0` into monitor
mode **drops your SSH session**. Options:

- Run it on the console (HDMI + keyboard) for development
- Plug in a USB WiFi dongle that supports monitor mode, and use that as
  the sniffing interface while `wlan0` stays on your hotspot. Pass
  `--iface wlan1` in that case.

## Useful flags

```bash
sudo python main.py --iface wlan0                  # default
sudo python main.py --iface wlan1                  # USB dongle
sudo python main.py --no-display                   # headless
sudo python main.py --no-monitor --iface wlan1mon  # already in monitor mode
```

## Later analysis

The SQLite file lives at `probes.db`. Copy it off the Pi for deeper analysis:

```bash
scp pi@<pi-ip>:~/probepi/probes.db ./
sqlite3 probes.db
```

Useful queries:

```sql
-- How many distinct devices per fingerprint
SELECT fingerprint, COUNT(DISTINCT mac) AS macs, probe_count
FROM devices ORDER BY macs DESC LIMIT 10;

-- SSIDs per group (person)
SELECT g.id, g.confidence, p.ssid, COUNT(*) AS hits
FROM groups g
JOIN devices d ON d.group_id = g.id
JOIN probes  p ON p.fingerprint = d.fingerprint
WHERE p.ssid != ''
GROUP BY g.id, p.ssid
ORDER BY g.id, hits DESC;
```

## Tuning the grouping

In `fingerprint.py`:

- `threshold=0.35` — Jaccard similarity needed to link two devices.
  Raise for fewer, tighter groups. Lower for looser clustering.
- `min_shared=2`   — at least N shared SSIDs required. Prevents noise
  from single common networks (e.g. `eduroam`) merging strangers.
