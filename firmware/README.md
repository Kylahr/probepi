# Heltec V3 Probe Sniffer Firmware

Arduino firmware for the **Heltec WiFi LoRa 32 V3** (ESP32-S3) that
captures WiFi probe requests, shows live stats on the built-in OLED,
and streams each probe as a JSON line over USB-CDC.

## Arduino IDE setup (one time)

1. **File → Preferences → Additional Board Manager URLs**, add:
   ```
   https://resource.heltec.cn/download/package_heltec_esp32_index.json
   ```
2. **Tools → Board → Boards Manager** → search `heltec` → install
   **Heltec ESP32 Series Dev-boards** (also installs the OLED library).
3. **Tools → Board → Heltec ESP32 Arduino → WiFi LoRa 32(V3)**
4. **Tools → USB CDC On Boot → Enabled**  ← critical for Serial over USB-C
5. **Tools → Upload Speed → 921600**

## Flashing

1. Plug Heltec into your laptop with USB-C
2. **Tools → Port** → pick the new COM port
3. Open `heltec_probesniff/heltec_probesniff.ino`
4. Click Upload (arrow icon)
5. After upload, open **Serial Monitor** at 115200 baud — you'll start
   seeing JSON lines like:
   ```
   {"t":12345,"mac":"aa:bb:cc:dd:ee:ff","rand":1,"ssid":"eduroam",
    "rssi":-61,"ch":6,"seq":1023,"fp":"a1b2c3d4e5f60708"}
   ```

## Using with your phone (Android)

1. Install **Serial USB Terminal** by Kai Morich from the Play Store
2. USB-C cable from Heltec to phone (the phone powers the board)
3. Open the app → it auto-detects the Heltec → tap the connect icon
4. **Settings → Receive → Log to file → Enable**, set filename
5. Walk around. Probes stream live to the OLED and to the log file.
6. Stop logging, copy the file off the phone to your laptop

## Processing on laptop

```bash
python ingest_jsonl.py probes.log
```

This writes into `probes.db` and runs the clustering automatically.
Then:

```bash
sqlite3 probes.db "SELECT g.id, g.confidence, COUNT(d.id) AS devices \
                   FROM groups g JOIN devices d ON d.group_id=g.id GROUP BY g.id;"
```

## Fingerprint logic

Same algorithm as the Pi version in `collector.py` / `fingerprint.py`:

- Hash of Information Elements (IE IDs 1, 45, 50, 127, 191, 221), which
  cover supported rates + HT/VHT/HE capabilities
- SSID (IE 0) is deliberately excluded so different SSID probes from the
  same device still match
- MAC address not included so randomized MACs from the same device
  collapse into one fingerprint

## OLED display

```
PROBE SNIFFER
ch:6  seen:1234
macs:89  fps:23
last SSID:
eduroam
```

- `seen` — total probe requests captured
- `macs` — distinct source MAC addresses (lots if MAC randomization)
- `fps` — distinct device fingerprints (≈ real device count)
- `last SSID` — most recent non-empty SSID probed for

## Heads-up on the unique counters

The firmware uses fixed-size 512-slot sets for unique tracking. If you
run it for hours in a crowded place, the set fills up and new MACs/fps
just stop incrementing (old ones still work). The serial log is
unaffected — all probes are written. The laptop-side ingest has no such
limit.
