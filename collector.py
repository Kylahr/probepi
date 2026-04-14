"""Probe request sniffer using scapy in monitor mode."""
import hashlib
import time
import subprocess
import threading
from scapy.all import sniff, Dot11, Dot11ProbeReq, Dot11Elt, RadioTap


def _mac_is_randomized(mac):
    """Locally administered bit (bit 1 of first octet) = randomized."""
    try:
        first = int(mac.split(":")[0], 16)
        return bool(first & 0x02)
    except Exception:
        return False


def _extract_ies(pkt):
    """Walk the Dot11Elt chain and return a list of (id, raw_bytes)."""
    ies = []
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        try:
            ies.append((int(elt.ID), bytes(elt.info)))
        except Exception:
            pass
        elt = elt.payload.getlayer(Dot11Elt)
    return ies


# IEs used for fingerprinting. SSID (0) is intentionally excluded.
FP_IE_IDS = {1, 45, 50, 127, 191, 221}


def _fingerprint(ies):
    """Stable fingerprint over capability-like IEs (not SSID).

    Two probes from the same device will generally share these IEs even
    when the MAC is randomized and the SSID list changes.
    """
    parts = []
    for ie_id, ie_data in ies:
        if ie_id in FP_IE_IDS:
            parts.append(f"{ie_id:02x}:{ie_data.hex()}")
    blob = "|".join(sorted(parts)).encode()
    return hashlib.sha1(blob).hexdigest()[:16]


def _channel_from_radiotap(pkt):
    try:
        freq = pkt[RadioTap].ChannelFrequency
        if 2412 <= freq <= 2484:
            return (freq - 2407) // 5 if freq != 2484 else 14
        if 5000 <= freq <= 5900:
            return (freq - 5000) // 5
    except Exception:
        pass
    return None


def _rssi_from_radiotap(pkt):
    try:
        return int(pkt[RadioTap].dBm_AntSignal)
    except Exception:
        return None


def parse_probe(pkt):
    if not pkt.haslayer(Dot11ProbeReq):
        return None
    dot11 = pkt.getlayer(Dot11)
    mac = (dot11.addr2 or "").lower()
    if not mac:
        return None

    ies = _extract_ies(pkt)
    ssid = ""
    for ie_id, data in ies:
        if ie_id == 0:
            try:
                ssid = data.decode("utf-8", errors="replace")
            except Exception:
                ssid = ""
            break

    return {
        "ts": time.time(),
        "mac": mac,
        "mac_random": _mac_is_randomized(mac),
        "ssid": ssid,
        "rssi": _rssi_from_radiotap(pkt),
        "channel": _channel_from_radiotap(pkt),
        "seq": int(getattr(dot11, "SC", 0) or 0) >> 4,
        "fingerprint": _fingerprint(ies),
        "ies_raw": b"".join(bytes([i]) + bytes([len(d)]) + d for i, d in ies),
    }


class ChannelHopper(threading.Thread):
    """Rotates the interface through 2.4 GHz channels."""

    CHANNELS = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13]

    def __init__(self, iface, dwell=0.35):
        super().__init__(daemon=True)
        self.iface = iface
        self.dwell = dwell
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        idx = 0
        while not self._stop.is_set():
            ch = self.CHANNELS[idx % len(self.CHANNELS)]
            try:
                subprocess.run(
                    ["iw", "dev", self.iface, "set", "channel", str(ch)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass
            idx += 1
            self._stop.wait(self.dwell)


def run_sniffer(iface, on_probe, stop_event):
    def _handler(pkt):
        if stop_event.is_set():
            return True
        probe = parse_probe(pkt)
        if probe:
            try:
                on_probe(probe)
            except Exception as e:
                print(f"[collector] handler error: {e}")

    sniff(
        iface=iface,
        prn=_handler,
        store=False,
        stop_filter=lambda _p: stop_event.is_set(),
        monitor=True,
    )
