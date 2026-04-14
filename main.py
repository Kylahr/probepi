"""Probe sniffer main loop.

Starts the sniffer, channel hopper, and display updater.
Run as root (monitor mode needs CAP_NET_ADMIN).
"""
import argparse
import signal
import subprocess
import sys
import threading
import time

import database
import collector
import fingerprint


def set_monitor(iface):
    print(f"[main] putting {iface} into monitor mode")
    subprocess.run(["ip", "link", "set", iface, "down"], check=True)
    subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], check=True)
    subprocess.run(["ip", "link", "set", iface, "up"], check=True)


def set_managed(iface):
    print(f"[main] restoring {iface} to managed mode")
    subprocess.run(["ip", "link", "set", iface, "down"], check=False)
    subprocess.run(["iw", "dev", iface, "set", "type", "managed"], check=False)
    subprocess.run(["ip", "link", "set", iface, "up"], check=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="wlan0")
    ap.add_argument("--no-display", action="store_true")
    ap.add_argument("--no-monitor", action="store_true",
                    help="assume iface is already in monitor mode")
    ap.add_argument("--display-interval", type=float, default=10.0)
    ap.add_argument("--group-interval", type=float, default=60.0)
    ap.add_argument("--duration", type=float, default=0,
                    help="auto-stop after N seconds (0 = run forever)")
    args = ap.parse_args()
    deadline = time.time() + args.duration if args.duration > 0 else None

    database.init_db()

    display = None
    if not args.no_display:
        try:
            from display import EinkDisplay
            display = EinkDisplay()
            display.message("booting...")
        except Exception as e:
            print(f"[main] display init failed: {e}")
            display = None

    if not args.no_monitor:
        set_monitor(args.iface)

    stop_event = threading.Event()

    def shutdown(*_):
        print("\n[main] shutting down")
        stop_event.set()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    hopper = collector.ChannelHopper(args.iface)
    hopper.start()

    probe_lock = threading.Lock()
    pending = []

    def on_probe(probe):
        with probe_lock:
            pending.append(probe)

    def sniffer_thread():
        try:
            collector.run_sniffer(args.iface, on_probe, stop_event)
        except Exception as e:
            print(f"[main] sniffer crashed: {e}")
            stop_event.set()

    st = threading.Thread(target=sniffer_thread, daemon=True)
    st.start()

    last_display = 0.0
    last_group = 0.0

    try:
        while not stop_event.is_set():
            if deadline and time.time() >= deadline:
                print("[main] duration reached, stopping")
                stop_event.set()
                break
            with probe_lock:
                batch, pending[:] = pending[:], []

            if batch:
                with database.connect() as conn:
                    for p in batch:
                        database.insert_probe(conn, p)

            now = time.time()

            if now - last_group > args.group_interval:
                with database.connect() as conn:
                    try:
                        n = fingerprint.group_devices(conn)
                        print(f"[main] regrouped: {n} person-clusters")
                    except Exception as e:
                        print(f"[main] grouping error: {e}")
                last_group = now

            if display and now - last_display > args.display_interval:
                try:
                    with database.connect() as conn:
                        s = database.stats(conn)
                        rs = database.recent_ssids(conn, limit=5)
                    display.render(s, rs, [])
                except Exception as e:
                    print(f"[main] display error: {e}")
                last_display = now

            time.sleep(0.5)
    finally:
        hopper.stop()
        if display:
            try:
                display.message("stopped")
                display.sleep()
            except Exception:
                pass
        if not args.no_monitor:
            set_managed(args.iface)


if __name__ == "__main__":
    main()
