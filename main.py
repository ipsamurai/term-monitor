"""
main.py — Entry point for term-monitor: CLI Network Packet Sniffer & Threat Scorer.

Usage:
    sudo python main.py                 # auto-detect interface
    sudo python main.py -i eth0         # specify interface
    sudo python main.py --interface en0
"""

import argparse
import os
import sys
import threading
import time
import logging

# Configure logging early (errors go to stderr, dashboard owns stdout)
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)


def _check_privileges() -> None:
    """Exit with a clear warning if the script is not running as root/sudo."""
    if os.geteuid() != 0:
        print(
            "\n[ERROR] term-monitor requires root privileges to capture packets.\n"
            "        Please re-run with: sudo python main.py\n",
            file=sys.stderr,
        )
        sys.exit(1)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="term-monitor",
        description="CLI Network Packet Sniffer & Threat Scorer",
    )
    parser.add_argument(
        "-i",
        "--interface",
        metavar="IFACE",
        default=None,
        help="Network interface to sniff (e.g. en0, eth0, wlan0). "
             "Auto-detected if omitted.",
    )
    return parser.parse_args()


def main() -> None:
    _check_privileges()
    args = _parse_args()

    # Deferred imports so privilege/argparse errors surface before scapy loads
    from sniffer.capture import get_default_interface, start_sniff
    from sniffer.extractor import extract_packet
    from sniffer.threat_engine import ThreatEngine
    from sniffer.ui import Dashboard

    # ── Interface ────────────────────────────────────────────────────────────
    iface = args.interface or get_default_interface()

    # ── Shared state ─────────────────────────────────────────────────────────
    stop_event = threading.Event()
    engine = ThreatEngine()
    dashboard = Dashboard(iface=iface)

    # ── Packet callback (runs in sniff thread) ────────────────────────────────
    def on_packet(packet) -> None:  # noqa: ANN001
        info = extract_packet(packet)
        if info is None:
            return  # Non-IP frame (ARP, Ethernet, etc.) — skip silently
        score, level = engine.score(info)
        dashboard.push(info, score, level)

    # ── Start sniff thread ────────────────────────────────────────────────────
    sniff_thread = start_sniff(
        iface=iface,
        packet_callback=on_packet,
        stop_event=stop_event,
    )

    # ── Run dashboard on main thread (owns terminal / Ctrl-C) ─────────────────
    try:
        dashboard.run()          # blocks until KeyboardInterrupt
    except KeyboardInterrupt:
        pass
    finally:
        # Signal the sniff thread to stop and wait briefly for it to exit
        stop_event.set()
        sniff_thread.join(timeout=3)
        dashboard.stop()
        print("\n[term-monitor] Capture stopped. Terminal restored. Goodbye.\n")


if __name__ == "__main__":
    main()
