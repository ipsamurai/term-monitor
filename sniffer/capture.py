"""
capture.py — Network interface detection and scapy sniff thread.

Rules enforced (per .context.md):
  - scapy.sniff() MUST use store=False (Rule 1 / Architecture Rules)
  - sniff runs in a daemon thread so the main thread owns the Rich live loop
"""

import threading
import logging
from typing import Callable, Optional

from scapy.all import sniff, conf  # type: ignore
from scapy.interfaces import get_if_list  # type: ignore

logger = logging.getLogger(__name__)


def get_default_interface() -> str:
    """
    Return the best available network interface.

    Strategy:
      1. Use scapy's own default interface (cross-platform: en0 on macOS, eth0/wlan0 on Linux).
      2. Fall back to the first non-loopback interface in get_if_list().
      3. Last resort: 'lo' (loopback) so we never crash.
    """
    # scapy.conf.iface is the most reliable cross-platform default
    default = str(conf.iface)
    if default:
        return default

    interfaces = get_if_list()
    for iface in interfaces:
        if iface not in ("lo", "lo0"):
            return iface

    # Ultimate fallback — loopback (useful for testing)
    return "lo"


def start_sniff(
    iface: str,
    packet_callback: Callable,
    stop_event: threading.Event,
) -> threading.Thread:
    """
    Launch scapy sniff in a background daemon thread.

    Args:
        iface:            Network interface name (e.g. 'en0', 'eth0').
        packet_callback:  Called for every captured packet.
        stop_event:       threading.Event; when set, the sniff loop exits.

    Returns:
        The running daemon Thread (already started).
    """

    def _sniff_loop() -> None:
        logger.debug("Sniff thread started on interface: %s", iface)
        try:
            sniff(
                iface=iface,
                prn=packet_callback,
                store=False,          # CRITICAL: never buffer packets in RAM
                stop_filter=lambda _: stop_event.is_set(),
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Sniff thread encountered an error: %s", exc)
        logger.debug("Sniff thread exiting.")

    thread = threading.Thread(target=_sniff_loop, daemon=True, name="sniff-thread")
    thread.start()
    return thread
