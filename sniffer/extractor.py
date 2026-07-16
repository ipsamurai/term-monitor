"""
extractor.py — Defensive packet field extraction.

KEY SAFETY RULE: Every Scapy layer access is guarded by haslayer().
Non-IP frames (ARP, raw Ethernet, etc.) return None so callers can skip
them silently without crashing the sniff thread.
"""

import time
from dataclasses import dataclass
from typing import Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore


@dataclass
class PacketInfo:
    """Structured record of a single captured packet."""
    timestamp: float       # Unix epoch (seconds)
    src_ip: str
    dst_ip: str
    protocol: str          # "TCP", "UDP", "ICMP", or "Other"
    dst_port: Optional[int]  # None for ICMP / unknown protocol
    payload_size: int      # Total bytes on wire


def extract_packet(packet) -> Optional[PacketInfo]:  # noqa: ANN001
    """
    Parse a Scapy packet into a PacketInfo.

    Returns None for any packet that does not have an IP layer
    (e.g. ARP broadcasts, raw Ethernet frames, LLC frames).
    This prevents KeyError crashes in the sniff thread.
    """
    # ── Guard: must have IP layer ─────────────────────────────────────────────
    if not packet.haslayer(IP):
        return None

    ip = packet[IP]
    src_ip: str = ip.src
    dst_ip: str = ip.dst
    payload_size: int = len(packet)
    ts: float = time.time()

    # ── Protocol + port detection (haslayer chain) ────────────────────────────
    if packet.haslayer(TCP):
        protocol = "TCP"
        dst_port: Optional[int] = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        dst_port = None   # ICMP has no port concept
    else:
        protocol = "Other"
        dst_port = None

    return PacketInfo(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        dst_port=dst_port,
        payload_size=payload_size,
    )
