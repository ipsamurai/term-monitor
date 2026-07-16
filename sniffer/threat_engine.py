"""
threat_engine.py — Stateful heuristic threat scoring engine.

Scoring heuristics (per .context.md § Threat Scoring):
  - Port Scanning:    ≥5 unique dst ports from same src IP in 10s  → +40 pts
  - Suspicious Ports: traffic on 4444 / 31337                      → +30 pts
  - Rapid SSH/Telnet: >5 hits on port 22 or 23 in 10s              → +20 pts
  - ICMP Flood:       >10 ICMP packets/sec from single IP          → +35 pts

Thresholds:
   0–30  → Safe     (green)
  31–70  → Warning  (yellow)
  71–100 → Critical (bold red)

MEMORY LEAK FIX: _prune() evicts any IP from the state dict whose
last-seen timestamp is older than STALE_SECONDS (10 s). This keeps the
dict bounded to only currently-active hosts, preventing unbounded growth
during long capture sessions.
"""

import threading
import time
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from sniffer.extractor import PacketInfo

# ── Constants ─────────────────────────────────────────────────────────────────
STALE_SECONDS: float = 10.0          # prune IPs not seen for this long
SUSPICIOUS_PORTS: Set[int] = {4444, 31337}
SENSITIVE_PORTS: Set[int] = {22, 23}  # SSH, Telnet
PORT_SCAN_THRESHOLD: int = 5          # unique ports in window → scan detected
SENSITIVE_HIT_THRESHOLD: int = 5      # rapid hits on SSH/Telnet in window
ICMP_FLOOD_THRESHOLD: int = 10        # ICMP packets per second


class _IPState:
    """Per-IP tracking state. Stored inside ThreatEngine._state."""
    __slots__ = ("last_seen", "dst_ports", "icmp_timestamps", "sensitive_hits")

    def __init__(self) -> None:
        self.last_seen: float = time.time()
        self.dst_ports: List[Tuple[float, int]] = []       # (ts, port)
        self.icmp_timestamps: List[float] = []              # ts of each ICMP pkt
        self.sensitive_hits: List[float] = []               # ts of SSH/Telnet hits


class ThreatEngine:
    """
    Thread-safe heuristic threat scorer.

    All public methods acquire self._lock before reading/writing state.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # dict[src_ip -> _IPState]; pruned on every score() call
        self._state: Dict[str, _IPState] = {}

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _prune(self, now: float) -> None:
        """
        Remove IPs that haven't been seen for STALE_SECONDS.
        Called at the start of every score() while the lock is held.
        This is Fix #2 — prevents the state dict from growing indefinitely.
        """
        cutoff = now - STALE_SECONDS
        stale_keys = [ip for ip, s in self._state.items() if s.last_seen < cutoff]
        for ip in stale_keys:
            del self._state[ip]

    def _get_or_create(self, ip: str) -> _IPState:
        """Return existing _IPState for ip, creating it if absent."""
        if ip not in self._state:
            self._state[ip] = _IPState()
        return self._state[ip]

    @staticmethod
    def _trim_window(ts_list: List[float], now: float) -> None:
        """Remove entries older than STALE_SECONDS from a timestamp list in-place."""
        cutoff = now - STALE_SECONDS
        # Lists are append-only, so old entries are always at the front
        while ts_list and ts_list[0] < cutoff:
            ts_list.pop(0)

    @staticmethod
    def _trim_port_window(port_list: List[Tuple[float, int]], now: float) -> None:
        """Remove (ts, port) tuples older than STALE_SECONDS from the front."""
        cutoff = now - STALE_SECONDS
        while port_list and port_list[0][0] < cutoff:
            port_list.pop(0)

    # ── Public API ────────────────────────────────────────────────────────────

    def score(self, info: PacketInfo) -> Tuple[int, str]:
        """
        Score a packet and return (score: int, level: str).

        Level labels:
            "Safe"     → 0–30   (green)
            "Warning"  → 31–70  (yellow)
            "Critical" → 71–100 (bold red)
        """
        now = time.time()
        points = 0

        with self._lock:
            # 1. Prune stale IPs first (memory leak fix)
            self._prune(now)

            state = self._get_or_create(info.src_ip)
            state.last_seen = now

            # ── Suspicious / sensitive port scoring ───────────────────────────
            if info.dst_port is not None:
                # Record port hit in time-windowed list
                state.dst_ports.append((now, info.dst_port))
                self._trim_port_window(state.dst_ports, now)

                # Suspicious backdoor ports
                if info.dst_port in SUSPICIOUS_PORTS:
                    points += 30

                # Rapid SSH / Telnet hits
                if info.dst_port in SENSITIVE_PORTS:
                    state.sensitive_hits.append(now)
                    self._trim_window(state.sensitive_hits, now)
                    if len(state.sensitive_hits) > SENSITIVE_HIT_THRESHOLD:
                        points += 20

                # Port scan: ≥ PORT_SCAN_THRESHOLD unique ports in window
                unique_ports_in_window = {p for _, p in state.dst_ports}
                if len(unique_ports_in_window) >= PORT_SCAN_THRESHOLD:
                    points += 40

            # ── ICMP flood scoring ────────────────────────────────────────────
            if info.protocol == "ICMP":
                state.icmp_timestamps.append(now)
                self._trim_window(state.icmp_timestamps, now)

                # Rate = count of ICMP packets in the last 1 second
                one_sec_ago = now - 1.0
                icmp_per_sec = sum(1 for t in state.icmp_timestamps if t >= one_sec_ago)
                if icmp_per_sec > ICMP_FLOOD_THRESHOLD:
                    points += 35

        # ── Clamp and label ───────────────────────────────────────────────────
        score = min(max(points, 0), 100)

        if score <= 30:
            level = "Safe"
        elif score <= 70:
            level = "Warning"
        else:
            level = "Critical"

        return score, level

    def get_state_size(self) -> int:
        """Return the number of IPs currently tracked (for diagnostics)."""
        with self._lock:
            return len(self._state)
