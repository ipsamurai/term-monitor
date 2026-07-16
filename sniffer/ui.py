"""
ui.py — Rich Live dashboard for term-monitor.

Architecture rules enforced (per .context.md):
  - Rule 2: Thread-safe rolling deque of last 20 packets (not updated per-packet).
  - Rule 3: rich.live.Live refreshes at fixed 0.5 s interval, independent of sniff rate.

Layout:
  ┌─────────── HEADER (title + iface + uptime) ────────────┐
  │  ┌── Global Stats ──┐  ┌── Threat Distribution ──┐     │
  │  └─────────────────-┘  └──────────────────────────┘     │
  └───────── Live Packet Table ────────────────────────────-┘
"""

import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from sniffer.extractor import PacketInfo

# ── Constants ────────────────────────────────────────────────────────────────
REFRESH_RATE: float = 2.0   # refreshes per second → 0.5 s interval (Rule 3)
MAX_PACKETS: int = 20        # rolling window size (Rule 2)

LEVEL_STYLES = {
    "Safe":     "bold green",
    "Warning":  "bold yellow",
    "Critical": "bold red",
}




@dataclass
class _PacketRecord:
    """A processed packet ready for display."""
    info: PacketInfo
    score: int
    level: str


class Dashboard:
    """
    Owns the Rich Live display and the thread-safe packet deque.

    Push packets from the sniff thread via push().
    Call run() from the main thread to block until Ctrl+C.
    Call stop() in the finally block to clean up.
    """

    def __init__(self, iface: str) -> None:
        self._iface = iface
        self._start_time = time.time()
        self._console = Console()
        self._live: Optional[Live] = None

        # Thread-safe rolling buffer (Rule 2: maxlen=20)
        self._lock = threading.Lock()
        self._deque: deque[_PacketRecord] = deque(maxlen=MAX_PACKETS)

        # Global counters
        self._total_packets = 0
        self._total_bytes = 0
        self._ip_hit_counts: dict[str, int] = {}

        # Threat level counters
        self._level_counts = {"Safe": 0, "Warning": 0, "Critical": 0}

    # ── Thread-safe write (called from sniff thread) ──────────────────────────

    def push(self, info: PacketInfo, score: int, level: str) -> None:
        """
        Push a processed packet into the rolling deque.
        Thread-safe — called from the sniff thread.
        """
        record = _PacketRecord(info=info, score=score, level=level)
        with self._lock:
            self._deque.append(record)
            self._total_packets += 1
            self._total_bytes += info.payload_size
            self._ip_hit_counts[info.src_ip] = (
                self._ip_hit_counts.get(info.src_ip, 0) + 1
            )
            self._level_counts[level] = self._level_counts.get(level, 0) + 1

    # ── Rendering helpers (called from main thread inside Live) ───────────────

    def _build_header(self) -> Panel:
        uptime_secs = int(time.time() - self._start_time)
        h, m, s = uptime_secs // 3600, (uptime_secs % 3600) // 60, uptime_secs % 60
        header_text = Text()
        header_text.append("⬡  TERM-MONITOR", style="bold cyan")
        header_text.append("  │  ", style="dim")
        header_text.append(f"Interface: ", style="dim")
        header_text.append(self._iface, style="bold white")
        header_text.append("  │  ", style="dim")
        header_text.append(f"Uptime: {h:02d}:{m:02d}:{s:02d}", style="dim cyan")
        return Panel(header_text, style="bold cyan", padding=(0, 1))

    def _build_stats_panel(self, records: list[_PacketRecord]) -> Panel:
        top_talker = "—"
        if self._ip_hit_counts:
            top_talker = max(self._ip_hit_counts, key=self._ip_hit_counts.get)  # type: ignore[arg-type]

        lines = Text()
        lines.append(f"  Total Packets : ", style="dim")
        lines.append(f"{self._total_packets:,}\n", style="bold white")
        lines.append(f"  Total Bytes   : ", style="dim")
        lines.append(f"{self._total_bytes:,} B\n", style="bold white")
        lines.append(f"  Top Talker    : ", style="dim")
        lines.append(f"{top_talker}\n", style="bold yellow")
        lines.append(f"  Tracked IPs   : ", style="dim")
        lines.append(f"{len(self._ip_hit_counts):,}", style="bold white")

        return Panel(lines, title="[bold cyan]Global Stats[/bold cyan]", padding=(0, 1))

    def _build_threat_panel(self) -> Panel:
        safe_c = self._level_counts["Safe"]
        warn_c = self._level_counts["Warning"]
        crit_c = self._level_counts["Critical"]
        total = max(safe_c + warn_c + crit_c, 1)

        def bar(count: int, color: str) -> str:
            filled = int((count / total) * 20)
            return f"[{color}]{'█' * filled}{'░' * (20 - filled)}[/{color}]"

        lines = Text.from_markup(
            f"  [bold green]Safe    [/bold green] {bar(safe_c, 'green')}  {safe_c}\n"
            f"  [bold yellow]Warning [/bold yellow] {bar(warn_c, 'yellow')}  {warn_c}\n"
            f"  [bold red]Critical[/bold red] {bar(crit_c, 'red')}  {crit_c}"
        )
        return Panel(lines, title="[bold cyan]Threat Distribution[/bold cyan]", padding=(0, 1))

    def _build_packet_table(self, records: list[_PacketRecord]) -> Table:
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold cyan",
            show_footer=False,
            expand=True,
            padding=(0, 1),
        )
        table.add_column("Time", style="dim", width=10, no_wrap=True)
        table.add_column("Src IP", min_width=15)
        table.add_column("Dst IP", min_width=15)
        table.add_column("Proto", width=6)
        table.add_column("Port", width=7, justify="right")
        table.add_column("Size", width=8, justify="right", style="dim")
        table.add_column("Score", width=7, justify="right")
        table.add_column("Level", width=10)

        for rec in reversed(records):   # newest first
            info = rec.info
            style = LEVEL_STYLES.get(rec.level, "white")
            ts = datetime.fromtimestamp(info.timestamp).strftime("%H:%M:%S")
            port_str = str(info.dst_port) if info.dst_port is not None else "—"

            table.add_row(
                ts,
                info.src_ip,
                info.dst_ip,
                info.protocol,
                port_str,
                f"{info.payload_size} B",
                f"[{style}]{rec.score}[/{style}]",
                f"[{style}]{rec.level}[/{style}]",
            )

        return table

    def _render(self) -> Layout:
        """Build the full Rich Layout for one frame."""
        # Snapshot the deque under lock (Rule 2: thread-safe read)
        with self._lock:
            records = list(self._deque)

        layout = Layout()
        layout.split_column(
            Layout(self._build_header(), name="header", size=3),
            Layout(name="stats_row", size=6),
            Layout(name="table"),
        )
        layout["stats_row"].split_row(
            Layout(self._build_stats_panel(records), name="global_stats"),
            Layout(self._build_threat_panel(), name="threat_dist"),
        )
        layout["table"].update(
            Panel(
                self._build_packet_table(records),
                title="[bold cyan]Live Capture[/bold cyan]",
                border_style="cyan",
            )
        )
        return layout

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        """
        Block on the Rich Live loop. Runs on the main thread.
        Exits on KeyboardInterrupt (propagated to caller).
        """
        with Live(
            self._render(),
            console=self._console,
            refresh_per_second=REFRESH_RATE,  # Rule 3: 0.5 s interval
            screen=True,
        ) as live:
            self._live = live
            while True:
                time.sleep(0.5)
                live.update(self._render())

    def stop(self) -> None:
        """Signal the Live display to stop (called from finally block)."""
        if self._live is not None:
            try:
                self._live.stop()
            except Exception:  # noqa: BLE001
                pass
