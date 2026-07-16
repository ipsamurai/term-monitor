# term-monitor

**CLI Network Packet Sniffer & Threat Scorer**

A terminal-based live network dashboard built with [`scapy`](https://scapy.net/) and [`rich`](https://github.com/Textualize/rich). Captures packets in real time, scores each one against heuristic threat rules, and renders a live color-coded dashboard — all with a hard memory ceiling.

---

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.10+ | Uses `match`-compatible type hints |
| `libpcap` | macOS: pre-installed. Linux: `sudo apt install libpcap-dev` |
| `sudo` / root | Required for raw packet capture |
| 8 GB RAM (max) | Enforced via `store=False` + rolling `deque(maxlen=20)` |

---

## Installation

```bash
# Clone / navigate to the project
cd term-monitor

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

```bash
# Auto-detect active interface
sudo .venv/bin/python main.py

# Specify an interface explicitly
sudo .venv/bin/python main.py -i eth0      # Linux
sudo .venv/bin/python main.py -i en0       # macOS
sudo .venv/bin/python main.py -i wlan0     # Wireless
```

Press **Ctrl+C** to stop. The terminal is fully restored on exit.

---

## Dashboard Layout

```
┌─────────────────── TERM-MONITOR | Interface: en0 | Uptime: 00:01:23 ──────────────────┐
│  ┌── Global Stats ──────────────┐  ┌── Threat Distribution ─────────────────────────┐ │
│  │  Total Packets: 1,204        │  │  Safe     ████████████████░░░░  980            │ │
│  │  Total Bytes:   892,304 B    │  │  Warning  ████░░░░░░░░░░░░░░░░  200            │ │
│  │  Top Talker:    192.168.1.5  │  │  Critical █░░░░░░░░░░░░░░░░░░░   24            │ │
│  └──────────────────────────────┘  └────────────────────────────────────────────────┘ │
│                                                                                       │
│  ┌── Live Capture ─────────────────────────────────────────────────────────────────┐  │
│  │  Time      Src IP          Dst IP          Proto  Port   Size    Score  Level   │  │
│  │  20:45:01  192.168.1.5     8.8.8.8         TCP    443    1420 B  0      Safe    │  │
│  │  20:45:01  10.0.0.2        192.168.1.1     UDP    53     64 B    0      Safe    │  │
│  │  20:45:02  192.168.1.99    192.168.1.1     TCP    4444   128 B   30     Warning │  │
│  │  20:45:03  192.168.1.99    192.168.1.1     TCP    31337  64 B    70     Critical│  │
│  └─────────────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Threat Scoring Heuristics

| Threat | Condition | Points |
|---|---|---|
| Suspicious port | Traffic on `4444` or `31337` | +30 |
| Port scan | ≥ 5 unique dst ports from same IP in 10 s | +40 |
| Rapid SSH/Telnet | > 5 hits on port `22`/`23` in 10 s | +20 |
| ICMP flood | > 10 ICMP packets/sec from single IP | +35 |

| Score | Level | Color |
|---|---|---|
| 0–30 | Safe | 🟢 Green |
| 31–70 | Warning | 🟡 Yellow |
| 71–100 | Critical | 🔴 Bold Red |

---

## Architecture & Memory Safety

- **`store=False`** — scapy never buffers packets in RAM.
- **`deque(maxlen=20)`** — only the last 20 packets are held in the UI queue.
- **`ThreatEngine._prune()`** — the threat state dict evicts any IP not seen in the last 10 seconds, preventing indefinite growth during long sessions.
- **Non-IP guard** — ARP, Ethernet, and other non-IP frames are silently skipped via `haslayer(IP)` before any field access, preventing `KeyError` crashes.
- **`rich.live` at 2 FPS** — the UI renders at a fixed 0.5 s interval, completely decoupled from the packet capture rate.

---

## Project Structure

```
term-monitor/
├── main.py                  # Entry point: argparse, privilege check, wiring
├── requirements.txt
├── README.md
└── sniffer/
    ├── __init__.py
    ├── capture.py           # Interface detection + scapy sniff daemon thread
    ├── extractor.py         # Defensive packet parser → PacketInfo dataclass
    ├── threat_engine.py     # ThreatEngine: scoring + _prune() memory safety
    └── ui.py                # Rich Live dashboard (deque + layout)
```

---

## Testing Under Load

```bash
# In one terminal — start the monitor
sudo .venv/bin/python main.py -i lo

# In another terminal — simulate a port scan
nmap -sS --min-rate 5000 localhost

# Watch htop in a third terminal — RSS of the python process should stay flat
```
