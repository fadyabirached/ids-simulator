# 🔐 Cyber Intrusion Detection System (IDS) Simulator

A Python simulator for generating network traffic, injecting attacks, detecting
anomalies with rule-based heuristics, and visualizing the results — with both a
**Tkinter GUI** and a **CLI**.

---

## Architecture

```
generate_normal_traffic() ──┐
inject_port_scan() ─────────┼──► events (list of dicts)
inject_dos_attack() ────────┘
    │
    ▼
filter_by_whitelist() ──────── drops trusted source IPs before analysis
    │
    ▼
run_all_detectors() ────────── Port-scan detector: flags an IP hitting >20 ports
    │                          DoS detector: flags >50 unique IPs on one target
    ▼
save_log_csv() ─────────────── data/traffic.csv
    │
    ▼
count_sources / count_destinations / count_ports ── analytics.py
    │
    ▼
plot_top_counts() ──────────── Matplotlib bar charts, malicious IPs in red
```

## Features

- Synthetic traffic generation — each event is `source_ip`, `destination_ip`,
  `destination_port`, `timestamp`
- Attack injection — **Port Scan** (one attacker, many ports on one target) and
  **DoS** (many attackers flooding one target)
- Rule-based detection — port-scan threshold (>20 distinct ports) and DoS threshold
  (>50 distinct source IPs)
- Whitelist filtering to suppress known-trusted sources before detection
- Top-N analytics (source IPs, destination IPs, destination ports)
- Dark-themed Matplotlib bar charts with malicious IPs highlighted in red
- Tkinter GUI (`gui.py`) alongside the scriptable CLI (`main.py`)

---

<img width="1120" height="623" alt="IDS Simulator screenshot 1" src="https://github.com/user-attachments/assets/d2b7ddd7-8a4e-4962-a7f3-c17c1f6c3c8a" />
<img width="1117" height="622" alt="IDS Simulator screenshot 2" src="https://github.com/user-attachments/assets/c3b04ca1-d9fa-41ca-a8dd-7613d26e4f2f" />
<img width="1119" height="619" alt="IDS Simulator screenshot 3" src="https://github.com/user-attachments/assets/ea2941c5-4351-4132-b29c-294e636e996d" />
<img width="1120" height="841" alt="IDS Simulator screenshot 4" src="https://github.com/user-attachments/assets/78862e0c-cfc3-485f-aa01-aeef7d47d510" />

---

## Project Structure

```
ids-simulator/
├── main.py            # CLI entry point — generate, inject, filter, detect, chart
├── gui.py              # Tkinter GUI wrapping the same pipeline
├── simulator.py        # Synthetic traffic generation + attack injection
├── filters.py          # Whitelist filtering
├── detectors.py        # Rule-based port-scan and DoS detectors
├── analytics.py        # Top-N counting helpers (sources, destinations, ports)
├── visualizer.py        # Matplotlib bar chart rendering
├── storage.py           # CSV save/load for event logs
├── LICENSE
└── README.md            # This file
```

---

## Quickstart

### 1. Clone & enter the project
```bash
git clone https://github.com/fadyabirached/ids-simulator.git
cd ids-simulator
```

### 2. Install dependencies
This project only needs `matplotlib` beyond the standard library (Tkinter ships with
most Python installations; on Linux you may need your distro's `python3-tk` package).
```bash
pip install matplotlib
```

### 3. Run the CLI
```bash
python main.py
```
Generates 200 normal events, injects a 30-port scan and a 60-attacker DoS flood, filters
out whitelisted IPs, runs both detectors, saves the log to `data/traffic.csv`, prints
alerts and top-N tables, then opens three bar charts.

### 4. Or run the GUI
```bash
python gui.py
```

---

## Configuration

Detection thresholds and injected attack sizes are currently set at the call sites
rather than exposed as CLI flags:

| Parameter | Default | Where |
|---|---|---|
| Port-scan threshold | 20 distinct ports | `detectors.detect_port_scans` |
| DoS threshold | 50 distinct source IPs | `detectors.detect_dos` |
| Normal events generated | 200 | `main.py` |
| Injected port-scan size | 30 ports | `main.py` |
| Injected DoS attackers | 60 | `main.py` |
| Whitelist | `127.0.0.1`, `10.0.0.1` | `main.py` |

Adjust these directly in `main.py` (or `gui.py`) or call the underlying functions with
different arguments in your own script.

---

## Testing

There is no automated test suite yet — the detection logic is pure and
side-effect-free (`detectors.py`, `analytics.py`, `filters.py` all operate on plain
lists/dicts), which would make it straightforward to cover with `pytest` if that's
added later.

---

## Tech Stack

| Component | Library |
|---|---|
| Traffic simulation | Python standard library (`random`, `time`) |
| GUI | `tkinter` |
| Visualization | `matplotlib` |
| Storage | `csv` (standard library) |

---

## License
See [LICENSE](LICENSE).
