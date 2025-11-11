

from pathlib import Path
from simulator import generate_normal_traffic, inject_port_scan, inject_dos_attack
from filters import filter_by_whitelist
from detectors import run_all_detectors
from analytics import count_sources, count_destinations, count_ports, top_k
from visualizer import plot_top_counts
from storage import save_log_csv
from datetime import datetime
from pprint import pprint


def pretty_event(ev):
    
    ev2 = dict(ev)
    try:
        ev2["timestamp_human"] = datetime.fromtimestamp(float(ev.get("timestamp", 0.0))).isoformat(sep=' ')
    except Exception:
        ev2["timestamp_human"] = str(ev.get("timestamp"))
    return ev2


def main():
    Path("data").mkdir(parents=True, exist_ok=True)

    print("Generating normal traffic (200 events)...")
    events = generate_normal_traffic(200)

    print("Injecting a port scan (30 ports)...")
    inject_port_scan(events, n_ports=30)
    print("Injecting a DoS attack (60 attackers)...")
    inject_dos_attack(events, n_attackers=60)

    whitelist = {"127.0.0.1", "10.0.0.1"}  
    print("\nFiltering whitelisted IPs...")
    events = filter_by_whitelist(events, whitelist)
    print(f"Remaining events after filtering: {len(events)}")

    csv_path = Path("data/traffic.csv")
    save_log_csv(csv_path, events)
    print(f"Saved {len(events)} events to {csv_path}")

    print("\nRunning detectors (port_threshold=20, dos_src_threshold=50)...")
    alerts, malicious_ips = run_all_detectors(events, port_threshold=20, dos_src_threshold=50)

    if not alerts:
        print("No alerts detected.")
    else:
        print(f"\n=== Alerts ({len(alerts)}) ===")
        for a in alerts:
            print(a)

    if malicious_ips:
        print("\nMalicious source IPs identified:")
        for ip in list(malicious_ips)[:10]:
            print("-", ip)

    src_counts = count_sources(events)
    dst_counts = count_destinations(events)
    port_counts = count_ports(events)

    print("\n=== Top 5 source IPs ===")
    for ip, c in top_k(src_counts, 5):
        print(f"{ip:>16}  -> {c}")

    print("\n=== Top 5 destination IPs ===")
    for ip, c in top_k(dst_counts, 5):
        print(f"{ip:>16}  -> {c}")

    print("\n=== Top 5 destination ports ===")
    for port, c in top_k(port_counts, 5):
        print(f"{port:>5}  -> {c}")

    print("\n=== First 6 events (pretty sample) ===")
    for i, ev in enumerate(events[:6], 1):
        print(f"{i:02d}:")
        pprint(pretty_event(ev), width=120)
        print("-" * 60)

    print("\nGenerating visual charts...")
    plot_top_counts(src_counts, "Top Source IPs", top_n=10)
    plot_top_counts(dst_counts, "Top Destination IPs", top_n=10)
    plot_top_counts(port_counts, "Top Destination Ports", top_n=10)


if __name__ == "__main__":
    main()
