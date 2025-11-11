

from typing import List, Dict, Tuple, Set

def detect_port_scans(events: List[Dict], port_threshold: int = 20):
   
    port_map: Dict[Tuple[str, str], Set[int]] = {}  
    alerts: List[str] = []
    malicious_ips: Set[str] = set()

    for e in events:
        src = e.get("source_ip", "")
        dst = e.get("destination_ip", "")
        try:
            port = int(e.get("destination_port", 0))
        except Exception:
            port = 0

        key = (src, dst)
        if key not in port_map:
            port_map[key] = set()
        port_map[key].add(port)

        
        if len(port_map[key]) == port_threshold:
            alert = f"[PORT-SCAN] {src} scanned {port_threshold} distinct ports on {dst}"
            alerts.append(alert)
            malicious_ips.add(src)

    return alerts, malicious_ips


def detect_dos(events: List[Dict], src_threshold: int = 50):
    
    dst_map: Dict[Tuple[str, int], Set[str]] = {}  
    alerts: List[str] = []
    involved_src_ips: Set[str] = set()

    for e in events:
        src = e.get("source_ip", "")
        dst = e.get("destination_ip", "")
        try:
            port = int(e.get("destination_port", 0))
        except Exception:
            port = 0

        key = (dst, port)
        if key not in dst_map:
            dst_map[key] = set()
        dst_map[key].add(src)

     
        if len(dst_map[key]) == src_threshold:
            alert = f"[DoS] {len(dst_map[key])} distinct sources targeting {dst}:{port}"
            alerts.append(alert)
            involved_src_ips.update(dst_map[key]) 

    return alerts, involved_src_ips


def run_all_detectors(events: List[Dict],
                      port_threshold: int = 20,
                      dos_src_threshold: int = 50):
   
    ps_alerts, ps_ips = detect_port_scans(events, port_threshold=port_threshold)
    dos_alerts, dos_ips = detect_dos(events, src_threshold=dos_src_threshold)

    alerts = ps_alerts + dos_alerts
    malicious_ips = set(ps_ips) | set(dos_ips)
    return alerts, malicious_ips
