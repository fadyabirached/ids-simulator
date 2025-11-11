

from typing import List, Dict, Tuple


def count_sources(events: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for e in events:
        src = e.get("source_ip", "")
        counts[src] = counts.get(src, 0) + 1
    return counts


def count_destinations(events: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for e in events:
        dst = e.get("destination_ip", "")
        counts[dst] = counts.get(dst, 0) + 1
    return counts


def count_ports(events: List[Dict]) -> Dict[int, int]:
    counts: Dict[int, int] = {}
    for e in events:
        try:
            port = int(e.get("destination_port", 0))
        except Exception:
            port = 0
        counts[port] = counts.get(port, 0) + 1
    return counts


def top_k(counter: Dict, k: int = 10) -> List[Tuple]:
   
    return sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:k]
