

from __future__ import annotations
from pathlib import Path
import csv
from typing import Iterable, Dict, List

FIELDNAMES = ["source_ip", "destination_ip", "destination_port", "timestamp"]


def ensure_dirs(path: str | Path) -> Path:
    p = Path(path)
    if p.parent and not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _coerce_types(row: Dict[str, str]) -> Dict[str, object]:
   
    out: Dict[str, object] = dict(row)  
   
    try:
        out["destination_port"] = int(row.get("destination_port", 0))
    except (TypeError, ValueError):
        out["destination_port"] = 0

    try:
        out["timestamp"] = float(row.get("timestamp", 0.0))
    except (TypeError, ValueError):
        out["timestamp"] = 0.0

    out["source_ip"] = str(row.get("source_ip", ""))
    out["destination_ip"] = str(row.get("destination_ip", ""))

    return out


def save_log_csv(path: str | Path, events: Iterable[Dict[str, object]]) -> None:

    p = ensure_dirs(path)
    events_list: List[Dict[str, object]] = list(events)

    with p.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for e in events_list:
            row = {
                "source_ip": e.get("source_ip", ""),
                "destination_ip": e.get("destination_ip", ""),
                "destination_port": int(e.get("destination_port", 0)),
                "timestamp": float(e.get("timestamp", 0.0)),
            }
            writer.writerow(row)


def load_log_csv(path: str | Path) -> List[Dict[str, object]]:
    
    p = Path(path)
    if not p.exists():
        return []

    events: List[Dict[str, object]] = []
    with p.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(_coerce_types(row))
    return events
