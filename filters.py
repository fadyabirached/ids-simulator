

from typing import List, Dict, Set


def filter_by_whitelist(events: List[Dict], whitelist: Set[str]):
   
    filtered = [e for e in events if e.get("source_ip", "") not in whitelist]
    return filtered


def add_to_whitelist(whitelist: Set[str], ip: str):
    whitelist.add(ip)


def remove_from_whitelist(whitelist: Set[str], ip: str):
    whitelist.discard(ip)  
