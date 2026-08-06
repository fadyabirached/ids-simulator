from analytics import count_sources, count_destinations, count_ports, top_k


def test_count_sources_and_destinations():
    events = [
        {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "destination_port": 80},
        {"source_ip": "1.1.1.1", "destination_ip": "3.3.3.3", "destination_port": 443},
    ]
    assert count_sources(events) == {"1.1.1.1": 2}
    assert count_destinations(events) == {"2.2.2.2": 1, "3.3.3.3": 1}
    assert count_ports(events) == {80: 1, 443: 1}


def test_top_k_orders_descending_and_limits():
    counts = {"a": 1, "b": 5, "c": 3}
    assert top_k(counts, k=2) == [("b", 5), ("c", 3)]
