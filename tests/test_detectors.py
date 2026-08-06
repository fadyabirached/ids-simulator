from detectors import detect_port_scans, detect_dos, run_all_detectors


def _event(src, dst, port):
    return {"source_ip": src, "destination_ip": dst, "destination_port": port, "timestamp": 0.0}


def test_detect_port_scans_flags_at_threshold():
    events = [_event("1.1.1.1", "2.2.2.2", p) for p in range(20)]
    alerts, malicious = detect_port_scans(events, port_threshold=20)
    assert len(alerts) == 1
    assert malicious == {"1.1.1.1"}


def test_detect_port_scans_below_threshold_is_silent():
    events = [_event("1.1.1.1", "2.2.2.2", p) for p in range(19)]
    alerts, malicious = detect_port_scans(events, port_threshold=20)
    assert alerts == []
    assert malicious == set()


def test_detect_dos_flags_at_threshold():
    events = [_event(f"10.0.0.{i}", "9.9.9.9", 80) for i in range(50)]
    alerts, involved = detect_dos(events, src_threshold=50)
    assert len(alerts) == 1
    assert len(involved) == 50


def test_detect_dos_below_threshold_is_silent():
    events = [_event(f"10.0.0.{i}", "9.9.9.9", 80) for i in range(49)]
    alerts, involved = detect_dos(events, src_threshold=50)
    assert alerts == []
    assert involved == set()


def test_run_all_detectors_combines_both():
    port_scan = [_event("1.1.1.1", "2.2.2.2", p) for p in range(20)]
    dos = [_event(f"10.0.0.{i}", "9.9.9.9", 80) for i in range(50)]
    alerts, malicious_ips = run_all_detectors(port_scan + dos, port_threshold=20, dos_src_threshold=50)
    assert len(alerts) == 2
    assert "1.1.1.1" in malicious_ips
    assert all(f"10.0.0.{i}" in malicious_ips for i in range(50))
