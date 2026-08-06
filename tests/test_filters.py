from filters import filter_by_whitelist, add_to_whitelist, remove_from_whitelist


def test_filter_by_whitelist_drops_whitelisted_sources():
    events = [
        {"source_ip": "127.0.0.1"},
        {"source_ip": "8.8.8.8"},
    ]
    filtered = filter_by_whitelist(events, {"127.0.0.1"})
    assert filtered == [{"source_ip": "8.8.8.8"}]


def test_add_and_remove_from_whitelist():
    whitelist = set()
    add_to_whitelist(whitelist, "1.2.3.4")
    assert "1.2.3.4" in whitelist
    remove_from_whitelist(whitelist, "1.2.3.4")
    assert "1.2.3.4" not in whitelist
