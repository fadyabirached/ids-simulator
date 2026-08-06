from pathlib import Path

from storage import save_log_csv, load_log_csv


def test_save_and_load_roundtrip(tmp_path):
    events = [
        {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "destination_port": 80, "timestamp": 123.0},
    ]
    csv_path = tmp_path / "traffic.csv"
    save_log_csv(csv_path, events)

    assert Path(csv_path).exists()
    loaded = load_log_csv(csv_path)
    assert loaded == events


def test_load_missing_file_returns_empty_list(tmp_path):
    assert load_log_csv(tmp_path / "does_not_exist.csv") == []
