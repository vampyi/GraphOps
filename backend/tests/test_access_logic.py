"""window arithmetic for granted vs used access; the graph queries are covered in test_flow2."""
from app.access import since


def test_window_start_is_days_before_asof_as_iso_text():
    assert since(30, "2026-10-21T09:00:00") == "2026-09-21T09:00:00"
    assert since(7, "2026-10-01T00:00:00") == "2026-09-24T00:00:00"


def test_window_start_compares_as_text_with_graph_times():
    start = since(30, "2026-10-21T09:00:00")
    assert "2026-10-20T06:00:00" >= start and "2026-09-20T23:59:59" < start
