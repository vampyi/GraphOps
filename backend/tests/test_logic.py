"""unit tests that need no database."""
from app.scoring import link_alerts, stages_in_order
from app.story import check_citations


def alert(i, t, ents, tactic=None):
    return {"id": i, "time": f"2026-10-20T{t}:00", "entities": [{"id": e} for e in ents], "tactic_id": tactic}


def test_shared_entity_links_alerts():
    groups = link_alerts([alert("a", "10:00", ["pc1"]), alert("b", "10:30", ["pc1"])], [])
    assert len(groups) == 1


def test_far_apart_alerts_stay_separate():
    groups = link_alerts([alert("a", "08:00", ["pc1"]), alert("b", "11:00", ["pc1"])], [])
    assert len(groups) == 2


def test_login_between_machines_links_alerts_in_direction_of_travel():
    hop = {"type": "RemoteLogon", "src": "pc1", "dst": "srv", "last_seen": "2026-10-20T10:10:00"}
    assert len(link_alerts([alert("a", "10:00", ["pc1"]), alert("b", "10:20", ["srv"])], [hop])) == 1
    # same login but going the other way does not link
    back = dict(hop, src="srv", dst="pc1")
    assert len(link_alerts([alert("a", "10:00", ["pc1"]), alert("b", "10:20", ["srv"])], [back])) == 2


def test_stages_counted_in_kill_chain_order():
    group = [alert("a", "10:00", [], "TA0001"), alert("b", "10:10", [], "TA0006"), alert("c", "10:20", [], "TA0008")]
    assert stages_in_order(group) == 3


def test_citation_checker_drops_sentences_citing_outside_ids():
    kept, dropped = check_citations(
        [{"text": "ok", "cites": ["a-01"]}, {"text": "made up", "cites": ["x-99"]}, {"text": "no cite", "cites": []}],
        {"a-01"},
    )
    assert [s["text"] for s in kept] == ["ok"]
    assert len(dropped) == 2
