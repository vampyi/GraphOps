"""the demo has a clear example in each place GraphOps covers: on-premises, cloud and ai agents. checked on the files
the demo loads, without a database: a route into a critical asset through the cloud, one through an ai agent, and a
real on-premises attack recording with labelled attack alerts. see docs/data-sources.md."""
import json
from pathlib import Path

import networkx as nx
import pytest

from app import scenarios
from app.attack import ATTACK_EDGES
from app.db import ROOT
from app.seed import EXTENSIONS, SAMPLE


def _sample_graph():
    """the sample organisation with its cloud and ai agent extension, as seed.load_network builds it."""
    network = json.loads((SAMPLE / "network.json").read_text())
    for ext in EXTENSIONS:
        extra = json.loads(ext.read_text())
        for key in ("nodes", "granted", "observed"):
            network[key] = network[key] + extra.get(key, [])
    g = nx.DiGraph()
    for n in network["nodes"]:
        g.add_node(n["id"], **n)
    for e in network["granted"] + network["observed"]:
        if e["type"] in ATTACK_EDGES:
            g.add_edge(e["src"], e["dst"])
    return g


def _critical(g):
    return [n for n, d in g.nodes(data=True) if d.get("critical")]


def test_cloud_example_route_from_on_prem_into_a_critical_cloud_resource():
    g = _sample_graph()
    on_prem = [n for n, d in g.nodes(data=True) if d.get("location", "onprem") == "onprem"]
    targets = [c for c in _critical(g) if g.nodes[c].get("location") == "cloud"]
    assert any(nx.has_path(g, u, c) for u in on_prem for c in targets)


def test_ai_agent_example_route_from_the_internet_through_an_agent_to_a_critical_asset():
    g = _sample_graph()
    agents = [n for n, d in g.nodes(data=True) if d["label"] == "AIAgent"]
    assert any(nx.has_path(g, "internet", a) and any(nx.has_path(g, a, c) for c in _critical(g)) for a in agents)


def test_on_prem_example_is_a_real_attack_recording_with_labelled_alerts():
    doc = json.loads(Path(scenarios._path_for("apt29_day1_sigma")).read_text())
    assert doc["source"].startswith("https://github.com/OTRF/Security-Datasets/")
    machines = {n["id"] for n in doc["network"]["nodes"] if n.get("location") == "onprem" and n["label"] == "Computer"}
    attack = [a for a in doc["alerts"] if a["scenario"] == "attack"]
    assert attack and all(a["involves"][0] in machines for a in attack)


@pytest.mark.xfail(reason="known gap: no labelled day has an alert on a cloud resource or an ai agent yet "
                          "(the live aws source was reverted); see docs/data-sources.md")
def test_some_labelled_day_has_an_alert_on_a_cloud_resource_or_an_ai_agent():
    g = _sample_graph()
    days = [SAMPLE / "alerts.json"] + sorted((ROOT / "data" / "scenarios").glob("*.json"))
    involved = {x for f in days for a in json.loads(f.read_text())["alerts"] for x in a["involves"]}
    assert any(g.has_node(x) and (g.nodes[x].get("location") == "cloud" or g.nodes[x]["label"] == "AIAgent")
               for x in involved)
