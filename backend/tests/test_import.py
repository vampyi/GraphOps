"""R19: load a BloodHound / SharpHound collection into the schema. a small AD written in the BloodHound CE
json shape, loaded and checked against a real neo4j."""
import json

from app import exposure
from app.analysis import run_all
from app.db import ROOT
from app.import_bloodhound import load_sharphound, to_network, read_collection

USERS = {"meta": {"type": "users"}, "data": [
    {"ObjectIdentifier": "S-1-5-21-1105", "Properties": {"name": "JDOE@CORP.LOCAL", "objectid": "S-1-5-21-1105",
                                                         "highvalue": False, "serviceprincipalnames": []}},
    {"ObjectIdentifier": "S-1-5-21-1106", "Properties": {"name": "SVC_SQL@CORP.LOCAL", "objectid": "S-1-5-21-1106",
                                                         "serviceprincipalnames": ["MSSQL/db.corp.local"]}},
]}
GROUPS = {"meta": {"type": "groups"}, "data": [
    {"ObjectIdentifier": "S-1-5-21-512", "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "objectid": "S-1-5-21-512",
                                                        "highvalue": True},
     "Members": {"Results": [{"ObjectIdentifier": "S-1-5-21-1105", "ObjectType": "User"}]}},
    {"ObjectIdentifier": "S-1-5-21-1200", "Properties": {"name": "HELPDESK@CORP.LOCAL", "objectid": "S-1-5-21-1200",
                                                         "highvalue": False},
     "Members": {"Results": [{"ObjectIdentifier": "S-1-5-21-1105", "ObjectType": "User"}]}},
]}
COMPUTERS = {"meta": {"type": "computers"}, "data": [
    {"ObjectIdentifier": "S-1-5-21-1001", "Properties": {"name": "WS01.CORP.LOCAL", "objectid": "S-1-5-21-1001",
                                                         "operatingsystem": "Windows 11", "highvalue": False},
     "Sessions": {"Results": [{"UserSID": "S-1-5-21-1105"}]},
     "LocalAdmins": {"Results": [{"ObjectIdentifier": "S-1-5-21-1200", "ObjectType": "Group"}]}},
    {"ObjectIdentifier": "S-1-5-21-1002", "Properties": {"name": "DC01.CORP.LOCAL", "objectid": "S-1-5-21-1002",
                                                         "operatingsystem": "Windows Server 2022", "highvalue": True},
     "LocalAdmins": {"Results": [{"ObjectIdentifier": "S-1-5-21-512", "ObjectType": "Group"}]}},
]}


def _write(tmp_path):
    for name, doc in (("users", USERS), ("groups", GROUPS), ("computers", COMPUTERS)):
        (tmp_path / f"corp_{name}.json").write_text(json.dumps(doc))
    return tmp_path


def test_to_network_maps_sids_names_and_tier_zero(tmp_path):
    net = to_network(read_collection(_write(tmp_path)))
    ids = {n["id"] for n in net["nodes"]}
    assert ids == {"jdoe", "svc_sql", "domain admins", "helpdesk", "ws01", "dc01"}
    by_id = {n["id"]: n for n in net["nodes"]}
    assert by_id["domain admins"]["critical"] is True   # Tier Zero by name
    assert by_id["dc01"]["critical"] is True             # high-value computer
    assert by_id["helpdesk"]["critical"] is False
    assert by_id["svc_sql"]["is_service_account"] is True
    types = sorted(e["type"] for e in net["granted"])
    assert types == ["AdminTo", "AdminTo", "HasSession", "MemberOf", "MemberOf"]


def test_r19_sharphound_loads_into_neo4j_and_has_attack_paths(neo4j_driver, tmp_path):
    with neo4j_driver.session() as s:
        result = load_sharphound(s, _write(tmp_path))
        run_all(s)
        assert result == {"nodes": 6, "edges": 5, "alerts": 0}
        crit = {r["id"] for r in s.run("MATCH (n) WHERE n.critical = true RETURN n.id AS id")}
        assert crit == {"domain admins", "dc01"}
        exp = exposure.analyse(s, "all")
    # jdoe -> domain admins -> dc01, and ws01 -> jdoe's session -> dc01
    assert any(p["source"] == "jdoe" and p["target"] == "dc01" for p in exp["paths"])
    assert any(p["source"] == "ws01" for p in exp["paths"])
    assert {c["id"] for c in exp["chokepoints"]} & {"jdoe", "domain admins"}


def test_read_collection_from_zip(tmp_path):
    import zipfile
    _write(tmp_path)
    zpath = tmp_path / "corp.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        for f in tmp_path.glob("*.json"):
            z.write(f, f.name)
    net = to_network(read_collection(zpath))
    assert len(net["nodes"]) == 6


def test_real_bloodhound_ce_sample_loads(neo4j_driver):
    """SpecterOps' public sample: three domains, SharpHound format v6, objects repeated across merged files."""
    from app.analysis import run_all
    zip_path = ROOT / "backend" / "tests" / "fixtures" / "bloodhound_ce_sample" / "ad_sampledata.zip"
    network = to_network(read_collection(zip_path))
    kinds = {e["type"] for e in network["granted"]}
    assert {"MemberOf", "AdminTo", "HasSession"} <= kinds
    ids = [n["id"] for n in network["nodes"]]
    assert len(ids) == len(set(ids))
    assert "krbtgt@phantom.corp" in ids and "krbtgt@wraith.corp" in ids
    with neo4j_driver.session() as s:
        counts = load_sharphound(s, zip_path)
        run_all(s)
        reach = s.run("MATCH (n) WHERE n.hops_to_critical > 0 RETURN count(n) AS c").single()["c"]
    assert counts["nodes"] == len(ids)
    assert reach > 0
