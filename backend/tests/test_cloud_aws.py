"""a connected aws account: findings from the credential report, identities drawn into the graph, kept on reload."""
from app import cloud_aws, seed

SNAP = {"account": "1234", "fetched": "2026-10-30T10:00:00+00:00", "identities": [
    {"name": "root", "kind": "root", "level": "admin", "policies": [], "groups": [], "console": True,
     "password_last_used": "2026-10-30T09:00:00+00:00", "mfa": False, "created": None, "keys": []},
    {"name": "deepthi", "kind": "user", "level": "admin", "policies": ["AdministratorAccess"], "groups": [],
     "console": True, "password_last_used": "2026-10-30T09:00:00+00:00", "mfa": False, "created": "2026-10-01T00:00:00+00:00",
     "keys": [{"created": "2026-10-01T00:00:00+00:00", "last_used": None, "service": None}]},
    {"name": "dev-intern", "kind": "user", "level": "read", "policies": ["ReadOnlyAccess"], "groups": [],
     "console": False, "password_last_used": None, "mfa": False, "created": "2026-10-30T00:00:00+00:00", "keys": []},
]}


def test_levels():
    assert cloud_aws.level(["AdministratorAccess"]) == "admin"
    assert cloud_aws.level(["AmazonS3FullAccess"]) == "write"
    assert cloud_aws.level(["ReadOnlyAccess", "SecurityAudit"]) == "read"
    assert cloud_aws.level([]) == "none"


def test_findings_worst_first():
    f = cloud_aws.findings(SNAP)
    assert f[0] == {"severity": "critical", "who": "root", "text": "Root account has no MFA", "fix": "Turn on MFA for the root user"}
    texts = {(x["who"], x["text"]) for x in f}
    assert ("deepthi", "Admin can sign in to the console without MFA") in texts
    assert ("deepthi", "Active access key never used (admin rights)") in texts
    assert not any(x["who"] == "dev-intern" for x in f)


def test_drawn_into_the_graph_and_kept_on_reload(neo4j_driver):
    with neo4j_driver.session() as s:
        try:
            cloud_aws.save(s, SNAP)
            seed.load_network(s)  # a reload wipes entities; the snapshot is drawn back
            rows = {r["id"]: r["t"] for r in s.run(
                "MATCH (n {source: 'aws'})-[r]->(:CloudResource {id: 'aws:account'}) RETURN n.id AS id, type(r) AS t")}
            assert rows["aws:user/deepthi"] in ("AdminOf", "UsedAccess")
            assert s.run("MATCH (:User {id: 'aws:user/deepthi'})-[:AdminOf]->(a:CloudResource {critical: true}) "
                         "RETURN count(*) AS n").single()["n"] == 1
            assert s.run("MATCH (:User {id: 'aws:user/dev-intern'})-[:HasReadAccess]->() RETURN count(*) AS n").single()["n"] == 1
        finally:
            s.run("MATCH (c:CloudSnapshot) DELETE c")
            seed.load(s)
