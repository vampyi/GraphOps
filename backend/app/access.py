"""granted vs used access: what an identity is allowed to reach against what the logs show it reached.

granted: group memberships followed through nested groups, then AdminTo, CanRDP and GenericAll rights.
used: LoggedInto and RemoteLogon edges whose last_seen falls inside the window. the difference is access that
is held but never used, which is risk with no benefit. access that was used with no right in the graph is
reported too: on real data it points at a right we have not imported (default logon rights are not modelled)."""
from datetime import datetime, timedelta

DEFAULT_DAYS = 30
RIGHTS = "AdminTo|CanRDP|GenericAll"
MAX_NESTING = 6


def since(days=DEFAULT_DAYS, asof=None):
    """the start of the window as an iso string. times in the graph are iso strings without a timezone, so
    comparing them as text is the same as comparing them as times."""
    if isinstance(asof, str):
        asof = datetime.fromisoformat(asof)
    asof = asof or datetime.now()
    return (asof - timedelta(days=days)).replace(microsecond=0).isoformat()


def granted(session, identity):
    """every machine, account or group the identity holds a right on, with the group chain that grants it."""
    rows = session.run(
        f"""
        MATCH (u {{id: $id}}) WHERE u:Entity
        MATCH (u)-[:MemberOf*0..{MAX_NESTING}]->(p)
        MATCH (p)-[r:{RIGHTS}]->(c)
        WITH u, c, collect(DISTINCT {{right: type(r), via: CASE WHEN p = u THEN null ELSE p.id END}}) AS rights
        RETURN c.id AS id, [l IN labels(c) WHERE l <> 'Entity'][0] AS kind, coalesce(c.critical, false) AS critical, rights
        ORDER BY critical DESC, id
        """, id=identity)
    return [dict(r) for r in rows]


def used(session, identity, window_start):
    """every machine the identity signed in to inside the window, from both kinds of logon edge."""
    rows = session.run(
        """
        MATCH (u {id: $id})-[r:LoggedInto]->(c) WHERE r.last_seen >= $since
        RETURN c.id AS id, [l IN labels(c) WHERE l <> 'Entity'][0] AS kind, coalesce(c.critical, false) AS critical,
               'LoggedInto' AS how, r.last_seen AS last_seen, coalesce(r.count, 1) AS count
        UNION ALL
        MATCH (x)-[r:RemoteLogon]->(c) WHERE r.last_seen >= $since AND $id IN coalesce(r.users, [r.user])
        RETURN c.id AS id, [l IN labels(c) WHERE l <> 'Entity'][0] AS kind, coalesce(c.critical, false) AS critical,
               'RemoteLogon' AS how, r.last_seen AS last_seen, coalesce(r.count, 1) AS count
        """, id=identity, since=window_start)
    out = {}
    for r in rows:
        r = dict(r)
        cur = out.get(r["id"])
        if cur is None:
            out[r["id"]] = {**r, "how": [r["how"]]}
        else:
            cur["count"] += r["count"]
            cur["last_seen"] = max(cur["last_seen"], r["last_seen"])
            if r["how"] not in cur["how"]:
                cur["how"].append(r["how"])
    return sorted(out.values(), key=lambda x: (not x["critical"], x["id"]))


def compare(session, identity, days=DEFAULT_DAYS, asof=None):
    """the two circles for one identity and the gap between them."""
    kind = session.run("MATCH (n {id: $id}) WHERE n:Entity RETURN [l IN labels(n) WHERE l <> 'Entity'][0] AS k", id=identity).single()
    if not kind:
        return None
    window_start = since(days, asof)
    g, u = granted(session, identity), used(session, identity, window_start)
    used_ids = {x["id"] for x in u}
    granted_ids = {x["id"] for x in g}
    unused = [x for x in g if x["id"] not in used_ids]
    return {
        "identity": identity, "kind": kind["k"], "days": days, "since": window_start,
        "granted": g, "used": u, "unused": unused,
        "used_without_grant": [x for x in u if x["id"] not in granted_ids],
        "summary": {"granted": len(g), "used": len(u), "unused": len(unused),
                    "unused_critical": sum(1 for x in unused if x["critical"]),
                    "share_unused": round(len(unused) / len(g), 3) if g else 0.0},
    }


def overview(session, days=DEFAULT_DAYS, asof=None):
    """every user account ranked by the access it holds but has not used: most unused critical access first."""
    window_start = since(days, asof)
    rows = session.run(
        f"""
        MATCH (u:User)
        OPTIONAL MATCH (u)-[:MemberOf*0..{MAX_NESTING}]->(p)-[:{RIGHTS}]->(c)
        WITH u, [x IN collect(DISTINCT c) WHERE x IS NOT NULL] AS granted
        OPTIONAL MATCH (u)-[l:LoggedInto]->(c1) WHERE l.last_seen >= $since
        WITH u, granted, [x IN collect(DISTINCT c1) WHERE x IS NOT NULL] AS used1
        OPTIONAL MATCH (x)-[rl:RemoteLogon]->(c2) WHERE rl.last_seen >= $since AND u.id IN coalesce(rl.users, [rl.user])
        WITH u, granted, used1, [y IN collect(DISTINCT c2) WHERE y IS NOT NULL] AS used2
        WITH u, granted, used1 + [y IN used2 WHERE NOT y IN used1] AS used
        RETURN u.id AS id, coalesce(u.is_service_account, false) AS service_account,
               [g IN granted | g.id] AS granted, [g IN used | g.id] AS used,
               [g IN granted WHERE NOT g IN used | g.id] AS unused,
               [g IN granted WHERE NOT g IN used AND coalesce(g.critical, false) | g.id] AS unused_critical
        """, since=window_start)
    out = []
    for r in rows:
        r = dict(r)
        r["summary"] = {"granted": len(r["granted"]), "used": len(r["used"]), "unused": len(r["unused"]),
                        "unused_critical": len(r["unused_critical"]),
                        "share_unused": round(len(r["unused"]) / len(r["granted"]), 3) if r["granted"] else 0.0}
        out.append(r)
    out.sort(key=lambda r: (-r["summary"]["unused_critical"], -r["summary"]["unused"], r["id"]))
    return {"days": days, "since": window_start, "identities": out,
            "totals": {"granted": sum(r["summary"]["granted"] for r in out), "used": sum(r["summary"]["used"] for r in out),
                       "unused": sum(r["summary"]["unused"] for r in out),
                       "unused_critical": sum(r["summary"]["unused_critical"] for r in out)}}
