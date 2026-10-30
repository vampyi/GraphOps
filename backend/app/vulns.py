"""vulnerabilities from real public sources, attached to the software each machine runs.

for every Software node (vendor, product, version) we ask the NIST NVD which CVEs affect that exact version
(cpe search), check each against the CISA Known Exploited Vulnerabilities catalog and add FIRST EPSS scores.
we keep the ones that matter: exploited in the wild (KEV) or critical (CVSS 9 or more). when a machine that
runs such software is exposed to the internet and the CVE is remotely exploitable without a login, the
internet gains a CanExploit step to that machine, so the CVE becomes part of the attack paths.

sources: NVD API 2.0 (https://nvd.nist.gov/developers), CISA KEV (CC0,
https://www.cisa.gov/known-exploited-vulnerabilities-catalog), FIRST EPSS (https://www.first.org/epss/).
"This product uses the NVD API but is not endorsed or certified by the NVD."

loading a scenario uses the saved snapshot in data/vuln_snapshot.json, so it is quick and repeatable.
refresh(live=True) fetches the sources again."""
import datetime as dt
import json
import urllib.parse
import urllib.request

from .db import ROOT

SNAPSHOT = ROOT / "data" / "vuln_snapshot.json"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}&isVulnerable"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss?cve={cves}"
MIN_CVSS = 9.0
TIMEOUT = 30


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "GraphOps (hackathon prototype)"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as res:
        return json.loads(res.read())


def cpe(sw):
    return f"cpe:2.3:a:{sw['vendor']}:{sw['product']}:{sw['version']}:*:*:*:*:*:*:*"


def _cvss(cve):
    m = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
        if m.get(key):
            d = m[key][0]["cvssData"]
            return d.get("baseScore"), d.get("vectorString", "")
    return None, ""


def fetch(software):
    """live lookup: {cpe: [cve records]} for every software item, plus when it was fetched."""
    kev = {v["cveID"]: v for v in _get(KEV)["vulnerabilities"]}
    out = {}
    for sw in software:
        key = cpe(sw)
        records = []
        for v in _get(NVD.format(cpe=urllib.parse.quote(key, safe=":*")))["vulnerabilities"]:
            c = v["cve"]
            score, vector = _cvss(c)
            k = kev.get(c["id"])
            if not k and (score or 0) < MIN_CVSS:
                continue
            records.append({
                "id": c["id"], "published": c["published"][:10], "cvss": score, "vector": vector,
                "remote_unauth": "AV:N" in vector and "PR:N" in vector,
                "kev": bool(k), "kev_added": k["dateAdded"] if k else None,
                "ransomware": k["knownRansomwareCampaignUse"] if k else None,
                "summary": next((d["value"] for d in c["descriptions"] if d["lang"] == "en"), "")[:300],
            })
        out[key] = records
    ids = sorted({r["id"] for rs in out.values() for r in rs})
    if ids:
        epss = {e["cve"]: float(e["epss"]) for e in _get(EPSS.format(cves=",".join(ids)))["data"]}
        for rs in out.values():
            for r in rs:
                r["epss"] = epss.get(r["id"])
    return {"fetched": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "by_cpe": out}


def software_in_graph(session):
    return [dict(r) for r in session.run(
        "MATCH (s:Software) RETURN s.id AS id, s.vendor AS vendor, s.product AS product, s.version AS version")]


def apply(session, data):
    """write Vulnerability nodes, HasVuln edges and the derived CanExploit steps from data (fetch() format)."""
    session.run("MATCH ()-[r:CanExploit]->() DELETE r")
    session.run("MATCH (v:Vulnerability) DETACH DELETE v")
    rows = []
    for sw in software_in_graph(session):
        for r in data["by_cpe"].get(cpe(sw), []):
            rows.append({"sw": sw["id"], **r})
    session.run(
        """
        UNWIND $rows AS row
        MATCH (s:Software {id: row.sw})
        MERGE (v:Vulnerability {id: row.id})
        SET v += row {.published, .cvss, .vector, .remote_unauth, .kev, .kev_added, .ransomware, .summary, .epss},
            v.source_fetched = $fetched
        MERGE (s)-[:HasVuln]->(v)
        """, rows=rows, fetched=data["fetched"])
    # the internet can exploit an exposed machine that runs software with a remotely exploitable, serious cve
    session.run(
        """
        MATCH (i:Internet)-[:ExposedTo]->(c:Computer)-[:Runs]->(:Software)-[:HasVuln]->(v:Vulnerability)
        WHERE v.remote_unauth AND (v.kev OR v.cvss >= $min)
        WITH i, c, collect(DISTINCT v.id) AS cves
        MERGE (i)-[r:CanExploit]->(c)
        SET r.cves = cves, r.family = 'derived'
        """, min=MIN_CVSS)
    session.run(
        """
        MATCH (c:Computer)-[:Runs]->(:Software)-[:HasVuln]->(v:Vulnerability)
        WITH c, collect(v.id) AS cves, max(CASE WHEN v.kev THEN 1 ELSE 0 END) AS kev
        SET c.vulns = cves, c.kev = kev = 1
        """)
    return len(rows)


def refresh(session, live=False):
    """attach vulnerabilities from the live sources (live=True) or from the saved snapshot. a failed live fetch
    falls back to the snapshot."""
    data, source = None, "snapshot"
    if live:
        try:
            data = fetch(software_in_graph(session))
            source = "live"
            try:
                SNAPSHOT.write_text(json.dumps(data, indent=1) + "\n")
            except OSError:  # read-only file system, for example on vercel
                pass
        except Exception:  # network error or rate limit: keep working from the snapshot
            data = None
    if data is None:
        data = json.loads(SNAPSHOT.read_text()) if SNAPSHOT.exists() else {"fetched": None, "by_cpe": {}}
    n = apply(session, data)
    return {"source": source, "fetched": data["fetched"], "vulnerabilities": n}


def summary(session):
    return [dict(r) for r in session.run(
        """
        MATCH (c:Computer)-[:Runs]->(s:Software)-[:HasVuln]->(v:Vulnerability)
        OPTIONAL MATCH (i:Internet)-[:ExposedTo]->(c)
        RETURN v.id AS cve, v.cvss AS cvss, v.kev AS kev, v.kev_added AS kev_added, v.epss AS epss,
               v.remote_unauth AS remote_unauth, v.ransomware AS ransomware, v.summary AS summary,
               v.published AS published, s.product + ' ' + s.version AS software, c.id AS host,
               i IS NOT NULL AS internet_exposed, v.source_fetched AS fetched
        ORDER BY kev DESC, epss DESC, cvss DESC
        """)]
