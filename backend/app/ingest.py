"""ingest: the doors telemetry comes in through, besides Kafka.

`ingest_events` takes events already in the streaming schema (what Kafka carries), writes them to the graph
once each through the same `events.apply_batch` the stream uses, creates any host or account an alert names
that is not in the graph yet, and re-scores. `map_alerts` turns alert payloads shaped like a named SIEM or EDR
product into those events.

the field maps are written from each product's public documentation and from sample payloads we wrote. they are
starting points to check against a real tenant, not certified connectors."""
import hashlib
import json

from . import stream
from .events import KINDS, BadEvent, apply_batch, parse
from .seed import NODE_LABELS

ALERT_FORMATS = ("graphops", "sentinel", "splunk", "elastic", "wazuh")


class MappingError(ValueError):
    pass


def ingest_events(session, events):
    """validate, write and re-score a batch of streaming-schema events. safe to call repeatedly: every event
    carries an id and is written at most once, so a replayed batch changes nothing."""
    parsed, bad = [], 0
    for ev in events:
        topic = KINDS.get(ev.get("kind"), (None,))[0]
        if topic is None:
            bad += 1
            continue
        try:
            parsed.append(parse(json.dumps(ev).encode(), topic))
        except BadEvent:
            bad += 1
    hints = {}
    for ev in events:
        for ent in ev.get("entities", []) or []:
            if isinstance(ent, dict) and ent.get("id") and ent.get("label") in NODE_LABELS:
                hints[ent["id"]] = ent["label"]

    def work(tx):
        for label in NODE_LABELS:
            ids = [i for i, lab in hints.items() if lab == label]
            if ids:
                tx.run(f"UNWIND $ids AS id MERGE (n:{label} {{id: id}}) ON CREATE SET n.name = id", ids=ids)
        result = apply_batch(tx, parsed) if parsed else {"events": 0, "skipped": 0, "alerts": 0, "network": False}
        tx.run("MERGE (s:StreamState {id: 'live'}) ON CREATE SET s.seq = 0, s.rescore = false, s.network = false")
        if result["alerts"] or result["network"] or hints:
            tx.run("MATCH (s:StreamState {id: 'live'}) SET s.rescore = true, s.network = coalesce(s.network, false) OR $n",
                   n=result["network"] or bool(hints))
        return result

    result = session.execute_write(work)
    result["bad"] = bad
    result["changed"] = stream.rescore(session) or []
    return result


# --- alert field maps -------------------------------------------------------

SEVERITY_WORDS = {"informational": "low", "info": "low", "low": "low", "medium": "medium", "moderate": "medium",
                  "high": "high", "critical": "critical", "severe": "critical"}


def _sev_word(value, default="medium"):
    if value is None:
        return default
    return SEVERITY_WORDS.get(str(value).strip().lower(), default)


def _sev_number(value, default="medium"):
    """map a numeric severity (Splunk 1-10ish, Wazuh rule level 0-15) into our four words."""
    try:
        n = float(value)
    except (TypeError, ValueError):
        return default
    scale = 15 if n > 10 else 10
    frac = n / scale
    return "critical" if frac >= 0.8 else "high" if frac >= 0.6 else "medium" if frac >= 0.3 else "low"


def _event_id(fmt, raw_id, payload):
    if raw_id:
        return f"{fmt}-{raw_id}"
    digest = hashlib.sha1(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:16]
    return f"{fmt}-{digest}"


def _host_id(name):
    return str(name).split(".")[0].strip().lower() if name else None


def _account_id(name):
    """drop a domain prefix or suffix so CORP\\jdoe and jdoe@corp.local both become jdoe."""
    if not name:
        return None
    name = str(name).strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.lower()


def _entities(hosts, accounts):
    """involved ids plus their labels, keeping order and dropping blanks and duplicates."""
    seen, involves, ents = set(), [], []
    for label, name, norm in ([("Computer", h, _host_id(h)) for h in hosts]
                              + [("User", a, _account_id(a)) for a in accounts]):
        if norm and norm not in seen:
            seen.add(norm)
            involves.append(norm)
            ents.append({"id": norm, "label": label})
    return involves, ents


def _alert_event(fmt, raw_id, time, source_tool, name, severity, tactic, technique, hosts, accounts, payload):
    involves, ents = _entities(hosts, accounts)
    if not name:
        raise MappingError(f"{fmt} alert has no name/title field")
    if not involves:
        raise MappingError(f"{fmt} alert '{name}' names no host or account")
    return {"event_id": _event_id(fmt, raw_id, payload), "time": time or _now(), "source_tool": source_tool,
            "kind": "Alert", "id": raw_id or _event_id(fmt, raw_id, payload), "name": name, "severity": severity,
            "tactic_id": tactic, "technique_id": technique, "involves": involves, "entities": ents}


def _now():
    import datetime as dt
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _first(d, *keys):
    for k in keys:
        if isinstance(d, dict) and d.get(k) not in (None, "", []):
            return d[k]
    return None


def _graphops(a):
    """already a GraphOps alert event or close to it: pass the fields through, fill entity hints if absent."""
    ev = dict(a)
    ev.setdefault("kind", "Alert")
    ev.setdefault("source_tool", "GraphOps")
    ev.setdefault("event_id", _event_id("graphops", a.get("id"), a))
    if "entities" not in ev and ev.get("involves"):
        ev["entities"] = [{"id": i, "label": "Computer"} for i in ev["involves"]]
    return ev


def _sentinel(a):
    """Microsoft Sentinel SecurityAlert: AlertName, AlertSeverity, TimeGenerated, Tactics, Techniques, Entities
    (a list of {Type: 'host'|'account', HostName/Name})."""
    hosts, accounts = [], []
    for e in a.get("Entities", []) or []:
        t = str(e.get("Type", "")).lower()
        if t in ("host", "machine"):
            hosts.append(_first(e, "HostName", "Name"))
        elif t in ("account", "user"):
            accounts.append(_first(e, "Name", "AadUserId", "Sid"))
    techniques = a.get("Techniques") or []
    tactics = a.get("Tactics") or []
    return _alert_event(
        "sentinel", _first(a, "SystemAlertId", "VendorOriginalId"), _first(a, "TimeGenerated", "StartTime"),
        _first(a, "ProductName") or "Microsoft Sentinel", _first(a, "AlertName", "DisplayName"),
        _sev_word(a.get("AlertSeverity")), (tactics[0] if tactics else None),
        (techniques[0] if techniques else None), hosts, accounts, a)


def _splunk(a):
    """Splunk Enterprise Security notable event: rule_name/search_name, urgency/severity, info_max_time/_time,
    src/dest/dvc, user, annotations.mitre_attack (technique ids)."""
    attack = (a.get("annotations") or {}).get("mitre_attack") or a.get("mitre_attack") or []
    if isinstance(attack, str):
        attack = [attack]
    return _alert_event(
        "splunk", _first(a, "event_id", "event_hash", "rule_id"), _first(a, "info_max_time", "_time", "time"),
        "Splunk ES", _first(a, "rule_name", "search_name", "rule_title"),
        _sev_number(a["urgency"]) if "urgency" in a and str(a.get("urgency")).replace(".", "").isdigit() else _sev_word(_first(a, "urgency", "severity")),
        None, (attack[0] if attack else None),
        [_first(a, "dest", "dest_host", "dvc"), _first(a, "src", "src_host")], [a.get("user")], a)


def _elastic(a):
    """Elastic Security detection alert (ECS): kibana.alert.rule.name, kibana.alert.severity, @timestamp,
    host.name, user.name, kibana.alert.rule.threat[].tactic.id/technique.id."""
    threat = _first(a, "kibana.alert.rule.threat") or ((a.get("kibana.alert.rule") or {}).get("threat")) or []
    tactic = technique = None
    if threat:
        first = threat[0]
        tactic = (first.get("tactic") or {}).get("id")
        techs = first.get("technique") or []
        technique = (techs[0].get("id") if techs else None)
    host = _first(a, "host.name") or (a.get("host") or {}).get("name")
    user = _first(a, "user.name") or (a.get("user") or {}).get("name")
    return _alert_event(
        "elastic", _first(a, "kibana.alert.uuid", "event.id", "_id"), _first(a, "@timestamp", "timestamp"),
        "Elastic Security", _first(a, "kibana.alert.rule.name", "message", "rule.name"),
        _sev_word(_first(a, "kibana.alert.severity") or (a.get("kibana.alert") or {}).get("severity")),
        tactic, technique, [host], [user], a)


def _wazuh(a):
    """Wazuh alert: rule.description, rule.level (0-15), timestamp, agent.name, data.srcuser/dstuser,
    rule.mitre.id (technique ids), rule.mitre.tactic."""
    rule = a.get("rule") or {}
    mitre = rule.get("mitre") or {}
    techs = mitre.get("id") or []
    if isinstance(techs, str):
        techs = [techs]
    tactics = mitre.get("tactic") or []
    data = a.get("data") or {}
    agent = (a.get("agent") or {}).get("name") or a.get("agent_name")
    return _alert_event(
        "wazuh", _first(a, "id", "_id"), a.get("timestamp"), "Wazuh",
        _first(rule, "description") or a.get("full_log"), _sev_number(rule.get("level")),
        (tactics[0] if isinstance(tactics, list) and tactics else None), (techs[0] if techs else None),
        [agent], [_first(data, "srcuser", "dstuser", "win.eventdata.targetUserName")], a)


MAPPERS = {"graphops": _graphops, "sentinel": _sentinel, "splunk": _splunk, "elastic": _elastic, "wazuh": _wazuh}


def map_alerts(alerts, fmt):
    if fmt not in MAPPERS:
        raise MappingError(f"unknown format {fmt}")
    if not isinstance(alerts, list):
        raise MappingError("alerts must be a list")
    return [MAPPERS[fmt](a) for a in alerts]
