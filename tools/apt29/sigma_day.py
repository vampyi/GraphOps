"""build the GraphOps 'APT29 day 1, Sigma rules' scenario from the public lab recording.

the alerts here come from real public SigmaHQ detection rules (not rules written for GraphOps), and the day keeps the
recording's real logons, process starts and connections, so the live replay streams the lab's own activity through
the identity, edr and flows topics instead of only the alerts.

sources
- the recording: MITRE ATT&CK Evaluations APT29 day 1, recorded by the Open Threat Research Forge (OTRF) Security
  Datasets project, MIT licence. download apt29_evals_day1_manual.zip from
  https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29/day1 and unzip it.
- the rules: a SigmaHQ release (https://github.com/SigmaHQ/sigma/releases), the sigma_core+ package, rules/windows
  only. Detection Rule License 1.1 (https://github.com/SigmaHQ/Detection-Rule-License): every alert keeps its rule's
  id, author and link.
- the network: the same machines, user and history as data/scenarios/apt29_day1.json (tools/apt29/build.py).

usage (pySigma is needed only to build this file; it is not a backend dependency):
  python3 -m venv /tmp/sigma-venv
  /tmp/sigma-venv/bin/pip install pysigma pysigma-backend-sqlite pysigma-pipeline-sysmon pysigma-pipeline-windows
  /tmp/sigma-venv/bin/python -I tools/apt29/sigma_day.py <apt29_evals_day1_manual_*.json> <the release's
      sigma_core+.zip> <release tag, e.g. r2026-07-01> > data/scenarios/apt29_day1_sigma.json

what it does: loads the 196,081 events into a temporary sqlite file, converts every windows rule with pySigma (sysmon
and windows log-source pipelines, sqlite backend) and keeps the first match of each rule per machine as one alert, at
the real time on the real machine. each alert and event is labelled attack or noise by us, following the published
emulation plan (center-for-threat-informed-defense adversary_emulation_library, apt29 scenario 1):
- the attacker's process trees: the payload with the hidden right-to-left character, PsExec's service and the
  javamtsup persistence service, hostui.exe from the Startup-folder shortcut, the attacker's remote PowerShell
  sessions (wsmprovhost.exe as pbeesly) and anything that contacts the attacker's server, plus all they started;
- everything done as pbeesly on NASHUA (pbeesly works only on SCRANTON, so that is the lateral movement);
- the logon from SCRANTON onto NASHUA as pbeesly.
the label is used only to score the ranking, never by it. command-line passwords are removed and script contents are
left out."""
import collections
import json
import os
import re
import sqlite3
import sys
import tempfile
import zipfile
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline

ROOT = Path(__file__).resolve().parents[2]
SY = "Microsoft-Windows-Sysmon/Operational"
RLO = ("‮", "â€®")  # the right-to-left override character, also as it appears mis-decoded in the file
ATTACK_SERVICES = ("javamtsup", "psexesvc")
ATTACKER_SERVER = "192.168.0.4"  # the emulation's attacker web server (WebDAV share), as in tools/apt29/build.py
PERSISTENCE = "hostui.exe"  # started by the hostui.lnk shortcut the attacker wrote into the Startup folder
SKIP_USERS = ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "-", "")
SEVERITY = {"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
# sigma tactic tags to ATT&CK tactic ids. defense-evasion is the pre-v19 name of TA0005 (now Stealth); v19 moved
# some of its techniques to TA0112 Defense Impairment, which newer rules tag as defense-impairment.
TACTICS = {"reconnaissance": "TA0043", "resource-development": "TA0042", "initial-access": "TA0001", "execution": "TA0002",
           "persistence": "TA0003", "privilege-escalation": "TA0004", "defense-evasion": "TA0005", "stealth": "TA0005",
           "defense-impairment": "TA0112", "credential-access": "TA0006", "discovery": "TA0007",
           "lateral-movement": "TA0008", "collection": "TA0009", "command-and-control": "TA0011",
           "exfiltration": "TA0010", "impact": "TA0040"}
LOGON_INTERACTIVE = {"2", "10", "11"}
PASSWORDS = [re.compile(r"(\s-p\s+|\s/p:|\s-password\s+|password\s*=\s*)(\S+)", re.I),
             re.compile(r"(\s-hp|\s-p)(?=\S)(\S+)")]  # rar and 7-zip take the password glued to the switch


def short_host(e):
    return (e.get("Hostname") or "").split(".")[0].lower()


def when(e):
    u = e.get("UtcTime")
    return u.replace(" ", "T")[:19] if u else (e.get("@timestamp") or "")[:19]


def base(path):
    name = (path or "").replace("/", "\\").split("\\")[-1]
    for r in RLO:
        name = name.replace(r, "")
    return name


def _secs(t):
    return int(t[11:13]) * 3600 + int(t[14:16]) * 60 + int(t[17:19])


def short_user(value):
    return (value or "").split("\\")[-1].lower()


def redact(text):
    text = text or ""
    for pattern in PASSWORDS:
        text = pattern.sub(lambda m: m.group(1) + "[removed]", text)
    return text


def pid(value):
    """process ids appear as decimal (sysmon) or hex strings (security log)."""
    if value in (None, "", "-"):
        return None
    try:
        return int(str(value), 16) if str(value).lower().startswith("0x") else int(value)
    except ValueError:
        return None


def load(path, db):
    """the recording into a sqlite table 'logs', one column per field. columns compare without case, as sigma does.
    sqlite column names ignore case too, so fields spelled two ways (TargetProcessGuid, TargetProcessGUID) share one."""
    keys = {}  # lower-case name -> first spelling seen
    for line in open(path, encoding="utf-8"):
        for k in json.loads(line):
            keys.setdefault(k.lower(), k)
    names = list(keys.values())
    cols = ", ".join(f'"{k}" COLLATE NOCASE' for k in names)
    db.execute(f"CREATE TABLE logs ({cols})")
    sql = f"INSERT INTO logs ({', '.join(chr(34) + k + chr(34) for k in names)}) VALUES ({', '.join('?' * len(names))})"
    batch = []
    for line in open(path, encoding="utf-8"):
        raw = json.loads(line)
        e = {}
        for k, v in raw.items():
            if e.get(keys[k.lower()]) is None:
                e[keys[k.lower()]] = v
        if (e.get("Channel") or "").lower() == "security":
            e["Channel"] = "Security"  # the recording spells the channel both ways; the rules expect 'Security'
        batch.append(tuple(json.dumps(e[k]) if isinstance(e.get(k), (dict, list)) else e.get(k) for k in names))
        if len(batch) == 5000:
            db.executemany(sql, batch)
            batch = []
    db.executemany(sql, batch)
    db.execute('CREATE INDEX ix ON logs (Channel, EventID)')
    db.commit()
    db.create_function("REGEXP", 2, lambda p, v: v is not None and re.search(p, str(v)) is not None)
    return set(names)


class Activity:
    """the recording's processes, machines and the attacker's process trees, used to label alerts and events."""

    def __init__(self, path):
        self.procs, self.children, self.by_pid, self.ip_host = {}, collections.defaultdict(list), collections.defaultdict(list), {}
        ips = collections.defaultdict(collections.Counter)
        security_starts = []
        for line in open(path, encoding="utf-8"):
            e = json.loads(line)
            if (e.get("Channel") or "").lower() == "security" and e.get("EventID") == 4688:
                security_starts.append(e)
            if e.get("Channel") != SY:
                continue
            h = short_host(e)
            if e.get("EventID") == 1:
                g = e.get("ProcessGuid")
                if not g:
                    continue  # one record in the recording has no process id at all
                self.procs[g] = e
                self.children[e.get("ParentProcessGuid")].append(g)
                self.by_pid[(h, pid(e.get("ProcessId")))].append((when(e), g))
            elif e.get("EventID") == 3 and str(e.get("Initiated")).lower() == "true" and (e.get("SourceIp") or "").startswith("10."):
                ips[h][e["SourceIp"]] += 1
        # each machine's own address is the one it most often connects out from
        self.ip_host = {c.most_common(1)[0][0]: h for h, c in ips.items()}
        # a few sysmon records are cut short; the security log's own process-start record (4688) fills the gap
        for e in security_starts:
            h, t, p = short_host(e), when(e), pid(e.get("NewProcessId"))
            if any(abs(_secs(s[0]) - _secs(t)) <= 2 for s in self.by_pid.get((h, p), [])):
                continue
            g = f"4688:{h}:{p}:{t}"
            self.procs[g] = {"Image": e.get("NewProcessName"), "Hostname": e.get("Hostname"), "UtcTime": t}
            self.children[self.guid_at(h, pid(e.get("ProcessId")), t)].append(g)
            self.by_pid[(h, p)].append((t, g))
        self.attack = set()
        # where the attacker's process trees start: the payload, PsExec's and javamtsup's services, the Startup-folder
        # program, the attacker's remote PowerShell sessions (pbeesly works only on SCRANTON) and anything that
        # contacts the attacker's server
        roots = [g for g, e in self.procs.items()
                 if any(r in (e.get("Image") or "") for r in RLO)
                 or base(e.get("Image")).lower().startswith(ATTACK_SERVICES)
                 or base(e.get("Image")).lower() == PERSISTENCE
                 or (base(e.get("Image")).lower() == "wsmprovhost.exe" and short_user(e.get("User")) == "pbeesly")
                 or ATTACKER_SERVER in (e.get("CommandLine") or "")]
        stack = list(roots)
        while stack:
            g = stack.pop()
            if g not in self.attack:
                self.attack.add(g)
                stack.extend(self.children.get(g, []))

    def guid_at(self, h, p, t):
        """the process that had this id on this machine at this time (the latest start at or before it)."""
        starts = [s for s in self.by_pid.get((h, p), []) if s[0] <= t]
        return max(starts)[1] if starts else None

    def is_attack(self, e):
        h, t = short_host(e), when(e)
        for f in ("ProcessGuid", "SourceProcessGUID", "SourceProcessGuid", "ParentProcessGuid"):
            if e.get(f) in self.attack:
                return True
        for f in ("ProcessId", "SourceProcessId", "ExecutionProcessID", "NewProcessId"):
            if self.guid_at(h, pid(e.get(f)), t) in self.attack:
                return True
        image = (e.get("ImagePath") or e.get("ServiceFileName") or "").lower()
        if any(s in image for s in ATTACK_SERVICES):
            return True
        if ATTACKER_SERVER in (str(e.get("DestinationIp") or "") + " " + (e.get("CommandLine") or "")):
            return True
        # pbeesly works only on SCRANTON: everything done as pbeesly on NASHUA is the attacker's lateral movement
        if h == "nashua" and "pbeesly" in {short_user(e.get(f)) for f in ("User", "SubjectUserName", "TargetUserName")}:
            return True
        return self.lateral_logon(e)

    def lateral_logon(self, e):
        """the attacker's PsExec logon: pbeesly from SCRANTON's address onto NASHUA."""
        return (e.get("Channel") == "Security" and e.get("EventID") == 4624 and str(e.get("LogonType")) == "3"
                and short_user(e.get("TargetUserName")) == "pbeesly" and short_host(e) == "nashua"
                and self.ip_host.get(e.get("IpAddress")) == "scranton")


def rules(release_zip, release):
    """every windows rule in the release package, read straight from the zip (keeps each rule's real path)."""
    backend = sqliteBackend(sysmon_pipeline() + windows_logsource_pipeline())
    out, failed = [], 0
    z = zipfile.ZipFile(release_zip)
    for member in sorted(n for n in z.namelist() if n.startswith("rules/windows/") and n.endswith(".yml")):
        try:
            col = SigmaCollection.from_yaml(z.read(member).decode("utf-8"))
            rule = col.rules[0]
            queries = backend.convert(col)
        except Exception:
            failed += 1
            continue
        tags = [str(t).lower() for t in rule.tags]
        tactic = next((TACTICS[t.split(".", 1)[1]] for t in tags if t.split(".", 1)[1] in TACTICS), None)
        tech = next((t.split(".", 1)[1].upper() for t in tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)), None)
        out.append({"id": str(rule.id), "title": rule.title, "author": rule.author or "unknown",
                    "level": rule.level.name.lower() if rule.level else "medium", "tactic_id": tactic, "technique_id": tech,
                    "link": f"https://github.com/SigmaHQ/sigma/blob/{release}/{member}",
                    "queries": [q.replace("SELECT * FROM logs WHERE", "SELECT rowid FROM logs WHERE", 1) for q in queries]})
    return out, failed


def evidence(e):
    parts = []
    if e.get("Image"):
        parts.append(base(e.get("Image")))
    if e.get("ParentImage"):
        parts.append(f"started by {base(e.get('ParentImage'))}")
    if e.get("CommandLine"):
        parts.append(f"command: {redact(e['CommandLine'])[:140]}")
    if e.get("TargetImage"):
        parts.append(f"opened {base(e.get('TargetImage'))}")
    if e.get("TargetFilename"):
        parts.append(f"file {base(e.get('TargetFilename'))}")
    if e.get("TargetObject"):
        parts.append(f"registry {e['TargetObject'][-80:]}")
    if e.get("ScriptBlockText") or e.get("Payload"):
        parts.append("PowerShell script content (not copied)")
    if e.get("ServiceName"):
        parts.append(f"service {e['ServiceName']}")
    if e.get("TargetUserName") and e.get("EventID") in (4624, 4625):
        parts.append(f"logon by {e['TargetUserName']} from {e.get('IpAddress')}")
    return "; ".join(parts) or f"event {e.get('EventID')} in {e.get('Channel')}"


def alerts(db, columns, rule_list, act, people):
    names = [r[1] for r in db.execute("PRAGMA table_info(logs)")]
    hits = {}  # (rule id, machine, label) -> [first event, match count]
    no_field = 0
    for rule in rule_list:
        for q in rule["queries"]:
            try:
                rows = db.execute(q).fetchall()
            except sqlite3.OperationalError:
                no_field += 1  # the rule reads a field this recording does not have
                continue
            for (rowid,) in rows:
                e = dict(zip(names, db.execute("SELECT * FROM logs WHERE rowid = ?", (rowid,)).fetchone()))
                key = (rule["id"], short_host(e), "attack" if act.is_attack(e) else "noise")
                if key not in hits or when(e) < when(hits[key][0]):
                    hits[key] = [e, hits.get(key, [None, 0])[1]]
                hits[key][1] += 1
    by_id = {r["id"]: r for r in rule_list}
    out = []
    for (rid, h, label), (e, count) in hits.items():
        r = by_id[rid]
        users = {short_user(e.get(f)) for f in ("User", "TargetUserName", "SubjectUserName")} & people
        out.append({"time": when(e), "name": r["title"], "severity": SEVERITY.get(r["level"], "medium"),
                    "source_tool": "Sigma", "tactic_id": r["tactic_id"], "technique_id": r["technique_id"],
                    "involves": [h] + sorted(users), "scenario": label,
                    "rule": rid, "rule_author": r["author"], "rule_link": r["link"],
                    "evidence": f"{evidence(e)} ({count} matching event{'s' if count != 1 else ''})"})
    out.sort(key=lambda a: (a["time"], a["name"], a["involves"][0]))
    for n, a in enumerate(out, 1):
        a["id"] = f"sig-{n:02d}"
    return out, no_field


def activity(path, act, hosts, people):
    """the day's real activity as GraphOps events: logons, connections between lab machines, process starts."""
    events, procs, skipped = [], [], collections.Counter()
    last_conn = {}
    for line in open(path, encoding="utf-8"):
        e = json.loads(line)
        ch, eid, h, t = e.get("Channel"), e.get("EventID"), short_host(e), when(e)
        label = "attack" if act.is_attack(e) else "noise"
        if (ch or "").lower() == "security" and eid == 4624:
            e["Channel"] = "Security"
            label = "attack" if act.is_attack(e) else "noise"
            user, lt = short_user(e.get("TargetUserName")), str(e.get("LogonType"))
            if user.endswith("$") or e.get("TargetUserName") in SKIP_USERS or user.startswith(("dwm-", "umfd-")):
                continue
            if user not in people:
                skipped["logon by an account outside the network"] += 1
            elif lt == "3" and act.ip_host.get(e.get("IpAddress")) not in (None, h):
                events.append({"src": act.ip_host[e["IpAddress"]], "type": "RemoteLogon", "dst": h, "user": user, "time": t,
                               "source_tool": "Windows Security", "scenario": label})
            elif lt in LOGON_INTERACTIVE:
                events.append({"src": user, "type": "LoggedInto", "dst": h, "time": t, "source_tool": "Windows Security",
                               "scenario": label})
            else:
                skipped["network logon with no known source machine"] += 1
        elif ch == SY and eid == 3 and str(e.get("Initiated")).lower() == "true":
            dst = act.ip_host.get(e.get("DestinationIp"))
            if dst is None or dst == h:
                skipped["connection to an address outside the lab machines"] += 1
                continue
            key = (h, dst, str(e.get("DestinationPort")), label)
            if key in last_conn and last_conn[key] >= t[:16]:
                continue  # one connection per machine pair, port and minute
            last_conn[key] = t[:16]
            events.append({"src": h, "type": "ConnectedTo", "dst": dst, "port": e.get("DestinationPort"),
                           "protocol": e.get("Protocol"), "time": t, "source_tool": "Sysmon", "scenario": label})
        elif ch == SY and eid == 1 and h in hosts:
            if not base(e.get("Image")):
                skipped["process start cut short in the recording"] += 1
                continue
            user = short_user(e.get("User"))
            procs.append({"time": t, "host": h, "process": base(e.get("Image")), "parent": base(e.get("ParentImage")),
                          "user": user if user in people else None, "source_tool": "Sysmon", "scenario": label})
    events.sort(key=lambda x: x["time"])
    procs.sort(key=lambda x: x["time"])
    return events, procs, skipped


def main(path, release_zip, release):
    base_day = json.loads((ROOT / "data" / "scenarios" / "apt29_day1.json").read_text(encoding="utf-8"))
    network = base_day["network"]
    hosts = {n["id"] for n in network["nodes"] if n["label"] == "Computer"}
    people = {n["id"] for n in network["nodes"] if n["label"] == "User"}
    act = Activity(path)
    fd, tmp = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    db = sqlite3.connect(tmp)
    try:
        columns = load(path, db)
        rule_list, failed = rules(release_zip, release)
        found, no_field = alerts(db, columns, rule_list, act, people)
    finally:
        db.close()
        os.remove(tmp)
    events, procs, skipped = activity(path, act, hosts, people)
    print(f"{len(rule_list)} rules converted, {failed} could not be converted, {no_field} queries read fields this "
          f"recording lacks; {len(found)} alerts, {len(events)} events, {len(procs)} process starts; skipped "
          f"{dict(skipped)}", file=sys.stderr)
    return {
        "name": "APT29 day 1, Sigma rules (real lab recording)",
        "description": "Real Windows, Sysmon and PowerShell logs of MITRE's APT29 emulation, from OTRF Security Datasets "
                       "(MIT licence). Alerts are public SigmaHQ rules matched on the real events; each keeps its rule's "
                       "author and link (Detection Rule License 1.1). The day's real logons, process starts and "
                       "connections stream through the Kafka topics. Attack or noise labels are ours, from the attacker's "
                       "process trees, and are used only to score the ranking.",
        "source": "https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29/day1",
        "rules": {"source": "SigmaHQ", "release": release, "package": "sigma_core+", "scope": "rules/windows",
                  "licence": "Detection Rule License 1.1", "licence_url": "https://github.com/SigmaHQ/Detection-Rule-License"},
        "network": network, "events": events, "process_starts": procs, "alerts": found,
    }


if __name__ == "__main__":
    print(json.dumps(main(sys.argv[1], sys.argv[2], sys.argv[3]), indent=1, ensure_ascii=False))
