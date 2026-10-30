"""responding to a confirmed incident: who to tell, what to contain, the CERT-In clock and a report draft, and a
real email to the people who need to act.

who to tell comes from the graph: the accounts in the incident, the owners of its machines, and the owners of the
critical assets it can reach. the containment steps come from the same picture: isolate the machines, reset the
accounts, cut the first steps of the attack path. GraphOps does not control an EDR or a directory, so each step is
recorded as requested by the analyst, with a time, not claimed as done.

emails go through gmail smtp with an app password (SMTP_USER, SMTP_APP_PASSWORD), only to the people listed in
NOTIFY_CONTACTS, never to an address typed into the page, and with a small cap, because the demo site is public.
CERT-In: incidents must be reported within 6 hours of noticing them (CERT-In Directions, 28 April 2022). the draft
follows the fields of CERT-In's Incident Reporting Form."""
import datetime as dt
import json
import os
import smtplib
from email.message import EmailMessage

from .attack import describe_removal
from .report import entry_line, entry_point, gather

CERT_IN_HOURS = 6
MAX_EMAILS_PER_INCIDENT = 5


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def contacts():
    """the people this deployment may email, from NOTIFY_CONTACTS: [{"name": ..., "email": ..., "role": ...}]."""
    try:
        return [c for c in json.loads(os.environ.get("NOTIFY_CONTACTS") or "[]") if c.get("email") and c.get("name")]
    except ValueError:
        return []


def _mask(email):
    user, _, domain = email.partition("@")
    return f"{user[:2]}…@{domain}"


def _state(session, incident_id):
    r = session.run("MATCH (i:Incident {id: $id}) RETURN i.response AS r", id=incident_id).single()
    if r is None:
        return None
    return json.loads(r["r"]) if r["r"] else {"confirmed_at": None, "actions": {}, "emails": []}


def _save(session, incident_id, state):
    session.run("MATCH (i:Incident {id: $id}) SET i.response = $r", id=incident_id, r=json.dumps(state))


def plan(session, incident_id):
    data = gather(session, incident_id)
    state = _state(session, incident_id)
    if data is None or state is None:
        return None
    ids = [e["id"] for e in data["entities"]]
    owners = {r["id"]: r for r in session.run(
        "MATCH (e) WHERE e.id IN $ids RETURN e.id AS id, e.owner AS owner, coalesce(e.is_service_account, false) AS svc",
        ids=ids)}
    notify, steps = [], []
    for e in data["entities"]:
        if e["kind"] == "User":
            notify.append({"who": e["id"], "why": "their account appears in the incident"})
            fix = ("Rotate the service account's password and check what uses it" if owners[e["id"]]["svc"]
                   else "Disable sign-in, reset the password and revoke sessions")
            steps.append({"id": f"reset:{e['id']}", "text": f"{fix}: {e['id']}"})
        elif e["kind"] == "Computer":
            if owners[e["id"]]["owner"]:
                notify.append({"who": owners[e["id"]]["owner"], "why": f"owns {e['id']}"})
            steps.append({"id": f"isolate:{e['id']}",
                          "text": f"{'Restrict network access to' if e['critical'] else 'Isolate'} {e['id']} (EDR network containment)"})
    path = data["attack_path"]
    if path:
        target = path["nodes"][-1]
        owner = session.run("MATCH (c {id: $id}) RETURN c.owner AS o", id=target).single()
        notify.append({"who": (owner and owner["o"]) or f"owner of {target}",
                       "why": f"{target} (critical) is {len(path['types'])} step{'s' if len(path['types']) > 1 else ''} from this incident"})
        for a, t, b in list(zip(path["nodes"], path["types"], path["nodes"][1:]))[:2]:
            steps.append({"id": f"cut:{a}>{b}", "text": describe_removal(a, t, b)})
    seen, unique = set(), []
    for n in notify:
        if n["who"] not in seen:
            seen.add(n["who"])
            unique.append(n)
    deadline = None
    if state["confirmed_at"]:
        deadline = (dt.datetime.fromisoformat(state["confirmed_at"]) + dt.timedelta(hours=CERT_IN_HOURS)).isoformat()
    return {
        "incident": incident_id, "entry": entry_line(entry_point(data["alerts"])),
        "notify": unique, "steps": [{**s, "requested_at": state["actions"].get(s["id"])} for s in steps],
        "confirmed_at": state["confirmed_at"], "cert_in_deadline": deadline,
        "contacts": [{"name": c["name"], "role": c.get("role"), "email": _mask(c["email"])} for c in contacts()],
        "email_ready": bool(os.environ.get("SMTP_USER") and os.environ.get("SMTP_APP_PASSWORD") and contacts()),
        "emails": state["emails"],
    }


def confirm(session, incident_id):
    state = _state(session, incident_id)
    if state is None:
        return None
    state["confirmed_at"] = state["confirmed_at"] or _now()
    _save(session, incident_id, state)
    return state


def request_step(session, incident_id, step_id, on=True):
    state = _state(session, incident_id)
    if state is None:
        return None
    if on:
        state["actions"][step_id] = _now()
    else:
        state["actions"].pop(step_id, None)
    _save(session, incident_id, state)
    return state


def cert_in_draft(session, incident_id):
    """a draft in the order of CERT-In's Incident Reporting Form. fields GraphOps cannot know are left to fill."""
    p = plan(session, incident_id)
    data = gather(session, incident_id)
    if p is None:
        return None
    alerts = data["alerts"]
    first, crit = alerts[0], [e["id"] for e in data["entities"] if e["critical"]]
    fmt = lambda t: dt.datetime.fromisoformat(t[:19]).strftime("%d/%m/%Y %H:%M")
    hosts = [e["id"] for e in data["entities"] if e["kind"] == "Computer"]
    lines = [
        f"# CERT-In incident report (draft) - {incident_id}", "",
        "Draft prepared by GraphOps from the incident's alerts and graph. Check every field before sending to "
        "incident@cert-in.org.in. Follows the fields of CERT-In's Incident Reporting Form.", "",
        "## Contact information of the reporter", "- Name & role/title: (fill in)", "- Organisation: (fill in)",
        "- Contact no. / email / address: (fill in)", "",
        "## Basic incident details",
        "- Incident type: Unauthorised access of IT systems/data (check the form's list; add others that apply)",
        f"- Is the affected system critical to the organisation's mission? {'Yes: ' + ', '.join(crit) if crit else 'Not directly; see reach below'}",
        "", "## Basic information of affected system",
        f"- Affected systems: {', '.join(hosts) or 'see below'}", "- Domain/URL, IP address, operating system, location, ISP: (fill in from CMDB)",
        "", "## Brief description of incident",
        f"- How it started: {p['entry']}",
        f"- {len(alerts)} linked alerts from {', '.join(sorted({a['source_tool'] for a in alerts if a['source_tool']}))}.",
        *[f"  - {a['time'][11:16]} {a['name']} on {', '.join(a['involves'])}" for a in alerts],
        f"- Occurrence date & time: {fmt(first['time'])} (first alert)",
        f"- Detection date & time: {fmt(p['confirmed_at']) if p['confirmed_at'] else '(when confirmed)'}",
        "", "## Actions taken",
        *([f"- {s['text']} (requested {s['requested_at'][11:16]} UTC)" for s in p["steps"] if s["requested_at"]] or ["- (none recorded yet)"]),
    ]
    return {"incident": incident_id, "markdown": "\n".join(lines) + "\n", "deadline": p["cert_in_deadline"]}


def send_email(session, incident_id, names, site_url=""):
    """email the chosen contacts about the incident. returns the names it was sent to."""
    state = _state(session, incident_id)
    p = plan(session, incident_id)
    if state is None or p is None:
        return None
    people = [c for c in contacts() if c["name"] in names]
    if not people:
        raise ValueError("choose at least one listed contact")
    if len(state["emails"]) + len(people) > MAX_EMAILS_PER_INCIDENT:
        raise ValueError(f"at most {MAX_EMAILS_PER_INCIDENT} emails per incident on the demo")
    msg = EmailMessage()
    msg["Subject"] = f"[GraphOps] Security incident {incident_id}: action needed"
    msg["From"] = os.environ["SMTP_USER"]
    msg["To"] = ", ".join(c["email"] for c in people)
    body = [
        f"GraphOps has a confirmed security incident, {incident_id}.", "",
        f"How it started: {p['entry']}", "",
        "Who is involved:", *[f"- {n['who']}: {n['why']}" for n in p["notify"]], "",
        "Containment steps:", *[f"- [{'requested' if s['requested_at'] else ' '}] {s['text']}" for s in p["steps"]], "",
    ]
    if p["cert_in_deadline"]:
        body.append(f"CERT-In report due by {p['cert_in_deadline'][:16].replace('T', ' ')} UTC (6 hours from confirmation).")
    if site_url:
        body += ["", f"Open in GraphOps: {site_url}"]
    body += ["", "This is a demo of GraphOps (hackFront India 2026) on a fictional organisation."]
    msg.set_content("\n".join(body))
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as smtp:
        smtp.login(os.environ["SMTP_USER"], os.environ["SMTP_APP_PASSWORD"])
        smtp.send_message(msg)
    state["emails"] += [{"to": c["name"], "at": _now()} for c in people]
    _save(session, incident_id, state)
    return [c["name"] for c in people]
