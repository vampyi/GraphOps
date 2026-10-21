"""load a BloodHound / SharpHound collection into GraphOps' schema.

    python -m app.import_bloodhound <dir-or-zip>

BloodHound is the tool most security teams already use to map Active Directory. Reading its collection means a
team can point GraphOps at a graph they already trust. We read the BloodHound Community Edition JSON shape: one
file per object type (users, groups, computers, domains), each `{"data": [ ... ], "meta": {"type": ...}}`.

This is a pragmatic subset, not a full BloodHound loader. We take the relationships that make attack paths:
group membership, local admin rights, remote-desktop rights, sessions and GenericAll. Objects are keyed by
their SID inside the file and given a readable id (the name, lower-cased, domain dropped) in our graph, with the
SID kept as a property. Tier Zero (high-value) groups and computers are marked critical."""
import json
import sys
import zipfile
from pathlib import Path

from .attack import GRANTED_EDGES
from .db import driver
from .seed import counts, load_network_data

# bloodhound marks the most sensitive objects high-value. we also treat these well-known Tier Zero groups as
# critical by name, because a collection does not always set high-value.
TIER_ZERO = {"DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS", "DOMAIN CONTROLLERS",
             "SCHEMA ADMINS", "KEY ADMINS", "ENTERPRISE KEY ADMINS", "BACKUP OPERATORS"}


def _short(name, sid, strip_dns=False):
    """a readable id: the name, lower-cased, with the domain dropped. falls back to the SID. computers are
    FQDNs (HOST.DOMAIN.TLD), so their dns domain is dropped; users and groups keep dots (john.doe stays whole)."""
    if not name:
        return sid
    name = str(name).split("@")[0].split("\\")[-1].strip()
    if strip_dns and "." in name:
        name = name.split(".")[0]
    return name.lower() if name else sid


def _results(block):
    """BloodHound wraps related lists as {"Results": [...], "Collected": bool}; older files use a bare list."""
    if isinstance(block, dict):
        return block.get("Results") or []
    return block or []


def read_collection(path):
    """read every BloodHound json file in a directory or zip. returns {type: [objects]}."""
    path = Path(path)
    out = {}

    def add(raw):
        doc = json.loads(raw)
        meta = doc.get("meta", {})
        kind = meta.get("type") or _guess_type(doc)
        out.setdefault(kind, []).extend(doc.get("data", []))

    if path.is_dir():
        for f in sorted(path.glob("*.json")):
            add(f.read_text(encoding="utf-8"))
    elif path.suffix == ".zip":
        with zipfile.ZipFile(path) as z:
            for name in sorted(z.namelist()):
                if name.endswith(".json"):
                    add(z.read(name).decode("utf-8"))
    else:
        add(path.read_text(encoding="utf-8"))
    return out


def _guess_type(doc):
    data = doc.get("data") or []
    if not data:
        return "unknown"
    labels = (data[0].get("Properties", {}).get("name") or "")
    return "unknown"


def to_network(collection):
    """turn a BloodHound collection into GraphOps' {nodes, granted, observed} network dict."""
    sid_to_id, nodes = {}, []
    sessions, members, admins, rdp, genericall = [], [], [], [], []

    def register(obj, label):
        props = obj.get("Properties", {}) or {}
        sid = obj.get("ObjectIdentifier") or props.get("objectid")
        name = props.get("name")
        nid = _short(name, sid, strip_dns=(label == "Computer"))
        sid_to_id[sid] = nid
        node = {"id": nid, "label": label, "name": (name or nid)}
        high = bool(props.get("highvalue") or props.get("system_tags") == "admin_tier_0")
        if label == "Group" and str(name or "").split("@")[0].upper() in TIER_ZERO:
            high = True
        if label == "Computer":
            node["os"] = props.get("operatingsystem")
            node["zone"] = "normal"
            node["critical"] = high or bool(props.get("isdc"))
        elif label == "Group":
            node["critical"] = high
        else:  # User
            node["is_service_account"] = bool(props.get("serviceprincipalnames"))
        return node

    for kind, label in (("users", "User"), ("groups", "Group"), ("computers", "Computer")):
        for obj in collection.get(kind, []):
            nodes.append(register(obj, label))

    # second pass: relationships, now that every SID has an id
    def rid(sid):
        return sid_to_id.get(sid)

    for obj in collection.get("groups", []):
        gid = rid(obj.get("ObjectIdentifier") or obj.get("Properties", {}).get("objectid"))
        for m in _results(obj.get("Members")):
            src = rid(m.get("ObjectIdentifier"))
            if src and gid:
                members.append({"src": src, "type": "MemberOf", "dst": gid})
    for obj in collection.get("computers", []):
        cid = rid(obj.get("ObjectIdentifier") or obj.get("Properties", {}).get("objectid"))
        for s in _results(obj.get("Sessions")):
            uid = rid(s.get("UserSID") or s.get("ObjectIdentifier"))
            if uid and cid:
                sessions.append({"src": cid, "type": "HasSession", "dst": uid})
        for a in _results(obj.get("LocalAdmins")):
            pid = rid(a.get("ObjectIdentifier"))
            if pid and cid:
                admins.append({"src": pid, "type": "AdminTo", "dst": cid})
        for r in _results(obj.get("RemoteDesktopUsers")):
            pid = rid(r.get("ObjectIdentifier"))
            if pid and cid:
                rdp.append({"src": pid, "type": "CanRDP", "dst": cid})
    for kind in ("users", "groups", "computers"):
        for obj in collection.get(kind, []):
            oid = rid(obj.get("ObjectIdentifier") or obj.get("Properties", {}).get("objectid"))
            for ace in _results(obj.get("Aces")):
                if ace.get("RightName") in ("GenericAll", "Owns") and rid(ace.get("PrincipalSID")) and oid:
                    genericall.append({"src": rid(ace["PrincipalSID"]), "type": "GenericAll", "dst": oid})

    granted = members + admins + rdp + genericall
    granted = [e for e in granted if e["type"] in GRANTED_EDGES] + sessions  # HasSession stored with grants
    return {"nodes": nodes, "granted": granted, "observed": []}


def load_sharphound(session, path):
    """read a BloodHound collection and load it as the GraphOps network (replacing what is there)."""
    network = to_network(read_collection(path))
    load_network_data(session, network)
    return counts(session)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m app.import_bloodhound <dir-or-zip>")
    with driver() as d, d.session() as s:
        result = load_sharphound(s, sys.argv[1])
        from .analysis import run_all
        run_all(s)
    print(json.dumps(result))
