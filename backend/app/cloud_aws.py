"""a real AWS account in the graph: who exists in IAM, what each identity may do, and whether its credentials are
used, read live with a read-only key (the AWS-managed SecurityAudit policy).

GraphOps does not try to replace AWS's own tools for what happens inside AWS. it draws the account's identities into
the same graph as the company's laptops, servers and AI agents, so a path that starts outside AWS (an alerted laptop,
an AI agent that can read a credentials file) and ends in AWS shows up as one path.

two read-only calls, signed with AWS signature version 4 using the standard library only:
- IAM credential report: every user, console password and MFA, access keys and when each was last used, root MFA
  (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html)
- IAM GetAccountAuthorizationDetails: the policies of every user, group and role
the result is stored on a CloudSnapshot node that reloading a scenario does not wipe, and drawn back after every load.
keys used: GRAPHOPS_AWS_ACCESS_KEY_ID and GRAPHOPS_AWS_SECRET_ACCESS_KEY. not the plain AWS_* names: vercel runs
functions on aws lambda and may set those itself with values that are not usable credentials. no region is needed:
IAM is a global service, signed for us-east-1."""
import base64
import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

NS = {"i": "https://iam.amazonaws.com/doc/2010-05-08/"}
ADMIN = {"AdministratorAccess", "IAMFullAccess"}  # IAM full access can grant itself anything
READ = {"ReadOnlyAccess", "SecurityAudit", "ViewOnlyAccess"}
STALE_DAYS = 90


KEY_VAR, SECRET_VAR = "GRAPHOPS_AWS_ACCESS_KEY_ID", "GRAPHOPS_AWS_SECRET_ACCESS_KEY"


def configured():
    return bool(os.environ.get(KEY_VAR) and os.environ.get(SECRET_VAR))


def _signed_get(service, host, params, region="us-east-1"):
    """an AWS query-API GET, signed with signature version 4."""
    key, secret = os.environ[KEY_VAR], os.environ[SECRET_VAR]
    now = dt.datetime.now(dt.timezone.utc)
    amz_date, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    query = "&".join(f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(str(v), safe='-_.~')}"
                     for k, v in sorted(params.items()))
    headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    canonical = f"GET\n/\n{query}\n{headers}\nhost;x-amz-date\n{hashlib.sha256(b'').hexdigest()}"
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
    k = hmac.new(f"AWS4{secret}".encode(), day.encode(), hashlib.sha256).digest()
    for part in (region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    req = urllib.request.Request(f"https://{host}/?{query}", headers={
        "x-amz-date": amz_date,
        "Authorization": f"AWS4-HMAC-SHA256 Credential={key}/{scope}, SignedHeaders=host;x-amz-date, Signature={sig}"})
    with urllib.request.urlopen(req, timeout=20) as res:
        return ET.fromstring(res.read())


def _iam(action, **params):
    return _signed_get("iam", "iam.amazonaws.com", {"Action": action, "Version": "2010-05-08", **params})


def _text(el, path):
    x = el.find(path, NS)
    return x.text if x is not None else None


def _names(el, path):
    return [m.text for m in el.findall(path, NS)]


def account_id():
    root = _signed_get("sts", "sts.amazonaws.com", {"Action": "GetCallerIdentity", "Version": "2011-06-15"})
    return root.find(".//{https://sts.amazonaws.com/doc/2011-06-15/}Account").text


def credential_report():
    """rows of the IAM credential report. generating one can take a few seconds; AWS reuses a report up to 4 hours old."""
    _iam("GenerateCredentialReport")
    for _ in range(10):
        try:
            content = _text(_iam("GetCredentialReport"), ".//i:Content")
            return list(csv.DictReader(io.StringIO(base64.b64decode(content).decode())))
        except urllib.error.HTTPError as exc:
            if exc.code != 410 and b"ReportInProgress" not in exc.read():
                raise
            time.sleep(1.5)
    raise RuntimeError("the credential report was not ready in time")


def authorization_details():
    users, groups, roles, marker = {}, {}, {}, None
    while True:
        root = _iam("GetAccountAuthorizationDetails", **({"Marker": marker} if marker else {}))
        for u in root.findall(".//i:UserDetailList/i:member", NS):
            users[_text(u, "i:UserName")] = {
                "groups": _names(u, "i:GroupList/i:member"),
                "policies": _names(u, "i:AttachedManagedPolicies/i:member/i:PolicyName")
                            + _names(u, "i:UserPolicyList/i:member/i:PolicyName")}
        for g in root.findall(".//i:GroupDetailList/i:member", NS):
            groups[_text(g, "i:GroupName")] = {
                "policies": _names(g, "i:AttachedManagedPolicies/i:member/i:PolicyName")
                            + _names(g, "i:GroupPolicyList/i:member/i:PolicyName")}
        for r in root.findall(".//i:RoleDetailList/i:member", NS):
            if (_text(r, "i:Path") or "").startswith("/aws-service-role/"):
                continue  # roles AWS creates for its own services
            trust = json.loads(urllib.parse.unquote(_text(r, "i:AssumeRolePolicyDocument") or "{}"))
            principals = []
            for st in trust.get("Statement", []):
                for v in (st.get("Principal") or {}).values():
                    principals += v if isinstance(v, list) else [v]
            roles[_text(r, "i:RoleName")] = {
                "policies": _names(r, "i:AttachedManagedPolicies/i:member/i:PolicyName")
                            + _names(r, "i:RolePolicyList/i:member/i:PolicyName"),
                "trusted": principals}
        if _text(root, ".//i:IsTruncated") != "true":
            return users, groups, roles
        marker = _text(root, ".//i:Marker")


def level(policies):
    if ADMIN & set(policies):
        return "admin"
    if any(p.endswith("FullAccess") or p == "PowerUserAccess" for p in policies):
        return "write"
    if not policies:
        return "none"
    if all(p in READ or p.endswith("ReadOnlyAccess") for p in policies):
        return "read"
    return "custom"


def _date(v):
    return v if v and v[:2] == "20" else None


def fetch():
    """read the account live. returns the snapshot stored and drawn into the graph."""
    acct = account_id()
    report = credential_report()
    users, groups, roles = authorization_details()
    now = dt.datetime.now(dt.timezone.utc)
    identities = []
    for row in report:
        name = row["user"]
        is_root = name == "<root_account>"
        detail = users.get(name, {"groups": [], "policies": []})
        policies = detail["policies"] + [p for g in detail["groups"] for p in groups.get(g, {}).get("policies", [])]
        keys = []
        for n in ("1", "2"):
            if row.get(f"access_key_{n}_active") == "TRUE":
                keys.append({"created": _date(row.get(f"access_key_{n}_last_rotated")),
                             "last_used": _date(row.get(f"access_key_{n}_last_used_date")),
                             "service": row.get(f"access_key_{n}_last_used_service")})
        identities.append({
            "name": "root" if is_root else name, "kind": "root" if is_root else "user",
            "level": "admin" if is_root else level(policies), "policies": sorted(set(policies)),
            "groups": detail["groups"], "console": row.get("password_enabled") == "TRUE" or is_root,
            "password_last_used": _date(row.get("password_last_used")), "mfa": row.get("mfa_active") == "TRUE",
            "created": _date(row.get("user_creation_time")), "keys": keys,
        })
    for name, r in roles.items():
        identities.append({"name": name, "kind": "role", "level": level(r["policies"]),
                           "policies": sorted(set(r["policies"])), "trusted": r["trusted"], "keys": []})
    return {"account": acct[-4:], "fetched": now.isoformat(timespec="seconds"), "identities": identities}


def findings(snapshot):
    """what an analyst should look at, worst first. each one names the identity and the fix."""
    out = []
    now = dt.datetime.now(dt.timezone.utc)
    age = lambda d: (now - dt.datetime.fromisoformat(d.replace("Z", "+00:00"))).days if d else None
    for i in snapshot["identities"]:
        n = i["name"]
        if i["kind"] == "root":
            if not i["mfa"]:
                out.append({"severity": "critical", "who": n, "text": "Root account has no MFA", "fix": "Turn on MFA for the root user"})
            if i["keys"]:
                out.append({"severity": "critical", "who": n, "text": "Root account has an access key", "fix": "Delete the root access key"})
            continue
        if i["kind"] == "role":
            continue
        if i["console"] and not i["mfa"]:
            sev = "high" if i["level"] == "admin" else "medium"
            out.append({"severity": sev, "who": n, "text": f"{'Admin' if i['level'] == 'admin' else 'User'} can sign in to the console without MFA",
                        "fix": "Require MFA for this user"})
        for k in i["keys"]:
            if not k["last_used"]:
                out.append({"severity": "high" if i["level"] == "admin" else "medium", "who": n,
                            "text": f"Active access key never used{' (admin rights)' if i['level'] == 'admin' else ''}",
                            "fix": "Delete the key if nothing needs it"})
            elif age(k["last_used"]) and age(k["last_used"]) > STALE_DAYS:
                out.append({"severity": "medium", "who": n, "text": f"Access key unused for {age(k['last_used'])} days", "fix": "Deactivate the key"})
            if age(k["created"]) and age(k["created"]) > STALE_DAYS:
                out.append({"severity": "low", "who": n, "text": f"Access key is {age(k['created'])} days old", "fix": "Rotate the key"})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(out, key=lambda f: order[f["severity"]])


def save(session, snapshot):
    session.run("MERGE (c:CloudSnapshot {id: 'aws'}) SET c.data = $d", d=json.dumps(snapshot))
    apply(session)


def load_snapshot(session):
    r = session.run("MATCH (c:CloudSnapshot {id: 'aws'}) RETURN c.data AS d").single()
    return json.loads(r["d"]) if r and r["d"] else None


def apply(session):
    """draw the stored snapshot into the graph: the account, its identities, and what each may do in it."""
    snap = load_snapshot(session)
    session.run("MATCH (n:Entity {source: 'aws'}) DETACH DELETE n")
    if not snap:
        return
    acct = "aws:account"
    session.run("MERGE (a:CloudResource:Entity {id: $id}) SET a.name = $name, a.location = 'cloud', a.critical = true, "
                "a.resourcetype = 'aws_account', a.source = 'aws'", id=acct, name=f"AWS account …{snap['account']}")
    for i in snap["identities"]:
        label = "ServiceIdentity" if i["kind"] == "role" else "User"
        nid = f"aws:{i['kind']}/{i['name']}"
        last_used = max([k["last_used"] for k in i["keys"] if k["last_used"]] + [i.get("password_last_used") or ""]) or None
        session.run(
            f"MERGE (n:{label}:Entity {{id: $id}}) SET n.name = $name, n.location = 'cloud', n.source = 'aws', "
            "n.aws_kind = $kind, n.level = $level, n.policies = $policies, n.mfa = $mfa, n.console = $console, "
            "n.active_keys = $keys, n.last_used = $last_used",
            id=nid, name=i["name"], kind=i["kind"], level=i["level"], policies=i["policies"], mfa=i.get("mfa"),
            console=i.get("console"), keys=len(i["keys"]), last_used=last_used)
        edge = {"admin": "AdminOf", "write": "CanModify"}.get(i["level"], "HasReadAccess")
        session.run(f"MATCH (n {{id: $id}}), (a {{id: $acct}}) MERGE (n)-[r:{edge}]->(a) SET r.family = 'granted', "
                    "r.policies = $p", id=nid, acct=acct, p=i["policies"])
        if last_used:
            session.run("MATCH (n {id: $id}), (a {id: $acct}) MERGE (n)-[r:UsedAccess]->(a) SET r.family = 'observed', "
                        "r.last_seen = $t", id=nid, acct=acct, t=last_used)


def view(session):
    snap = load_snapshot(session)
    if not snap:
        return {"connected": False, "configured": configured()}
    return {"connected": True, "configured": configured(), "account": snap["account"], "fetched": snap["fetched"],
            "identities": snap["identities"], "findings": findings(snap)}
