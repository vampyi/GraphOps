"""the edges an attacker can follow, with the MITRE ATT&CK tag and crossing likelihood of each.

this is the table from docs/schema.md kept in code, so the ranker, the exposure analysis, the api and the
dashboard all read one source. `p` is our starting estimate of how likely an attacker who controls the source
can use the edge. it is a design choice, not a measurement. path search uses the cost -log(p), so the
cheapest path is the most likely one."""
import math

# in the direction the edge is stored. HasSession points from a computer to the user whose credentials may
# be on it, so an attacker who controls the computer gains that user: the stored direction is the attack direction.
EDGES = {
    "MemberOf":    {"p": 1.0, "tactic": None,     "technique": None,        "step": "is a member of"},
    "AdminTo":     {"p": 0.9, "tactic": "TA0008", "technique": "T1021",     "step": "has admin rights on"},
    "GenericAll":  {"p": 0.9, "tactic": "TA0003", "technique": "T1098",     "step": "has full control of"},
    "RemoteLogon": {"p": 0.8, "tactic": "TA0008", "technique": "T1021",     "step": "has logged on to"},
    "CanRDP":      {"p": 0.7, "tactic": "TA0008", "technique": "T1021.001", "step": "can remote desktop to"},
    "HasSession":  {"p": 0.6, "tactic": "TA0006", "technique": "T1003",     "step": "holds a session of"},
    # internet entry, cloud, hybrid and ai agent steps. p values are our design estimates, like those above.
    "CanExploit":  {"p": 0.9, "tactic": "TA0001", "technique": "T1190",     "step": "can exploit"},
    "SyncedTo":    {"p": 0.8, "tactic": "TA0008", "technique": "T1078.004", "step": "is synced to the cloud account"},
    "Owns":        {"p": 0.9, "tactic": "TA0003", "technique": "T1098.001", "step": "owns"},
    "RunsAs":      {"p": 1.0, "tactic": None,     "technique": None,        "step": "runs as"},
    "RoleOn":      {"p": 0.9, "tactic": "TA0006", "technique": "T1555.006", "step": "holds a role on"},
    "CanEmail":    {"p": 1.0, "tactic": "TA0001", "technique": "T1566",     "step": "can send email to"},
    "FeedsUntrustedInput": {"p": 0.5, "tactic": "AML.TA0005", "technique": "AML.T0051.001", "step": "feeds untrusted input to"},
    "CanPrompt":   {"p": 0.7, "tactic": "AML.TA0005", "technique": "AML.T0051.000", "step": "can prompt"},
    "HasToolAccess": {"p": 0.9, "tactic": None,   "technique": None,        "step": "can call the tool"},
    "CanAccess":   {"p": 0.9, "tactic": "TA0002", "technique": "T1059.001", "step": "can run commands on"},
    # a real ai agent on a laptop (sources.py): the folders it works in, the secret files there, the services
    # their keys open, and the accounts the agent is signed in to
    "CanRead":     {"p": 1.0, "tactic": "TA0009", "technique": "T1005",     "step": "can read files in"},
    "Contains":    {"p": 1.0, "tactic": None,     "technique": None,        "step": "contains"},
    "HoldsKeyFor": {"p": 0.9, "tactic": "TA0006", "technique": "T1552.001", "step": "holds credentials for"},
    "SignedInTo":  {"p": 0.9, "tactic": "TA0001", "technique": "T1078.004", "step": "is signed in to"},
}
ATTACK_EDGES = list(EDGES)

# granted = a permission someone holds. observed = something the logs saw happen. a session is an observation
# (who was signed in when the snapshot was taken), not a right, even though network.json lists it with the grants.
GRANTED_EDGES = ["MemberOf", "AdminTo", "CanRDP", "GenericAll", "SyncedTo", "Owns", "RunsAs", "RoleOn",
                 "CanPrompt", "HasToolAccess", "CanAccess", "CanRead", "SignedInTo"]
USED_EDGES = ["LoggedInto", "RemoteLogon", "InvokedTool", "UsedAccess"]

# mitre att&ck enterprise names, checked on attack.mitre.org. the dashboard copy in frontend/src/tactics.js matches.
TACTICS = {
    "TA0043": "Reconnaissance", "TA0042": "Resource Development", "TA0001": "Initial Access",
    "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Stealth", "TA0112": "Defense Impairment", "TA0006": "Credential Access",
    "TA0007": "Discovery", "TA0008": "Lateral Movement", "TA0009": "Collection",
    "TA0011": "Command and Control", "TA0010": "Exfiltration", "TA0040": "Impact",
    # mitre atlas (ai systems), checked in atlas-data 5.6.0
    "AML.TA0005": "Execution (ATLAS)",
}
TECHNIQUES = {
    "T1003": "OS Credential Dumping", "T1021": "Remote Services", "T1021.001": "Remote Desktop Protocol",
    "T1046": "Network Service Discovery", "T1053": "Scheduled Task/Job", "T1059": "Command and Scripting Interpreter",
    "T1078": "Valid Accounts", "T1098": "Account Manipulation", "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force", "T1189": "Drive-by Compromise", "T1204": "User Execution",
    "T1550.002": "Pass the Hash", "T1566": "Phishing",
    "T1136.001": "Create Account: Local Account", "T1571": "Non-Standard Port", "T1686": "Disable or Modify System Firewall",
    "T1176": "Browser Extensions", "T1133": "External Remote Services", "T1195": "Supply Chain Compromise",
    "T1190": "Exploit Public-Facing Application", "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1098.001": "Additional Cloud Credentials", "T1555.006": "Cloud Secrets Management Stores",
    "T1059.001": "PowerShell", "T1005": "Data from Local System",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "AML.T0051.000": "LLM Prompt Injection: Direct", "AML.T0051.001": "LLM Prompt Injection: Indirect",
}


def cost(edge_type):
    """path cost of one edge: -log(p), plus a hair so that among equally likely routes the shorter one wins."""
    return -math.log(EDGES[edge_type]["p"]) + 1e-6


def tag(edge_type):
    """the att&ck tactic and technique an edge represents, with names, for a path that reads as a kill chain."""
    e = EDGES.get(edge_type, {})
    return {"type": edge_type, "step": e.get("step", edge_type), "p": e.get("p"),
            "tactic": e.get("tactic"), "tactic_name": TACTICS.get(e.get("tactic")),
            "technique": e.get("technique"), "technique_name": TECHNIQUES.get(e.get("technique"))}


def describe_removal(src, edge_type, dst):
    """the fix, in the words an analyst would file a ticket with."""
    if edge_type == "MemberOf":
        return f"Remove {src} from the group {dst}"
    if edge_type == "AdminTo":
        return f"Remove {src}'s admin rights on {dst}"
    if edge_type == "CanRDP":
        return f"Remove {src}'s remote desktop right on {dst}"
    if edge_type == "GenericAll":
        return f"Remove {src}'s full control of {dst}"
    if edge_type == "HasSession":
        return f"Keep {dst} from signing in on {src} (its credentials sit there)"
    if edge_type == "RemoteLogon":
        return f"Block logons from {src} to {dst} (a route in use)"
    fixes = {
        "ExposedTo": f"Take {dst} off the internet or put it behind a VPN or web application firewall",
        "CanExploit": f"Patch the vulnerable software on {dst}",
        "SyncedTo": f"Stop syncing {src}'s password to the cloud account {dst}, or require MFA for it",
        "Owns": f"Remove {src} as an owner of {dst}",
        "RunsAs": f"Give {src} its own identity with only the permissions it needs, instead of {dst}",
        "RoleOn": f"Remove {src}'s role on {dst}",
        "CanEmail": f"Filter outside email reaching {dst}",
        "FeedsUntrustedInput": f"Stop passing untrusted content from {src} to {dst}, or require human approval before it acts",
        "CanPrompt": f"Limit who in {src} can instruct {dst}",
        "HasToolAccess": f"Remove the tool {dst} from {src}, or require human approval for each call",
        "CanAccess": f"Restrict what the tool {src} can run on {dst}",
        "CanRead": f"Narrow {src}'s working folders so {dst} is outside them",
        "Contains": f"Move {dst} out of {src}, into a secrets manager",
        "HoldsKeyFor": f"Rotate the key in {src} and keep {dst}'s credentials in a secrets manager instead of a file",
        "SignedInTo": f"Sign {src} out of {dst}, or give it a token limited to what it needs",
    }
    return fixes.get(edge_type, f"Remove {src} -{edge_type}-> {dst}")
