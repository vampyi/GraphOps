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
}
ATTACK_EDGES = list(EDGES)

# granted = a permission someone holds. observed = something the logs saw happen. a session is an observation
# (who was signed in when the snapshot was taken), not a right, even though network.json lists it with the grants.
GRANTED_EDGES = ["MemberOf", "AdminTo", "CanRDP", "GenericAll"]
USED_EDGES = ["LoggedInto", "RemoteLogon"]

# mitre att&ck enterprise names, checked on attack.mitre.org. the dashboard copy in frontend/src/tactics.js matches.
TACTICS = {
    "TA0043": "Reconnaissance", "TA0042": "Resource Development", "TA0001": "Initial Access",
    "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion", "TA0112": "Defense Impairment", "TA0006": "Credential Access",
    "TA0007": "Discovery", "TA0008": "Lateral Movement", "TA0009": "Collection",
    "TA0011": "Command and Control", "TA0010": "Exfiltration", "TA0040": "Impact",
}
TECHNIQUES = {
    "T1003": "OS Credential Dumping", "T1021": "Remote Services", "T1021.001": "Remote Desktop Protocol",
    "T1046": "Network Service Discovery", "T1053": "Scheduled Task/Job", "T1059": "Command and Scripting Interpreter",
    "T1078": "Valid Accounts", "T1098": "Account Manipulation", "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force", "T1189": "Drive-by Compromise", "T1204": "User Execution",
    "T1550.002": "Pass the Hash", "T1566": "Phishing",
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
    return f"Remove {src} -{edge_type}-> {dst}"
