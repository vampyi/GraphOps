# Graph schema

Draft for team review. This is the shared blueprint every program reads and writes. Change it here first, then in code.

## Naming rules

- **Node labels and edge types use the same names as BloodHound and ADSynth** (`User`, `Computer`, `MemberOf`, `AdminTo`). ADSynth output then loads without renaming, and anyone who knows BloodHound can read our graph.
- Labels and edge types are written in PascalCase: `Computer`, `LoggedInto`.
- Properties are written in snake_case: `first_seen`, `hops_to_critical`.
- Every node has a unique `id` string.

## The three families of edges

The shrinking circle feature only works if these stay separate.

| Family | Meaning | Comes from |
|---|---|---|
| **Granted** | What someone is allowed to do | ADSynth (permissions and group memberships) |
| **Observed** | What someone actually did | Telemetry (logins, network connections, processes) |
| **Alert** | What a security tool flagged | Alerts |

## Nodes

| Label | What it is | Key properties | Source |
|---|---|---|---|
| `User` | A person or service account | `id`, `name`, `enabled`, `is_service_account` | ADSynth, LANL |
| `Computer` | A laptop, server or virtual machine | `id`, `name`, `os`, `owner`, `critical`, `zone` | ADSynth, LANL, CMDB |
| `Group` | A set of users or computers | `id`, `name`, `critical` | ADSynth |
| `Domain` | An Active Directory domain | `id`, `name` | ADSynth |
| `OU` | An organisational unit, a folder of AD objects | `id`, `name` | ADSynth |
| `Application` | A business application | `id`, `name`, `critical` | CMDB |
| `Process` | A program that ran on a computer | `id`, `name` | EDR, LANL |
| `Vulnerability` | A known weakness | `id` (the CVE ID), `cvss` | CMDB or scanner |
| `Alert` | One alert from a security tool | see Alert properties below | Alerts |
| `Incident` | A group of linked alerts | `id`, `opened_at`, `score`, `stage_order` | Alert ranker |

Cloud and hybrid nodes (cloud users, service principals, sync servers) keep the labels ADSynth gives them.

### Properties written by the background graph analysis

Stored on `User`, `Computer` and `Group` nodes. Refreshed every 5 minutes.

| Property | Meaning |
|---|---|
| `hops_to_critical` | Fewest steps to the nearest critical node |
| `choke_score` | How many attack paths pass through this node |
| `community` | The ID of the group of machines it normally works with |

### Alert properties

| Property | Meaning |
|---|---|
| `id` | Unique alert ID |
| `time` | When it fired |
| `source_tool` | Which tool raised it, such as EDR or SIEM |
| `name` | Short description, such as "suspicious login" |
| `severity` | low, medium, high or critical, as the tool reported it |
| `tactic_id` | MITRE ATT&CK tactic, such as `TA0008` |
| `technique_id` | MITRE ATT&CK technique, such as `T1021` |
| `score` | Our rank score, written by the alert ranker |
| `reasons` | The ranking questions that pushed the score up |
| `status` | new, real or false, set by the analyst |

## Edges

### Granted edges

From ADSynth, using BloodHound's names.

| Edge | Meaning |
|---|---|
| `(User\|Computer\|Group)-[:MemberOf]->(Group)` | Is a member of the group |
| `(User\|Group)-[:AdminTo]->(Computer)` | Has admin rights on the computer |
| `(User\|Group)-[:CanRDP]->(Computer)` | Is allowed to log in by Remote Desktop |
| `(User\|Group)-[:GenericAll]->(User\|Group\|Computer)` | Has full control over the object |
| `(Computer)-[:HasSession]->(User)` | The user was logged in when the snapshot was taken, so their credentials may be on that computer |
| `(Domain\|OU)-[:Contains]->(OU\|User\|Computer\|Group)` | Folder structure. Not used for attack paths |

ADSynth generates more permission edges than these. We keep all of them and decide during week 2 which ones count for attack paths.

### Observed edges

From telemetry. Every observed edge has these properties:

| Property | Meaning |
|---|---|
| `first_seen` | First time this exact connection happened |
| `last_seen` | Most recent time |
| `count` | How many times it happened |

`first_seen` is what makes never-taken path detection possible.

| Edge | Meaning | Extra properties | Source |
|---|---|---|---|
| `(User)-[:LoggedInto]->(Computer)` | The user logged into the computer | `logon_type`, `auth_type` | LANL `auth`, identity logs |
| `(Computer)-[:RemoteLogon]->(Computer)` | Someone used an account to log in from one computer to another. This is one hop of lateral movement. | `user`, `logon_type`, `auth_type` | LANL `auth` where source and destination computers differ |
| `(Computer)-[:ConnectedTo]->(Computer)` | The two computers exchanged network traffic | `port`, `protocol`, `bytes` | LANL `flows`, network flow logs |
| `(Computer)-[:Ran]->(Process)` | A program ran on the computer | `user` | LANL `proc`, EDR |

### Alert edges

| Edge | Meaning |
|---|---|
| `(Alert)-[:Involves]->(User\|Computer\|Process)` | The alert is about this entity |
| `(Alert)-[:PartOf]->(Incident)` | The alert ranker linked it into this incident |

### Other edges

| Edge | Meaning | Source |
|---|---|---|
| `(Computer)-[:HasVulnerability]->(Vulnerability)` | The computer has this known weakness | CMDB or scanner |
| `(Application)-[:RunsOn]->(Computer)` | The application is hosted on this computer | CMDB |

## Granted vs used access

| | Built from |
|---|---|
| **Granted access** of a user | `MemberOf`, followed through nested groups, then `AdminTo`, `CanRDP` and `GenericAll` |
| **Used access** of a user | `LoggedInto` and `RemoteLogon` edges with `last_seen` inside the chosen window, for example the last 30 days |

The shrinking circle runs the same blast radius query twice: once over granted edges and once over used edges.

## Critical assets and zones

| Property | Values | How it is set |
|---|---|---|
| `critical` | true or false | Copied from ADSynth's `highvalue` flag, plus anything the CMDB marks as critical |
| `zone` | `low_trust` or `normal` | Set from the CMDB, for example guest Wi-Fi laptops and internet-facing machines are `low_trust` |

Which assets are critical is a team decision.

## Edge risk for attack paths

How easy each edge is for an attacker to cross. `p` is our starting guess at the chance an attacker can use the edge. Path search uses the cost `-log(p)`, so the cheapest path is the most likely one.

**These numbers are our design choice, not measured facts.** We tune them in week 2.

| Edge | Starting `p` | Reasoning |
|---|---|---|
| `MemberOf` | 1.0 | Membership is automatic. No effort needed. |
| `AdminTo` | 0.9 | Admin rights give direct control of the computer. |
| `GenericAll` | 0.9 | Full control over the object. |
| `CanRDP` | 0.7 | Login is allowed but still needs valid credentials. |
| `HasSession` | 0.6 | Credentials may be stolen from memory, but not always. |
| `RemoteLogon` | 0.8 | This route has already been used, so it works. |
| `ConnectedTo` | 0.3 | Network access alone does not give control. |
| `Contains` | not used | Folder structure, not an attack step. |

## MITRE ATT&CK tags

Our own lookup table. No standard mapping from BloodHound edges to ATT&CK exists, so we keep this one small and explain it. All IDs checked on [attack.mitre.org](https://attack.mitre.org).

| Edge or alert type | Tactic | Technique |
|---|---|---|
| Phishing alert | TA0001 Initial Access | T1566 Phishing |
| Script or command execution alert | TA0002 Execution | T1059 Command and Scripting Interpreter |
| `HasSession` used to steal credentials | TA0006 Credential Access | T1003 OS Credential Dumping |
| `RemoteLogon`, `AdminTo` | TA0008 Lateral Movement | T1021 Remote Services |
| `CanRDP` | TA0008 Lateral Movement | T1021.001 Remote Desktop Protocol |
| Login with a stolen password | TA0004 Privilege Escalation | T1078 Valid Accounts |
| Login with a stolen password hash | TA0008 Lateral Movement | T1550.002 Pass the Hash |
| `GenericAll` used to change an account | TA0003 Persistence | T1098 Account Manipulation |

The tactic order (Initial Access, Execution, Credential Access, Lateral Movement and so on) is what the alert ranker uses to check whether linked alerts follow attack stages.

## How each data source maps in

### LANL 2015

| LANL file | Line format | Becomes |
|---|---|---|
| `auth` | `time, source user@domain, destination user@domain, source computer, destination computer, auth type, logon type, orientation, success/failure` | `User` and `Computer` nodes, a `LoggedInto` edge, and a `RemoteLogon` edge when the two computers differ. Failed logins are kept as a property. |
| `flows` | `time, duration, source computer, source port, destination computer, destination port, protocol, packets, bytes` | `ConnectedTo` edge |
| `proc` | `time, user@domain, computer, process name, start/end` | `Process` node and `Ran` edge |
| `redteam` | `time, user@domain, source computer, destination computer` | Labels on the matching `RemoteLogon` edges, used only to measure detection. Never shown to the ranker. |

Accounts ending in `$`, such as `C625$`, are computer accounts that log in automatically. They are kept but flagged with `is_service_account = true` so noise filters can skip them.

### ADSynth

Loaded as-is from its Neo4j JSONL output. After loading we set `critical` from `highvalue`.

### CMDB

A CSV file with one row per machine or application: `id, name, owner, critical, zone, os`. Updates properties on existing `Computer` nodes and adds `Application` nodes.

## Example: the scripted attack in this schema

```cypher
// granted: the help desk group can administer server-7
(:User {id:"intern_a"})-[:MemberOf]->(:Group {id:"helpdesk"})
(:Group {id:"helpdesk"})-[:AdminTo]->(:Computer {id:"server-7"})

// observed: intern_a's laptop logs into server-7 for the first time
(:Computer {id:"laptop-42"})-[:RemoteLogon {user:"intern_a", first_seen:"2026-10-20T10:20:00"}]->(:Computer {id:"server-7"})

// alerts: two alerts on the same path
(:Alert {id:"a1", name:"phishing link clicked", tactic_id:"TA0001", technique_id:"T1566"})-[:Involves]->(:Computer {id:"laptop-42"})
(:Alert {id:"a2", name:"suspicious login", tactic_id:"TA0008", technique_id:"T1021"})-[:Involves]->(:Computer {id:"server-7"})

// linked by the alert ranker
(:Alert {id:"a1"})-[:PartOf]->(:Incident {id:"inc-1"})
(:Alert {id:"a2"})-[:PartOf]->(:Incident {id:"inc-1"})
```

## Open questions for the team

1. Which assets count as critical in our demo network?
2. Which machines are low-trust?
3. Which ADSynth permission edges beyond the ones above should count for attack paths?
4. How long is the "used access" window: 7, 30 or 90 days?
5. Are the starting edge risk values sensible?
