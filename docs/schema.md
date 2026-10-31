# Graph schema

The shared blueprint every program reads and writes. Change it here first, then in code. Updated 31 October 2026 to match what is built; parts still planned are marked.

## Naming rules

- **Node labels and edge types use the same names as BloodHound** (`User`, `Computer`, `MemberOf`, `AdminTo`). Anyone who knows BloodHound can read our graph.
- Labels and edge types are written in PascalCase: `Computer`, `LoggedInto`.
- Properties are written in snake_case: `first_seen`, `hops_to_critical`.
- Every node has a unique `id` string.

## The three families of edges

The shrinking circle feature only works if these stay separate.

| Family | Meaning | Comes from |
|---|---|---|
| **Granted** | What someone is allowed to do | The sample network, a BloodHound import, real laptops (local admins) and the AI agent access scan |
| **Observed** | What someone actually did | Telemetry (logins, network connections, processes) |
| **Alert** | What a security tool flagged | Alerts |

## Nodes

| Label | What it is | Key properties | Source |
|---|---|---|---|
| `User` | A person or service account | `id`, `name`, `enabled`, `is_service_account` | Sample network, APT29 lab logs, BloodHound import, osquery laptops (`user-xxxx@<host>`) |
| `Computer` | A laptop, server or virtual machine | `id`, `name`, `os`, `owner`, `critical`, `zone` | Sample network, APT29 lab logs, osquery laptops (`<host>`), CMDB |
| `Group` | A set of users or computers | `id`, `name`, `critical` | Sample network, BloodHound import |
| `Domain` | An Active Directory domain (planned) | `id`, `name` | BloodHound import |
| `OU` | An organisational unit, a folder of AD objects (planned) | `id`, `name` | BloodHound import |
| `Application` | A business application | `id`, `name`, `critical` | CMDB |
| `Process` | A program that ran on a computer | `id`, `name` | EDR stream (the APT29 day's Sysmon process starts) |
| `Vulnerability` | A known weakness | `id` (the CVE ID), `cvss`, `kev`, `epss` | NIST NVD, CISA KEV and FIRST EPSS, for the software each machine runs (`vulns.py`) |
| `Alert` | One alert from a security tool | see Alert properties below | Alerts |
| `Incident` | A group of linked alerts | `id`, `opened_at`, `score`, `stage_order` | Alert ranker |

Cloud, AI and exposure nodes (`data/sample_org/cloud_ai.json` and the real sources):

| Label | What it is | Source |
|---|---|---|
| `AIAgent` | An AI agent, treated as an identity with access | Sample network (`finance-agent`, `support-agent`, illustrative); a real Claude Code agent |
| `Tool` | Something an agent can call: an MCP server, a shell, web fetch, a browser | Sample network; the agent access scan |
| `ServiceIdentity` | A cloud service principal an agent runs as | Sample network |
| `CloudResource` | A cloud resource or a service a key opens, such as a key vault, AWS or Neo4j AuraDB | Sample network; the agent access scan |
| `Software` | A product and version running on a machine, used to look up CVEs | Sample network |
| `Internet` | The open internet, the start of outside attack paths | Sample network |
| `Folder`, `Secret` | A folder an agent can read, and a secret file in it (by name only) | The agent access scan |

**AI agents** are identities: granted edges say what they can reach, observed edges what they used.

### Properties written by the background graph analysis

Stored on `User`, `Computer` and `Group` nodes. Recomputed when data is loaded, after a BloodHound import, when an asset is marked critical, and on the next re-score after the network changes. There is no timer.

| Property | Meaning |
|---|---|
| `hops_to_critical` | Fewest steps to the nearest critical node |
| `choke_score` | Betweenness centrality on the attack graph: how often the node sits on the shortest path between two other nodes, scaled so the highest is 1 |
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

The sample network and a BloodHound import, using BloodHound's names.

| Edge | Meaning |
|---|---|
| `(User\|Computer\|Group)-[:MemberOf]->(Group)` | Is a member of the group |
| `(User\|Group)-[:AdminTo]->(Computer)` | Has admin rights on the computer |
| `(User\|Group)-[:CanRDP]->(Computer)` | Is allowed to log in by Remote Desktop |
| `(User\|Group)-[:GenericAll]->(User\|Group\|Computer)` | Has full control over the object |
| `(Computer)-[:HasSession]->(User)` | The user was logged in when the snapshot was taken, so their credentials may be on that computer |
| `(Domain\|OU)-[:Contains]->(OU\|User\|Computer\|Group)` | Folder structure. BloodHound treats it as an attack step, because rights set on an OU pass down to what it contains. We do not load it yet. |

BloodHound has more permission edges than these; the import keeps the ones above.

### AI agent, cloud and exposure edges

| Edge | Meaning | Source |
|---|---|---|
| `(Group)-[:CanPrompt]->(AIAgent)` | Can give the agent instructions | Sample network |
| `(AIAgent)-[:HasToolAccess]->(Tool)` | The agent can call this tool | Sample network; agent scan |
| `(AIAgent)-[:RunsAs]->(ServiceIdentity)` | The agent acts with this identity's rights | Sample network |
| `(ServiceIdentity)-[:RoleOn]->(CloudResource)` | Holds a role on the resource | Sample network |
| `(User)-[:SyncedTo]->(User)` | An on-premises account synced to a cloud account | Sample network |
| `(Internet\|CloudResource)-[:FeedsUntrustedInput]->(AIAgent)` | The agent reads content an outsider can write: prompt injection (MITRE ATLAS AML.T0051) | Sample network; agent scan |
| `(AIAgent)-[:CanRead]->(Folder)`, `(Folder)-[:Contains]->(Secret)`, `(Secret)-[:HoldsKeyFor]->(CloudResource)`, `(AIAgent)-[:SignedInTo]->(CloudResource)` | What a real agent can reach, and through which key | Agent scan |
| `(Computer)-[:Runs]->(Software)`, `(Internet)-[:CanExploit]->(Computer)` | A machine runs this software; an internet-facing machine with a remotely exploitable CVE gains an attack step from the internet | Sample network; `vulns.py` |

Other edges in `cloud_ai.json`: `CanAccess`, `CanEmail`, `ExposedTo`, `Owns`.

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
| `(User)-[:LoggedInto]->(Computer)` | The user logged into the computer | `logon_type`, `auth_type` (planned; today edges carry only `first_seen`, `last_seen`, `count` and `user`) | Identity logs (Windows logon events on the APT29 day), osquery signed-in users |
| `(Computer)-[:RemoteLogon]->(Computer)` | Someone used an account to log in from one computer to another. This is one hop of lateral movement. | `user`; `logon_type`, `auth_type` planned | Identity logs where source and destination computers differ |
| `(Computer)-[:ConnectedTo]->(Computer)` | The two computers exchanged network traffic | `port`, `protocol` where the day's network gives them; `bytes` planned | Network flow logs (Sysmon connections on the APT29 day) |
| `(Computer)-[:Ran]->(Process)` | A program ran on the computer | `user` | EDR (Sysmon process starts on the APT29 day) |
| `(AIAgent)-[:InvokedTool]->(Tool)` | The agent actually called the tool | none | Sample network |
| `(AIAgent)-[:UsedAccess]->(anything it can reach)` | A real agent touched it in the last 7 days | `count`, `last_seen` | The Claude Code hook |

### Alert edges

| Edge | Meaning |
|---|---|
| `(Alert)-[:Involves]->(User\|Computer\|Process)` | The alert is about this entity |
| `(Alert)-[:PartOf]->(Incident)` | The alert ranker linked it into this incident |

### Other edges

| Edge | Meaning | Source |
|---|---|---|
| `(Software)-[:HasVuln]->(Vulnerability)` | This software version has this known weakness | NIST NVD (`vulns.py`) |
| `(Application)-[:RunsOn]->(Computer)` | The application is hosted on this computer | CMDB |

## Granted vs used access

| | Built from |
|---|---|
| **Granted access** of a user | `MemberOf`, followed through nested groups, then `AdminTo`, `CanRDP` and `GenericAll` |
| **Used access** of a user | `LoggedInto` and `RemoteLogon` edges with `last_seen` inside the chosen window, for example the last 30 days |
| **Granted access** of an AI agent | `HasToolAccess`, `RunsAs` and the rights behind it, and for a real agent `CanRead`, `SignedInTo` and the keys it can reach |
| **Used access** of an AI agent | `InvokedTool`, and for a real agent `UsedAccess` edges from its last 7 days of tool calls |

The shrinking circle runs the same blast radius query twice: once over granted edges and once over used edges.

## Critical assets and zones

| Property | Values | How it is set |
|---|---|---|
| `critical` | true or false | Set from the CMDB, the BloodHound import (Tier Zero) or by an analyst. |
| `zone` | `low_trust` or `normal` | Set from the CMDB, for example guest Wi-Fi laptops and internet-facing machines are `low_trust` |

Which assets are critical is a team decision.

## Edge risk for attack paths

How easy each edge is for an attacker to cross. `p` is our starting guess at the chance an attacker can use the edge. The Attack paths tab's "most likely path" uses the cost `-log(p)`, so the cheapest path is the most likely one. Alert ranking and blast radius count hops and ignore `p`.

**These numbers are our design choice, not measured facts.**

| Edge | Starting `p` | Reasoning |
|---|---|---|
| `MemberOf` | 1.0 | Membership is automatic. No effort needed. |
| `AdminTo` | 0.9 | Admin rights give direct control of the computer. |
| `GenericAll` | 0.9 | Full control over the object. |
| `CanRDP` | 0.7 | Login is allowed but still needs valid credentials. |
| `HasSession` | 0.6 | Credentials may be stolen from memory, but not always. |
| `RemoteLogon` | 0.8 | This route has already been used, so it works. |
| `ConnectedTo` | 0.3 | Network access alone does not give control. |
| `Contains` | not loaded yet | BloodHound treats it as an attack step, because rights set on an OU pass down to what it contains. |

## MITRE ATT&CK tags

Our own lookup table. No standard mapping from BloodHound edges to ATT&CK exists, so we keep this one small and explain it. All IDs checked on [attack.mitre.org](https://attack.mitre.org).

| Edge or alert type | Tactic | Technique |
|---|---|---|
| Phishing alert | TA0001 Initial Access | T1566 Phishing |
| Script or command execution alert | TA0002 Execution | T1059 Command and Scripting Interpreter |
| `HasSession` used to steal credentials | TA0006 Credential Access | T1003 OS Credential Dumping |
| `RemoteLogon`, `AdminTo` | TA0008 Lateral Movement | T1021 Remote Services |
| `CanRDP` | TA0008 Lateral Movement | T1021.001 Remote Desktop Protocol |
| Login with a stolen password | TA0001 Initial Access (our choice; ATT&CK lists T1078 under four tactics) | T1078 Valid Accounts |
| Login with a stolen password hash | TA0008 Lateral Movement | T1550.002 Pass the Hash |
| `GenericAll` used to change an account | TA0003 Persistence | T1098 Account Manipulation |

The tactic order (Initial Access, Execution, Credential Access, Lateral Movement and so on) is what the alert ranker uses to check whether linked alerts follow attack stages.

## How each data source maps in

### Real sources

| Source | Becomes |
|---|---|
| osquery laptop inventory | A `Computer` named by its host name, a `User` per local account (`user-xxxx@<host>`, masked), `AdminTo` for admins, `LoggedInto` and `HasSession` for whoever is signed in |
| osquery laptop changes | One `Alert` per change (new admin, new listening port, sign-in, firewall off, disk encryption off), `source_tool: osquery`, `real: true` |
| Claude Code access scan | `AIAgent`, `Folder`, `Secret`, `CloudResource`, `Tool` nodes and the granted edges above |
| Claude Code hook | `UsedAccess` edges from the agent to what each tool call touched |

These are stored as `SourceRecord` and `SourceEvent` nodes, which a reload never wipes, and drawn back into the graph after every load.

### The APT29 lab day

Windows logon events become `LoggedInto` and `RemoteLogon`, Sysmon network connections between lab machines become `ConnectedTo`, Sysmon process starts become `Process` and `Ran`, and the SigmaHQ rule matches become `Alert` nodes. Details in [data-sources.md](data-sources.md#apt29-day-1-with-sigma-rules).

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

1. Which assets count as critical in our sample organisation?
2. Which machines are low-trust?
3. Which BloodHound permission edges beyond the ones above should count for attack paths?
4. How long is the "used access" window: 7, 30 or 90 days?
5. Are the starting edge risk values sensible?
