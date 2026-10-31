# Analyst guide

GraphOps for the person on shift. The console has six tabs, switched from the top bar: **Triage**, **Attack paths**, **Access**, **AI agents**, **Graph** and **Ask**. **Help** in the top bar starts a short guided tour.

## What data you are looking at

The **Scenario** picker under the top bar has two choices:

- **APT29 attack (real lab logs).** Real Windows, Sysmon and PowerShell logs of MITRE's APT29 emulation, recorded on four lab machines by OTRF, with alerts from the public SigmaHQ rules. The team's live laptops and agents are in the graph too.
- **Real data (live laptops & AI agents).** Only what reports in live: the team's laptops through osquery and their Claude Code agents. Nothing recorded or written by us.

Real sources' alerts carry a **REAL** tag. The badge next to the picker says which you are seeing.

Switching the day reloads the data for everyone looking at the site. Only one reload runs at a time.

## Triage: what needs me now

The default tab. Every alert of the day, ranked by where it sits on the attacker's map, nothing hidden.

- **Inbox.** Highest score first. The number is the GraphOps score; the thin bar under each alert shows which ranking questions earned it, and the small number on the right is where sorting by severity would have put it. Switch to **Severity** to see the order most tools use. Filter by severity, verdict and graph signals (near a critical asset, new route, linked to other alerts), or search.
- **Why it ranks.** The six graph questions and the points each added, with the reasons in words.
- **Blast radius.** What an attacker on this alert's machine or account could reach in 1, 2 and 3 hops. The red dashed line is the shortest attack path to a critical asset. Three modes:
  - **All attack edges**: every route an attacker could follow.
  - **Granted**: only the permissions the identity holds.
  - **Used**: only the logons actually seen in the last 30 days.
  The gap between *granted* and *used* is the access least privilege would remove.
- **Incident.** Alerts GraphOps linked into one attack, listed by time and tagged with their ATT&CK stage. **How it started** names the entry point, or says it was not seen and where to look further back. Set the incident's status (open, investigating, contained, closed); it sticks as new alerts arrive. Download the incident report as PDF or Markdown.
- **Respond.** For an incident you believe is real:
  - **Confirm incident** starts the CERT-In clock: 6 hours to report, counting down.
  - **Who needs to know**: the accounts in the incident, the owners of its machines and of the critical assets it can reach.
  - **Containment**: isolate the machines, reset the accounts, cut the first steps of the attack path. GraphOps does not control your EDR or directory, so each step is recorded as *requested*, with the time.
  - **CERT-In report draft**, in the order of CERT-In's Incident Reporting Form, with the fields GraphOps cannot know left to fill.
  - **Email**: built (it sends through a Gmail app password to a fixed contact list), but not enabled on the public demo.
- **Story.** Sarvam AI writes what happened in plain words, in English or one of 10 Indian languages. Every sentence cites the alerts, accounts or machines it is based on, and is marked as needing an analyst's check.
- **Verdict.** Mark each alert **Real attack**, **Benign** or **False alarm**. *Benign* records real but allowed activity, so it is not counted as a miss.

## Live: watch it happen

**Stream live** in the top bar: on the APT29 day it replays the day through Kafka as if it were happening now, and alerts arrive one by one as the inbox re-ranks; the lab's real logons, connections and process starts stream too. On **Real data** it follows the team's laptops and agents, and new alerts appear every few seconds as they report. **Stop** returns to the full view. Switching the day stops a running stream first.

## Attack paths: fix it before it is used

The attack paths that exist today, before any alert.

- **The number** is how many start-to-critical-asset pairs an attacker could reach, of all possible. Switch the scope between **From low-trust machines** (guest, intern and internet-facing machines) and **From anything** (if any machine, account or agent were compromised).
- **Choke points** are the systems the most paths run through.
- **Fixes that cut the most paths.** Each fix shows the share of paths it actually cuts, recomputed on the graph with the fix applied, never estimated.
- **What one system can reach.** Pick any machine, account or agent: everything it can reach, the critical assets among them, and the paths to each as **Shortest path** or **Most likely path** (the route most likely to succeed, multiplying each step's likelihood). **Needs securing** lists paths with no recorded control; mark a step secured (for example MFA added or a permission removed) and it moves to **Secured**.

## Access: the least-privilege gap

Every account, ranked by the access it holds but has not used in the chosen window (7, 30 or 90 days).

- **The shrinking circle.** The outer ring is everything the identity is granted; the solid disc is what it actually uses. The gap is unused access: risk with no benefit, and the first thing to remove.
- **Granted vs used columns.** Side by side, with unused grants highlighted and critical ones flagged.
- **Used without a grant.** Routes the logs show that no modelled permission explains.

## AI agents: a real agent's access

A real Claude Code agent on a team laptop, reporting in.

- **What it can reach**: folders, secret files (by name only), the services their keys open, the accounts it is signed in to and the tools it can call.
- **History**: counts from its past sessions, such as web pages read and git pushes.
- **If this agent is hijacked**: the routes from the open web, through content the agent reads, to a critical service, each step tagged with its ATT&CK or ATLAS technique and a fix.
- **Live activity**: each tool call as it happens, with what it touched and never what it read.

## Graph: the Neo4j graph itself

- **Connected sources**: the real laptops reporting, with their accounts, open ports, disk encryption, firewall and last report.
- **The live graph**, drawn with Neo4j's NVL on the hosted site, in five views: **Node types**, **Communities** (Louvain), **Influence** (PageRank), **Choke points** (betweenness) and **On-prem, cloud, AI**. Each view says which algorithm drew it and whether it ran on Neo4j Graph Data Science or in Python.
- **Path finder**: the shortest attack path between two systems, with the Cypher query behind it, drawn on the graph.
- **Proof**: for every labelled day, how high the attack sat above the noise for GraphOps and for sorting by severity.

## Ask: questions in plain words

Type a question such as "What can laptop-42 reach?" and choose a language. Sarvam AI answers using eight fixed, read-only GraphOps lookups. Every sentence cites what it is based on, and the answer lists which lookups it used.

## A good first five minutes

1. Open **Triage** on the APT29 lab day and read the top of the inbox. The top incident is the attack.
2. Open **Incident**: read *How it started* and the attack stages in order.
3. Open **Respond**, confirm the incident and watch the CERT-In clock start.
4. Switch to **Attack paths**, apply the top fix and note the share of paths it cuts.
5. Open **AI agents** and read *If this agent is hijacked*.
