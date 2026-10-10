# GraphOps research

Everything we found while deciding what to build. It is written for teammates who are new to cybersecurity. If a word is unfamiliar, check [glossary.md](glossary.md).

Each fact has a source at the bottom of its section. "Our view" marks our own reasoning rather than a published fact.

## Contents

1. [The problem in plain words](#1-the-problem-in-plain-words)
2. [The numbers](#2-the-numbers)
3. [Why a graph](#3-why-a-graph)
4. [What already exists](#4-what-already-exists)
5. [Who solves which pain point](#5-who-solves-which-pain-point)
6. [What nobody covers](#6-what-nobody-covers)
7. [What research says about how to build it](#7-what-research-says-about-how-to-build-it)
8. [What Neo4j gives us for free](#8-what-neo4j-gives-us-for-free)
9. [Data we can use](#9-data-we-can-use)
10. [What we could not verify](#10-what-we-could-not-verify)

---

## 1. The problem in plain words

A **Security Operations Centre (SOC)** is the team that watches a company's systems for attacks. Their tools raise **alerts** all day, for example "unusual login on laptop-42" or "strange program on server-7".

A real attack usually looks like this:

1. An attacker gets into one unimportant machine, often through a phishing email.
2. They steal passwords saved on it.
3. They use those passwords to log into the next machine, then the next. This hopping is called **lateral movement**.
4. They reach something valuable, such as the customer database.

Each hop raises a small, separate alert in a different tool. The analyst sees a list of unrelated rows, not one attack. Someone has to stitch the story together by hand while the attacker keeps moving.

Microsoft's John Lambert summed it up: *"Defenders think in lists. Attackers think in graphs. As long as this is true, attackers win."*

### The 7 pain points we picked

| # | Pain point | In one line |
|---|---|---|
| 1 | Too many alarms | Most alerts are false, so the real attack hides in the noise. |
| 2 | Alerts don't connect | One attack shows up as many separate alerts. |
| 3 | Attackers are faster | Attackers spread in minutes. Analysts take hours. |
| 4 | "How bad is this?" | Nobody can quickly see what a hacked machine can reach. |
| 5 | Hidden danger | Risky access paths exist long before anyone uses them. |
| 6 | Too much access | People hold far more access than they use, and every unused permission is a free road for an attacker. |
| 7 | One step at a time | Rules check each step. A route can be strange even when every step looks normal. |

Pain points 2 to 7 come from the hackFront GraphOps challenge brief. Pain point 1 comes from the SANS survey below.

Source: John Lambert, [post on X](https://x.com/johnlatwc/status/549049397602828288).

---

## 2. The numbers

| Fact | Number | Source |
|---|---|---|
| Survey respondents citing false positives as a main detection challenge, the most cited one | **73%** in 2025, up from 64% in 2024 | SANS 2025 Detection and Response Survey |
| Organisations seeing false positives frequently or very frequently | **more than 60%** | same survey |
| Average time for an attacker to start spreading (eCrime breakout time) | **29 minutes** in 2025, down from 48 minutes in 2024 | CrowdStrike 2026 and 2025 Global Threat Reports |
| Fastest breakout seen | **27 seconds** in 2025 | CrowdStrike 2026 Global Threat Report |
| Average cost of a data breach, global | **USD 4.99 million** (2026) | IBM Cost of a Data Breach 2026 |
| Average cost of a data breach, India | **INR 25.5 crore**, a record high (2026) | IBM India 2026 |
| Time Indian organisations have to report a cyber incident to CERT-In | **6 hours** from noticing it | CERT-In Directions, 28 April 2022 |

SANS also writes that "excessive noise provides attackers with greater cover and erodes defenders' ability to respond swiftly."

Do not quote "960 alerts a day" or "174 alerts per analyst". Some blogs attribute these to the SANS survey, but they are not in it.

Sources:
- SANS Institute, *SANS 2025 Detection and Response Survey: Unseen Threats Have Security Teams Rethinking Detection*, Josh Lemon, December 2025 (read in the original PDF).
- CrowdStrike, [2026 Global Threat Report](https://www.crowdstrike.com/en-us/press-releases/2026-crowdstrike-global-threat-report/) and [2025 Global Threat Report](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-releases-2025-global-threat-report/).
- IBM, [Cost of a Data Breach 2026](https://newsroom.ibm.com/2026-07-29-ibm-study-one-in-four-malicious-breaches-are-ai-enabled,-costing-companies-6-million-on-average) and [IBM India 2026](https://in.newsroom.ibm.com/India-Records-its-Highest-Average-Cost-of-a-Data-Breach-2026).
- CERT-In, [Directions under Section 70B of the IT Act](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf).

---

## 3. Why a graph

Most security data sits in **tables**. A table of logins looks like this:

```
user      | computer
intern_a  | laptop-42
admin_b   | laptop-42
admin_b   | server-7
svc_db    | server-7
svc_db    | customer-db
```

The question during an attack is: *"intern_a's laptop is hacked. Can the attacker reach customer-db?"*

To answer it you go: laptop-42, then who else logged in there (admin_b), then where admin_b goes (server-7), then who else logged in there (svc_db), then where svc_db goes (customer-db). In SQL that means joining the table to itself four times. If the attack takes 6 hops instead of 4, you need a different query.

In a **graph**, users and machines are dots (nodes) and logins are lines (edges). The same question becomes one short query: "find a path from laptop-42 to customer-db in up to 4 steps."

Why a graph wins for this problem:

1. **Unknown number of steps.** A graph query can say "up to N steps". SQL needs one join per step.
2. **Mixed kinds of steps.** Real attack paths mix logins, group memberships, admin rights and network connections. In a graph they are all just edges.
3. **Speed.** Neo4j stores direct links from each node to its neighbours, so a search only touches the part of the network it walks.
4. **Ready-made algorithms.** Shortest path, choke points and community detection are graph algorithms. Neo4j ships them.
5. **You can see it.** An analyst understands a drawn attack path in seconds. A 5,000-row table tells them nothing at a glance.

To be fair to SQL: modern SQL has recursive queries that can follow chains, and at small sizes both are fast. The real advantage is that SOC questions are path questions, and a graph lets you ask, compute and draw them directly.

---

## 4. What already exists

### BloodHound

**What it is.** A tool by SpecterOps that maps **attack paths** inside Microsoft Active Directory (the system that controls who can log into what in most companies). It was released in 2016 at DEF CON, a large hacker conference. There is a free Community Edition and a paid Enterprise edition.

**How it works.**
1. A collector program reads group memberships, admin rights and who is logged in where.
2. It runs on a schedule, every few hours to daily.
3. It stores this as a graph and answers questions like "what is the shortest path from this user to the domain admins?"

**What it does well.**
- Shows attack paths before an attack happens.
- The Enterprise edition finds **choke points**: the few permissions that many attack paths pass through.
- Its help text links each type of connection to MITRE ATT&CK techniques.

**What it does not do in the product.**
- It does not read live alerts, endpoint logs or network traffic. Its official integrations with SIEM and SOAR tools (Splunk, Microsoft Sentinel and others) send BloodHound's findings out to those tools. Nothing comes in.
- Its alerts are about new attack paths appearing between collections. They do not detect unusual behaviour. SpecterOps hands anomaly detection to a partner (Quest).
- It does not merge alerts into incidents. Its Sentinel integration creates one incident per BloodHound finding.
- It does not compare granted access with access that is actually used.

**Careful.** BloodHound *can* help during an incident through an outside playbook. SpecterOps published a Tines workflow (December 2025) that checks a flagged user's paths to the most sensitive accounts when an alert fires. This queries BloodHound's last snapshot, not live data.

Sources: [SpecterOps BloodHound on GitHub](https://github.com/SpecterOps/BloodHound), [BloodHound docs](https://bloodhound.specterops.io/), [SpecterOps Tines blog](https://specterops.io/blog/2025/12/09/bloodhound-enterprise-tines-security-automation/), [DEF CON 24 talk slides](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEF%20CON%2024%20-%20Robbins-Vazarkar-Schroeder-Six-Degrees-of-Domain-Admin.pdf).

### Microsoft

Microsoft comes closest to covering everything, but only by combining several paid products:

| Product | What it does for us |
|---|---|
| **Defender XDR** | Groups alerts into incidents aligned to MITRE ATT&CK. Gives each incident a 0 to 100 priority score with reasons (public preview). Has "Blast radius analysis" in the incident graph (preview). |
| **Sentinel data lake** | Required for Defender XDR's blast radius analysis. Microsoft's page says it is available to customers who onboarded before 23 September 2026. |
| **Security Exposure Management** | Attack paths and choke points before an attack. |
| **Sentinel UEBA** | Flags unusual behaviour such as a first-time event for a user. It does not look at whole paths. |
| **Defender for Identity** | Flags accounts unused for 90 days. Its older "lateral movement paths" maps stopped updating in May 2025. |
| **Entra Permissions Management** | Compared granted with used permissions, for cloud only. Retired in late 2025. |

Microsoft's priority score uses, among other things:
- attack disruption signals
- threat analytics
- alert severity
- signal-to-noise ratio
- MITRE techniques
- asset criticality
- alert type and rarity
- high-profile threats

Attack paths, blast radius and distance to critical systems are not listed.

Sources: Microsoft Learn pages for [Defender XDR incidents](https://learn.microsoft.com/en-us/defender-xdr/investigate-incident-cases), [Security Exposure Management attack paths](https://learn.microsoft.com/en-us/security-exposure-management/review-attack-paths), [Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) and [Defender for Identity what's new](https://learn.microsoft.com/en-us/defender-for-identity/whats-new).

### Other platforms

| Product | What it covers |
|---|---|
| **Wiz Defend** | Ranks threats using its Security Graph, including whether a threat could reach crown-jewel data or an admin role. Links related detections and shows the blast radius when an alert fires. Cloud only. |
| **XM Cyber** | Attack paths and choke points. Adds attack-path context to alerts from SIEM and EDR tools. |
| **Tenable One** | Attack paths with a choke point priority, mapped to MITRE ATT&CK. |
| **Google Security Operations** | Ranks entities by a weighted sum of detection risk scores. Groups alerts into cases by shared entities. Its entity graph shows how a threat may have spread, looking backward. |
| **Palo Alto Cortex XSIAM / XDR** | Ranks incidents with SmartScore and groups alerts into cases. Finds unused permissions for AWS, Azure and GCP only. |
| **Splunk Enterprise Security 8** | Risk-based alerting that scores entities and groups activity into findings aligned to MITRE ATT&CK. |
| **CrowdStrike Falcon** | Correlates detections with AI risk scores. Attack Path Analysis to business-critical systems. |

### Open source and research

| Name | What it is |
|---|---|
| **FalconHound** (FalconForce, BSD-3 licence, archived 2023) | Pulls logons and incidents from Sentinel, Defender, Splunk and Elastic into BloodHound's graph and alerts on short paths to admin groups. |
| **Cartography** (Apache-2.0) | Loads cloud and security tool inventory into Neo4j. No on-premises Active Directory and no network flows. |
| **LogonTracer** (JPCERT) | A Neo4j graph of Windows logon events. Logins only, no permissions. |
| **Heat-ray** (Microsoft Research, SOSP 2009) | Built an Active Directory attack graph from logins and admin rights and recommended removing out-of-date privileges. The idea of comparing granted and used access is at least this old. |

Sources: [Wiz Defend launch blog](https://www.wiz.io/blog/wiz-defend-general-availability), [Wiz threat prioritization blog](https://www.wiz.io/blog/wiz-cdr-and-amazon-guardduty-contextualize-and-prioritize-threat-detection), [FalconHound](https://github.com/FalconForceTeam/FalconHound), [Cartography](https://github.com/cartography-cncf/cartography), vendor product pages as listed in each row's documentation.

---

## 5. Who solves which pain point

✅ yes   ⚠️ partly   ❌ no evidence found   ➖ not their area

### Main competitors

| Pain point | Microsoft (several paid products) | BloodHound | Wiz | XM Cyber |
|---|---|---|---|---|
| 1. Rank alerts | ✅ ranks **incidents** 0 to 100 with reasons | ❌ | ✅ cloud only, uses graph context such as paths to crown jewels | ❌ |
| 2. Join alerts into one story | ✅ | ❌ | ✅ cloud only | ❌ |
| 3. "What can they reach next?" fast | ✅ blast radius (preview, needs Sentinel data lake) | ⚠️ only through a playbook, on the last snapshot | ✅ cloud only | ⚠️ adds attack-path context to alerts |
| 4. "How bad is this?" mid-attack | ✅ same feature as 3 | ⚠️ same as 3 | ✅ cloud only | ⚠️ |
| 5. Dangerous paths before an attack | ✅ | ✅ its main job | ✅ | ✅ |
| 6. Granted vs used access | ❌ for on-premises networks. Cloud tool retired in 2025. Only flags accounts unused for 90 days | ❌ | ➖ | ➖ |
| 7. Never-taken path | ⚠️ flags "first time this user did X", not "first time this **route**" | ❌ | ➖ | ➖ |

### Big SOC platforms

| Pain point | Google SecOps | Palo Alto Cortex | Splunk ES | CrowdStrike |
|---|---|---|---|---|
| 1. Rank alerts | ✅ no graph signals | ✅ SmartScore | ✅ risk-based alerting | ✅ AI risk scores |
| 2. Join alerts into one story | ✅ up to 30 alerts per case | ✅ | ✅ ATT&CK-aligned | ✅ |
| 3 and 4. Blast radius from an alert | ⚠️ looks backward | ❌ | ❌ | ⚠️ only through XM Cyber |
| 5. Dangerous paths before an attack | ⚠️ separate cloud product | ❌ | ❌ | ✅ |
| 6. Granted vs used access (on-premises) | ❌ | ⚠️ cloud only | ❌ | ❌ |
| 7. Never-taken path | ❌ first-time events only | ❌ baselines only | ❌ baselines only | ❌ baselines only |

"No evidence found" means we read the vendor's public pages and did not see it. It does not prove the feature is missing.

---

## 6. What nobody covers

Across the products above, we found **no documented feature** that does any of these:

1. **Rank alerts by where they sit on the attacker's map, for on-premises and hybrid networks.** Everyone ranks alerts. Wiz uses graph context for this, but only in the cloud. None of the others lists attack paths, choke points or distance to critical systems as ranking inputs.
2. **Granted vs used access for on-premises networks**, shown as two blast radius circles for the same hacked user.
3. **Never-taken path detection.** Every platform flags first-time *events*. None flags a first-time *route*.
4. **All seven pain points in one open, self-hosted tool** that takes data from any vendor.

Our view: GraphOps is not a new algorithm. Its value is putting all of this on one graph so one query can cross it.

Our view on scope: we focus on on-premises and hybrid networks. In the cloud, Wiz already ranks threats and shows blast radius using graph context. On company networks and the paths that cross from them into the cloud, none of the tools we checked does.

---

## 7. What research says about how to build it

### Simple methods hold up better than complex ones

Several published lateral movement detectors use deep learning on graphs and reported excellent results. Newer studies re-tested them fairly and the results collapsed:

| Study | What it found |
|---|---|
| Larroche, ANUBIS 2026 (workshop at ESORICS 2026) | Under realistic testing on the LANL dataset, Argus's precision fell from 32.27% to 0.09% and Euler's from 5.23% to 0.02%. Conclusion: "lateral movement detection remains an open problem." |
| Bouček and Husák, CNSM 2025 | Could not reproduce Jbeil (IEEE S&P 2024). Its test code ignored the true labels. |
| Zhao and Hassan, ACM CCS 2026 | A deliberately simple model with no graph neural network ranked first on 2 of 4 datasets. |

Our view: simple, explainable graph rules are the right choice, and we can back that choice with these papers.

### But simple rules alone are noisy

| Study | What it found |
|---|---|
| Bowman et al., RAID 2020 | A plain "never seen this login before" rule caught 72% of attacks on LANL but raised 530,082 false alarms. |
| Hopper, USENIX Security 2021 | Following login paths, filtering out repetitive automated logins and flagging a change of account along a path caught 94.5% of 300+ attack scenarios at under 9 alerts a day. |

Our view: we need the never-taken-path rule plus Hopper-style noise filters, not the rule alone.

### Ideas for ranking alerts

| Idea | From |
|---|---|
| Rare events are more suspicious than common ones | NoDoze, NDSS 2019 |
| Alerts that follow attack stages in order are more convincing | RapSheet, IEEE S&P 2020 |
| Alerts that share a user or machine within a time window belong together | GraphWeaver, Microsoft (preprint) |

### Choke points

- A research group at the University of Adelaide and CSIRO has published more than ten papers on choosing which permissions to block in Active Directory. Their exact methods are too heavy for a hackathon.
- Zhang, Ward and Nguyen (IEEE CSF 2025) argue that choke points found only from *shortest* paths miss real ones. Their metric counts connections between sources and targets instead. The full paper is behind IEEE's paywall, so we use the idea, not their exact formula.
- Neo4j can find choke points three ways: betweenness centrality, max flow (from which we derive the minimum cut) and a reachability count. Showing where the three disagree is our idea.

### Using an LLM safely

Kramer et al. (USENIX SOUPS 2025) studied AI-written incident summaries at Google. In about 211 analyst comparisons, unchecked summaries left out critical details 35% of the time and added inaccuracies 42% of the time. Working alongside analysts, they reduced effort.

Our view: an LLM can draft the incident story only if every sentence cites real graph nodes and an analyst approves it.

Sources: [Larroche 2026](https://arxiv.org/abs/2607.29390), [Bouček and Husák 2025](https://opendl.ifip-tc6.org/db/conf/cnsm/cnsm2025/1571196179.pdf), [Zhao and Hassan 2026](https://arxiv.org/abs/2609.12263), [Bowman et al. 2020](https://www2.seas.gwu.edu/~howie/publications/CyberGraph-RAID20.pdf), [Hopper](https://arxiv.org/abs/2105.13442), [NoDoze](https://www.ndss-symposium.org/ndss-paper/nodoze-combatting-threat-alert-fatigue-with-automated-provenance-triage/), [RapSheet](https://dartlab.org/assets/pdf/rapsheet.pdf), [GraphWeaver](https://arxiv.org/abs/2406.01842), [Zhang, Ward and Nguyen 2025](https://ieeexplore.ieee.org/document/11097865/), [Kramer et al. 2025](https://www.usenix.org/system/files/soups2025-kramer.pdf).

---

## 8. What Neo4j gives us for free

Every algorithm we need is in the free Community edition of Neo4j's Graph Data Science library. The Community edition is limited to 4 CPU cores.

| We want to | Neo4j feature |
|---|---|
| Find the most likely attack path | `gds.shortestPath.dijkstra` |
| Find the top few alternative paths | `gds.shortestPath.yens` |
| Find choke points | `gds.betweenness`, `gds.maxFlow` (returns flows, we derive the cut) |
| Find important nodes | `gds.pageRank`, `gds.degree` |
| Find groups of machines that work together | `gds.louvain`, `gds.leiden` |
| Group linked alerts into one incident | `gds.wcc` (connected components) |
| Connect alerted machines with the smallest tree | `gds.steinerTree` |
| Get the 1, 2 and 3 hop blast radius | Cypher path patterns or `apoc.path.subgraphNodes` with a 3 hop limit |
| Turn a plain-English question into a query | `Text2CypherRetriever` in the `neo4j-graphrag` Python package |

Notes:
- `gds.bridges` and `gds.articulationPoints` only work on undirected graphs. Attack paths have a direction, so they are extras only.
- Neo4j's docs warn that a query generated by `Text2CypherRetriever` "is not guaranteed to be syntactically correct". We show the query to the analyst and run it read-only.
- Neo4j publishes a cybersecurity attack path example with a ready schema: [cyber-apa](https://github.com/neo4j-field/cyber-apa).

Sources: [Neo4j Graph Data Science docs](https://neo4j.com/docs/graph-data-science/current/), [APOC docs](https://neo4j.com/docs/apoc/current/), [neo4j-graphrag docs](https://neo4j.com/docs/neo4j-graphrag-python/current/).

---

## 9. Data we can use

| Dataset | What it is | Good for | Watch out |
|---|---|---|---|
| **ADSynth** (DSN 2024, BSD-3 licence) | Generates realistic fake Active Directory networks and exports them to Neo4j or BloodHound format | Attack paths, choke points, granted access | No activity data: no logins over time and no alerts. Pins an old Neo4j driver (4.4.10). |
| **LANL 2015** (Los Alamos National Laboratory, public domain) | 58 days of real logins, processes, network flows and DNS from a real network, with a file of red-team attack events | Testing never-taken-path detection with real attacks | Must request access with an email form. The login file is 7.2 GB compressed, so we use a slice. Names are anonymised. |
| **Our own scripted alerts** | Alerts we write onto ADSynth machines that follow a known attack path | The end-to-end demo | Synthetic. We say so on screen. |

Our view: use all three. ADSynth for the network, a slice of LANL for testing detection and scripted alerts for the demo.

Sources: [ADSynth](https://github.com/AUCyberLab/ADSynth), [LANL 2015 dataset](https://csr.lanl.gov/data/cyber1/).

---

## 10. What we could not verify

- The exact formula of the IEEE CSF 2025 choke point metric (paywall).
- CrowdStrike's documentation behind its login.
- Whether CrowdStrike uses the term "choke points" (seen only in a search snippet).
- Specifics of identity vendors such as Veza and Sonrai.
- Conference talk archives were not searched. Someone at a vendor may know of a feature we did not find.
