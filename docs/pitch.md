# GraphOps pitch

What we tell judges, how we win and what we must never say. The evidence behind every point is in [research.md](research.md).

## The pitch

> **"Five major security platforms each solve some of these problems. None solves all seven. GraphOps does it in one free, open graph, ranks every alert by where it sits on the attacker's map and never throws an alert away."**

India line:

> **"In India you have 6 hours to report an incident to CERT-In. GraphOps tells you what happened in seconds."**

## How we win

### 1. One open tool, any data
Everything lives in one free, self-hosted Neo4j graph that takes data from any vendor. Microsoft only comes close with four paid products: Defender XDR, Security Exposure Management, Sentinel with its data lake and Defender for Identity.

### 2. We fill the two empty spots
- **The shrinking circle (pain point 6).** Draw a hacked user's blast radius twice: once over all the access they are allowed and once over only the access they use. The difference is the risk that least privilege removes.
- **The never-taken path (pain point 7).** Raise an alert's score when a machine-to-machine logon route near it was used for the first time shortly before, even when each step looks normal.

### 3. We rank alerts by where they sit on the attacker's map
Every platform ranks alerts. Wiz uses graph context to rank threats, but only in the cloud. For on-premises and hybrid networks, none of the tools we checked lists attack paths, choke points or distance to critical systems as ranking inputs. Ours does.

We keep every alert and delete none. GraphOps works like a smart inbox: dangerous alerts float to the top and each one shows why.

Each alert is scored on six questions:

| # | Question | Idea comes from |
|---|---|---|
| 1 | Is it linked to other alerts through the same user or machine within a short time? | GraphWeaver (Microsoft) |
| 2 | How many steps is it from a critical asset? | Shortest path |
| 3 | How many critical assets sit within 3 hops of it? | Blast radius |
| 4 | Is it unusual, such as a first-time action or a never-used path? | NoDoze (NDSS 2019) |
| 5 | Do the linked alerts follow attack stages in order? | RapSheet (IEEE S&P 2020) and MITRE ATT&CK |
| 6 | Does it sit on a choke point? | Betweenness and min cut |

How much each question counts is our design choice. We tune it on test data.

### 4. AI in three safe places

| Where | What it does | Why it is safe |
|---|---|---|
| Ranking weights (built, off by default) | A small logistic regression learns from analysts marking alerts real, benign or false, and shows its weights next to the hand-set ones | Simple and explainable. Big graph neural networks collapsed when re-tested fairly in 2025 and 2026 studies. On our six synthetic days it did no better than the hand-set weights, so it stays off until real verdicts exist ([evaluation.md](evaluation.md)). |
| Incident story (built, Sarvam AI) | Sarvam's `sarvam-105b` drafts what happened, step by step, in English or translated into 10 Indian languages | Every sentence cites the alerts, users or machines it is based on; a checker removes any sentence citing something outside the incident, and the story is marked as needing analyst approval. A Google study found unchecked summaries often missed details or added errors. |
| Ask tab (built, Sarvam AI) | "What can the intern's laptop reach?" is answered in plain words, in English or an Indian language | The model can only call eight fixed, read-only GraphOps lookups; it cannot write or run free-form queries. Every sentence cites what it is based on, and sentences citing anything the lookups did not return are removed. We chose this over generating Cypher (`Text2CypherRetriever`), whose output Neo4j says is not guaranteed to be correct. |

### 5. Fast because the hard work happens before the alert
- A shortest-path search from each node to the crown jewels stores "steps to nearest crown jewel" on every node. Scoring a new alert becomes a lookup.
- Blast radius is a search capped at 3 hops.
- Linked alerts are grouped with connected components, one of the cheapest graph algorithms.
- Heavy jobs such as choke points and communities are worked out ahead of time, when the network changes, never while the analyst waits.

This is standard engineering practice, not a new algorithm.

## Demo moments

| # | Moment | What the judge sees |
|---|---|---|
| 1 | Beat the 29-minute clock | A timer at 29:00. An alert fires and one click shows what the attacker can reach. |
| 2 | Scattered alerts become 1 story | The 4 attack alerts are spread among 26 others in the raw list. GraphOps links them into one incident, listed by time and tagged with attack stages, and drafts its story. |
| 3 | The fix-it button | "Remove these N permissions and X% of attack paths disappear." The red paths vanish on screen. Numbers come from our data. |
| 4 | The shrinking circle | Blast radius over granted access, then over used access. The circle shrinks. |
| 5 | The sleeping alert wakes up (not in our data yet) | An alert low in the inbox jumps to the top when a new alert links it to a path toward the database. In our sample day this does not happen: the attack's first alert already arrives at #2, because its laptop is close to the crown jewels. Showing it needs a scenario built for it. |
| 6 | Set the trap (bonus, not built) | GraphOps suggests where to place a decoy admin account on the most likely attack path. Backed by Adelaide and CSIRO research. We have not checked whether products already do this. |

**Proof.** Time 2 or 3 people answering "what happened?" with the raw alert list, then with GraphOps. Show both times.

## Never say

| Do not say | Why |
|---|---|
| "BloodHound can't do blast radius" | SpecterOps published a Tines playbook that does this from an alert. |
| "BloodHound has no ATT&CK mapping" | Its help text links techniques. Say "no structured, queryable ATT&CK field". |
| "Nobody has combined BloodHound with logs" | FalconHound does. |
| "We are the first to compute blast radius from an alert" | Microsoft Defender XDR and Wiz do. |
| "We are the first to compare granted and used access" | Heat-ray did a version in 2009 and cloud tools do it today. |
| "No platform ranks alerts" | All five big platforms do. Our difference is ranking by graph position. |
| "Nobody ranks alerts by graph position" | Wiz does, for cloud. Say "for on-premises and hybrid networks". |
| "Our choke point metric is the CSF 2025 metric" | We have not read its formula. Say "inspired by". |
| "Recalculating centrality improves results by 80%" | That number comes from an epidemics paper. |
| "SANS found 960 alerts a day" | That number is not in the SANS survey. |
| "Breaches take 247 days" (2026) | That number is not on IBM's release. |
| "Microsoft's ranking is based on BM25" | Only secondary sources say this. |
| Any AUC number on its own | AUC can look excellent while almost every alert is false. Report precision and alerts per day. |

## Hackathon rules and judging

Read from the [hackFront India page](https://whereuelevate.com/drills/hackfrontindia-2026) on 7 October 2026.

### Timeline (IST)

| What | When |
|---|---|
| Registration closes | 23 October 2026, 11:59 PM |
| Prototype submission closes | 31 October 2026, 11:59 PM |
| 30-hour in-person hackathon | 14 November 2026, 9:00 AM to 15 November 2026, 3:00 PM, New Delhi |

### Rules that affect us
- "Solutions must be original work built during the league timeline, not pre existing products or prior submissions."
- "Use of AI tools, open source frameworks, and third party APIs is allowed and encouraged, provided this is disclosed at submission." We list every AI tool, library and dataset in the main README.
- Plagiarism or misrepresentation leads to disqualification.

### What judges score

**Main prize (1st place INR 1 lakh):** "innovation, problem solving, technical execution, scalability, and real world impact ... a compelling, deployable solution with the potential to create lasting impact."

**Best Use of Neo4j (1st place INR 25,000 plus USD 600 credits):** "exceptional use of graph technology to model relationships, uncover meaningful insights, and solve a real world problem with creativity and technical excellence."

| Judging word | What we show |
|---|---|
| Innovation | Ranking by graph position, the shrinking circle, the never-taken path |
| Problem solving | The 7 pain points |
| Technical execution | A working, clickable demo |
| Scalability | Precomputed scores, capped searches, heavy jobs run ahead of time |
| Real-world impact | SANS 73%, 29-minute breakout, CERT-In 6 hours, INR 25.5 crore per breach |
| Deployable | Runs with one `docker compose up` |
| Neo4j prize | Relationships are the whole product: paths, choke points, communities and blast radius |

### Partners worth knowing
- **DSCI Cybersecurity Centre of Excellence** is the industry partner. Expect judges who know security well.
- **Neo4j** is the track partner.
- **Sarvam** is the AI partner and builds Indian-language AI. GraphOps uses it for the incident story and the Ask tab, with answers in English or 10 Indian languages (Sarvam Track).
