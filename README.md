# GraphOps

Graph analytics for security operations centres (SOCs). GraphOps puts an organisation's users, machines, applications, permissions and security alerts into one Neo4j graph so analysts can see how alerts connect, what an attacker can reach next and which access paths are dangerous before an attack happens.

Built by Team Pingu Haters for hackFront India 2026 (Cybersecurity theme).

## Scope

GraphOps focuses on on-premises and hybrid networks: a company's own machines and Active Directory, plus the cloud accounts and services connected to them. Cloud-only tools already rank threats and show blast radius using graph context in the cloud. The gap we target is the company network and the attack paths that cross from it into the cloud.

## Status

Research and planning. No code yet. Features below describe what we are building, not what already works.

## The problem

- **Too much noise.** In the SANS 2025 Detection and Response Survey, 73% of organisations named false positives as their top detection challenge, up from 64% in 2024. SANS also notes that excessive noise gives attackers cover.
- **Attackers are fast.** CrowdStrike measured an average eCrime breakout time of 29 minutes in 2025, down from 48 minutes in 2024. Breakout time is how long an attacker takes to move from the first compromised machine to others.
- **Breaches are expensive.** IBM puts the average cost of a data breach at USD 4.99 million globally and a record INR 25.5 crore in India (2026).
- **Reporting deadlines are tight.** Under the CERT-In Directions of 28 April 2022, organisations in India must report cyber incidents to CERT-In within 6 hours of noticing them.

## Pain points we tackle

| # | Pain point | What GraphOps does |
|---|---|---|
| 1 | Too many alerts, most of them false | Ranks every alert by where it sits in the graph. No alert is deleted and every rank shows its reasons. |
| 2 | Alerts arrive as separate rows | Links alerts that share a user or machine into one incident, ordered by MITRE ATT&CK stage. |
| 3 | Attackers move faster than analysts | Precomputes each node's distance to critical assets so a new alert is scored instantly. |
| 4 | No quick answer to "how bad is this?" | Shows the 1, 2 and 3 hop blast radius around any alerted node. |
| 5 | Dangerous paths exist before any attack | Maps attack paths from low-trust zones to critical assets and lists the choke points that cut off the most paths. |
| 6 | People hold more access than they use | Draws the blast radius twice: once over granted access and once over access actually used. The difference is the risk that least privilege removes. |
| 7 | Rules check one step at a time | Flags a user reaching a system through a path they have never used before, even when each step looks normal. |

## How alerts are ranked

Each alert is scored on six questions answered from the graph:

1. Is it linked to other alerts through the same user or machine within a short time?
2. How many steps is it from a critical asset?
3. How many critical assets sit within 3 hops of it?
4. Is it unusual, such as a first-time action or a never-used path?
5. Do the linked alerts follow attack stages in order?
6. Does it sit on a choke point?

The weight of each question is our design choice. It will be tuned on test data and can learn from analyst feedback.

## Where AI is used

- **Ranking weights.** A small, explainable model (logistic regression or decision trees) learns from analysts marking alerts as real or false.
- **Incident summaries.** An LLM drafts the incident story from the graph. Every sentence must cite graph node IDs and an analyst approves the draft.
- **Plain-English questions.** Questions such as "what can this laptop reach?" are turned into graph queries with Neo4j's `Text2CypherRetriever`. The generated query is shown to the analyst and runs read-only.

## How GraphOps differs from existing tools

Existing products each cover part of this list. In our review of Microsoft, Google SecOps, Palo Alto Cortex, Splunk Enterprise Security, CrowdStrike, BloodHound, Wiz and XM Cyber, none covered all seven pain points. None documented points 6 and 7 for on-premises networks.

GraphOps is not a new algorithm. It brings these capabilities into one open, self-hosted Neo4j graph that takes data from any vendor.

## Planned stack

| Layer | Choice |
|---|---|
| Graph database | Neo4j with Graph Data Science and APOC |
| Backend | Python |
| Frontend | React with a graph visualisation library |
| Deployment | Docker Compose |

This may change as we build.

## Team

Team Pingu Haters: Deepthi Sree Dubasi, Vatanesh Sharma, Bhanu Sai Teja, Raja Mohamad and SK MD Mahasin.

## Disclosure

As the hackFront India rules require, we will list every AI tool, open source framework, API and dataset used in this project here before submission.

## Sources

- SANS Institute, *SANS 2025 Detection and Response Survey*, Josh Lemon, December 2025.
- CrowdStrike, [2026 Global Threat Report press release](https://www.crowdstrike.com/en-us/press-releases/2026-crowdstrike-global-threat-report/) and [2025 Global Threat Report press release](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-releases-2025-global-threat-report/).
- IBM, [Cost of a Data Breach 2026 release](https://newsroom.ibm.com/2026-07-29-ibm-study-one-in-four-malicious-breaches-are-ai-enabled,-costing-companies-6-million-on-average) and [IBM India 2026 release](https://in.newsroom.ibm.com/India-Records-its-Highest-Average-Cost-of-a-Data-Breach-2026).
- CERT-In, [Directions under Section 70B of the IT Act, 28 April 2022](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf).
- Neo4j, [neo4j-graphrag Python documentation](https://neo4j.com/docs/neo4j-graphrag-python/current/).
