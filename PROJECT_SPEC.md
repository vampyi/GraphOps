# PROJECT_SPEC

Spec for the first working flow of GraphOps. Every build conversation starts from this file.

## 1. What is this

GraphOps ranks every security alert by where it sits on the attacker's map, using a Neo4j graph of a company's users, machines and permissions. This first version covers one flow: from a ranked alert inbox to an alert's blast radius, its linked incident and the incident story, ending with the analyst's verdict.

## 2. Who uses it

An IT or security analyst at a medium-sized Indian company who handles alerts from several tools without Microsoft's full security stack.

## 3. What it must do

Each requirement can be tested.

| # | Requirement | How we test it |
|---|---|---|
| R1 | Load the sample organisation's network and a scripted attack with noise alerts into Neo4j with one command | Run the command on an empty database and count nodes, edges and alerts |
| R2 | Show every alert in an inbox, highest score first, each with the reasons behind its score. No alert is hidden. | Inbox count equals alert count in Neo4j |
| R3 | Score each alert on at least four graph questions: hops to the nearest critical asset, critical assets within 3 hops, links to other alerts and never-taken path | Unit tests on a small graph with known answers |
| R4 | Clicking an alert draws its 1, 2 and 3 hop blast radius | Rings match a Cypher query run by hand |
| R5 | Linked alerts appear as one incident, listed by time, whose tactics follow MITRE ATT&CK order | The scripted attack's alerts form exactly one incident in the right order |
| R6 | The incident story is drafted by an LLM. Every sentence cites node IDs and any sentence citing an ID outside the incident is dropped. Without an LLM key, the incident's facts are shown as a list instead. | Feed a fake LLM answer with a wrong ID and check that the sentence is dropped |
| R7 | The analyst marks an alert as real or false and the verdict is saved on the alert | Read the alert back from Neo4j |
| R8 | The scripted attack's alerts rank in the top 5 of about 30 alerts | Seed the sample data and check the inbox order |

## 4. What it does not do

These are left out on purpose. They are not bugs.

- No Kafka streaming. Data is loaded in one batch. Streaming is the next flow, designed in [docs/streaming.md](docs/streaming.md).
- No real data. Only the sample organisation and scripted alerts. (Later flows added the APT29 lab recording and live real sources; the LANL dataset was dropped.)
- No training of the ranking model. Verdicts are saved for later training. Scores use hand-set weights.
- No plain-English question box.
- No granted vs used access view.
- No choke point comparison screen.
- No AI agents in the sample organisation.
- No logins, user accounts or roles.
- No cloud hosting in this spec. It runs on a laptop. After the flow worked we also put a copy on Vercel with Neo4j AuraDB Free and Aiven Kafka, described in [docs/hosting.md](docs/hosting.md).
- No real company data.

## 5. What data it uses

| Data | Source | Sensitive? |
|---|---|---|
| Sample organisation network: users, computers, groups and permissions | A small synthetic network in the repository, using the names in `docs/schema.md` | No. All synthetic. |
| Scripted attack and noise alerts | A synthetic alert file in the repository | No. All synthetic. |
| LLM API key | A local `.env` file | Yes. Never committed. `.env` is in `.gitignore`. |

## 6. Constraints

- **Time:** working by 20 October 2026.
- **Tools:** free only. Neo4j Community with Graph Data Science and APOC, Python, React. One LLM API key.
- **Machine:** a laptop with 16 GB of memory running Docker.
- **Skills:** built by a data engineer new to cybersecurity, with AI assistance.

## 7. What done means

Someone who has never seen GraphOps can:

1. clone the repository,
2. start it with one command following the README,
3. open the dashboard and complete the flow: inbox, blast radius, incident story, verdict,

and requirements R1 to R8 pass.

## 8. What is still unknown

| Unknown | Status |
|---|---|
| Which LLM provider to use | Resolved: Claude through the Anthropic SDK, logged in with `ant auth login` so no API key is stored. The account needs API credit before stories are drafted. |
| Whether NVL is easy to use in React | Resolved: NVL's licence only allows use with Neo4j Aura or Neo4j's commercial products, so we draw the graph ourselves in SVG instead. |
| Whether the Graph Data Science plugin installs cleanly in Docker on this laptop | Resolved: Neo4j, Graph Data Science and APOC 2026.09.0 all load. |
| Good ranking weights | Open: hand-set weights in `backend/app/scoring.py` pass R8 on the sample data. They are our design choice, not measured. |

---

# Flow 2: SOC-ready (branch `feature/soc-ready`, October 2026)

The first flow proved the idea on one scripted day. This flow turns GraphOps into something a security team could run on its own network and that judges can click through end to end. It follows the problem statement's four capabilities and the "what a good solution demonstrates" list, and the team's own research notes (branch `raja`, `docs/data-and-testing-research.md`).

## 1. Goals, in order

1. **Pre-incident exposure.** Map the attack paths from low-trust machines to critical assets, name the choke points and show which few permissions or sessions to remove to cut the most paths, with the effect recomputed exactly.
2. **Zero trust in numbers.** Compare the access each identity is granted with the access it actually uses, and draw the blast radius twice: granted and used. The gap is the risk least privilege removes.
3. **Live.** Alerts arrive while the analyst watches, scores and incidents change in front of them, and the dashboard says what moved and why.
4. **Structure, not rules.** Louvain communities over observed activity. An incident that spans communities is lateral movement; a first-time route that crosses communities is stranger than one inside them.
5. **Real data in.** One event schema, reachable three ways: Kafka topics, an HTTP webhook (with field maps for common SIEM and EDR alert formats) and file imports (BloodHound SharpHound JSON; CSV for inventory, logons and flows is planned).
6. **Analyst workflow.** Verdicts that match how SOCs grade (real, benign, false), incident status and notes, and a one-click incident report whose sections follow what CERT-In's 6-hour report asks for.
7. **Deployable.** `docker compose --profile app up` runs the whole stack. Tests run on every push.

## 2. Requirements and how each is tested

| # | Requirement | How we test it |
|---|---|---|
| R9 | `GET /api/exposure` lists every shortest attack path from low-trust machines (and optionally all identities) to critical assets, each edge tagged with its MITRE ATT&CK technique, plus choke points ranked by paths through them and a minimum edge cut. | Known-answer unit tests on a 13-node graph; on the sample organisation `server-7` is a choke point. |
| R10 | `POST /api/exposure/simulate` recomputes reachability after removing chosen nodes or edges and reports pairs and paths cut, exactly, not estimated. | Removing `laptop-42 -HasSession-> it_admin` cuts every path from the low-trust zone; removing `g_helpdesk` leaves the Domain Admins path. |
| R11 | `GET /api/entities/{id}/access` returns granted reach, used reach (last N days) and the grants never used. `GET /api/access/overview` ranks identities by unused grants. | `it_admin` holds admin rights on 9 machines and used 4 in the last 30 days. |
| R12 | Blast radius takes `mode=all|granted|used`; the used radius is never larger than the granted one on the sample data. | Compare node counts for `a-03` across modes. |
| R13 | Louvain communities are stored on every entity (`community`). Incidents report the communities they span. (Planned: the never-taken reason says when a route crosses communities.) | The attack incident spans at least 2 communities. Works without Graph Data Science (networkx fallback). |
| R14 | Incident IDs are stable across re-scoring: an incident keeps its ID when alerts join it. Incident status and notes survive re-scoring. | Score, add an alert that joins the incident, score again: same ID, notes intact. |
| R15 | The dashboard polls `/api/live` while a replay runs, shows new alerts within one poll, and marks rank changes. Replay can be started and reset from the dashboard. | Streaming test already proves the API; a frontend build plus a scripted API walk-through covers the flow. |
| R16 | `PATCH /api/assets/{id}` marks an asset critical or sets its zone and re-runs the analysis and scoring. | Mark `server-files` critical: `printer-01` gains no path (not an attack edge), alerts on `hr_1` gain hops points. |
| R17 | Verdicts accept `real`, `benign` and `false`, and record who and when. | Read back from Neo4j. Unknown values still return 422. |
| R18 | `POST /api/ingest` accepts a batch of events in the streaming schema; `POST /api/ingest/alerts?format=...` maps alert payloads shaped like Microsoft Sentinel, Splunk ES, Elastic Security and Wazuh into it. Unknown hosts and accounts named by an alert are created so the graph grows from telemetry. | Sample payloads per format produce the expected alert, entities and ATT&CK tags; the alert is scored on the next read. |
| R19 | `python -m app.import_bloodhound <dir or zip>` loads SharpHound JSON (users, groups, computers) into the schema, with Tier Zero groups and domain controllers marked critical. | A small SharpHound-shaped fixture (6 nodes, 5 edges) loads with the expected counts and Tier Zero marked critical. |
| R20 | `GET /api/incidents/{id}/report` returns a Markdown report: summary, timeline in ATT&CK order, affected assets, blast radius, communities, recommended containment, and the analyst's notes. | The attack incident's report names all four alerts and `customer-db`. |
| R21 | Existing requirements R1 to R8 still pass unchanged. | Same tests. |

## 3. What it does not do

- No ranking model trained on verdicts yet. Verdicts now carry analyst and time so training is possible later.
- No plain-English question box. Every analytic has a fixed, read-only Cypher or Python path and shows its numbers.
- No sign-in. The hosted site is a public demo: a real lab recording and a synthetic company, with real laptops and an AI agent reporting in.
- The sample organisation stays as it is. Realism work (default rights, hubs, normal first-time routes) belongs in a separate dataset, as the research recommends.
- Field maps for SIEM formats are written from public documentation and sample payloads we wrote. They are starting points to check against a real tenant, not certified connectors.

## 4. Design decisions

- **Paths come from Neo4j, remediation maths from Python.** `allShortestPaths` in Cypher finds the paths; `networkx` ranks choke points, finds the minimum cut and recomputes reachability after a simulated fix. This runs the same on AuraDB Free (no Graph Data Science) and on a laptop.
- **One event schema for every door.** Kafka, the webhook and the file importers all produce the same JSON events and go through `events.apply_batch`, so every path is idempotent and tested once.
- **IDs are names.** Imported identities use their principal name (`jdoe@corp.local`) as `id` so the dashboard reads naturally; the SID is kept as a property.
- **Honest numbers.** Every "cuts X of Y paths" figure is recomputed on the graph after removal, never estimated from betweenness.

## 5. Order of work

1. Backend analytics (`exposure.py`, `access.py`, `communities.py`, `attack.py`), stable incidents, asset and verdict endpoints, with tests.
2. Dashboard: view switcher (Triage, Exposure, Access), live mode, blast radius modes, critical toggle, incident workflow and report.
3. Ingest: webhook and field maps, BloodHound and CSV importers, with fixtures and tests.
4. Deployability: Dockerfiles, compose profile, GitHub Actions. Docs: README status, analyst guide, ingest guide, corrections from the research notes that touch this work.

# Flow 3: real data and response (late October 2026)

What changed after flow 2, all on `main`. Each part has tests in `backend/tests`.

| Part | Where |
|---|---|
| Tabs merged to Triage, Attack paths (Exposure + Explore), Access, AI agents, Graph (with the Proof table) and Ask | `frontend/src/Dashboard.jsx` |
| Real data: two choices in the picker, the APT29 lab recording with public SigmaHQ rules and "Real data" (only the team's live laptops and agents); the demo company and the other days used only for the Proof table | [docs/data-sources.md](docs/data-sources.md), [docs/evaluation.md](docs/evaluation.md) |
| Live real sources: team laptops through osquery, a Claude Code agent's access and activity, behind `INGEST_TOKEN` | `backend/app/sources.py`, `collectors/` |
| Cloud resources, AI agents and real CVEs (NVD, CISA KEV, EPSS) in the attack graph | `data/sample_org/cloud_ai.json`, `backend/app/vulns.py` |
| Respond panel: who to tell, containment steps recorded as requested, the CERT-In 6-hour clock and report draft; email built but off on the public demo | `backend/app/respond.py`, `frontend/src/Respond.jsx` |
| "How it started" on every incident and report | `backend/app/report.py` |
| A lock so only one visitor reloads the shared demo data at a time | `backend/app/scenarios.py` |
| The Graph tab drawn with Neo4j NVL on Aura, five algorithm views | `frontend/src/NvlMap.jsx`, `GraphEngine.jsx` |

