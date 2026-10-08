# Build plan

Draft. Dates are in IST.

## Deadlines

| Date | What |
|---|---|
| 31 October 2026, 11:59 PM | Prototype submission closes |
| 14 to 15 November 2026 | 30-hour in-person hackathon, New Delhi |

That gives us about 3.5 weeks to a working prototype, then two weeks to polish before the in-person round.

## What must work by 31 October

The core demo, end to end:

1. A scripted attack streams through Kafka into Neo4j.
2. Alerts appear in the dashboard ranked, each with its reasons.
3. Clicking an alert shows its 1, 2 and 3 hop blast radius.
4. Linked alerts merge into one incident in ATT&CK order.
5. Attack paths and choke points are shown for the network before any attack.
6. The shrinking circle: blast radius over granted access and over used access.
7. Never-taken path detection runs on a LANL slice with measured precision and alerts per day.

8. The three AI parts in a first working version:
   - ranking model trained with scikit-learn
   - incident story with checked node citations
   - plain-English questions through Text2Cypher

Nice to have by 31 October. Must have by 14 November:
- Ranking model retrained from feedback given in the dashboard.
- The three-way choke point comparison.

Bonus if time allows: decoy placement suggestions.

## Roles

Five roles, one owner each. Owners pair up when one area runs ahead or falls behind.

| Role | Owns | Skills that help |
|---|---|---|
| A. Data and streaming | Docker Compose, Kafka, the live data simulator, the graph loader, ADSynth and LANL loading | Python, Kafka, Docker |
| B. Graph analytics | Graph schema, the background graph analysis, attack paths, choke points, blast radius | Python, Cypher, graph algorithms |
| C. Detection and ranking | The alert ranker, never-taken path rules and noise filters, alert linking, the attack scenario script, the LANL evaluation | Python, data analysis |
| D. Dashboard | The dashboard: NVL graph view, alert inbox, blast radius rings, incident view | React, JavaScript |
| E. API, AI and quality | The backend server, the incident story writer, the plain-English question box, the ranking model, tests and GitHub Actions | Python, APIs, testing |

Who takes which role is for the team to decide.

## Timeline

### Week 1: 8 to 14 October. Foundation

| Role | Task | Done when |
|---|---|---|
| All | Agree on the graph schema: node types, edge types, properties and ATT&CK tags | Schema written in `docs/schema.md` |
| A | Docker Compose with Neo4j (GDS and APOC) and Kafka | `docker compose up` starts both |
| A | Request LANL 2015 access on day one | Request sent |
| A | Generate an ADSynth network and load it into Neo4j | Users, groups, computers and permissions visible in Neo4j |
| A | Live data simulator and graph loader for one topic | Events written to Kafka show up in Neo4j |
| B | Pick the critical assets and low-trust zones in the ADSynth network | Listed and tagged in the graph |
| C | Write the scripted attack scenario: entry point, hops, alerts and expected story | Scenario file with expected results |
| D | React app skeleton showing a graph from Neo4j with NVL | A page renders nodes and edges |
| E | Backend server skeleton (FastAPI), test setup with Testcontainers, GitHub Actions running | One passing test on every push |

### Week 2: 15 to 21 October. Core analysis

| Role | Task | Done when |
|---|---|---|
| A | All topics flowing: identity, EDR events, network flows, alerts, CMDB | The full scenario replays end to end |
| B | Attack paths with Dijkstra and Yen's k shortest paths | Top paths from low-trust zones to critical assets returned |
| B | Blast radius at 1, 2 and 3 hops | API returns the rings for any node |
| B | Precompute distance to the nearest critical asset on every node | Stored as a node property, refreshed on a timer |
| C | Alert linking with connected components and ATT&CK ordering | The scenario's alerts merge into one incident |
| C | Score version 1 with hand-set weights | Every alert gets a score and reasons |
| D | Alert inbox and blast radius rings | Clicking an alert draws its rings |
| E | REST endpoints and WebSocket push | New alerts appear in the dashboard live |

### Week 3: 22 to 28 October. What makes us different

| Role | Task | Done when |
|---|---|---|
| A | Load a LANL slice around the red-team window | Slice in Neo4j with red-team labels attached |
| B | Choke points with betweenness and min cut | Ranked list with "remove these N permissions" impact |
| B | Granted vs used blast radius | Two sets of rings for the same user |
| C | Never-taken path rule with automation filtering and account-switch detection | Runs on the LANL slice |
| C | Evaluation on LANL | Precision, true and false positives and alerts per day written to `docs/results.md` |
| D | Incident story view, attack path view, shrinking circle view | All demo screens clickable |
| E | Incident story writer: Cypher pulls the incident subgraph, the LLM drafts the story, a checker verifies every cited node ID | Story for the scripted attack with all citations valid |
| E | Plain-English question box with `Text2CypherRetriever`, run in a read-only transaction | "What can this laptop reach?" returns the right nodes, and a write attempt is refused |
| E | Ranking model version 1 with scikit-learn, trained on labelled scenario and LANL alerts | Scores compared against hand-set weights in `docs/results.md` |

### 29 to 31 October. Freeze and submit

| Task | Done when |
|---|---|
| Known-answer, replay, break and speed tests pass | All green in GitHub Actions |
| Setup steps tested by a teammate on a clean machine | They start it from the README alone |
| Demo recording | Under 3 minutes, covers the core demo |
| Disclosure list in README | Every AI tool, library, API and dataset listed |
| Submission | Uploaded before 31 October, 11:59 PM |

### 1 to 13 November. Polish

- People test with at least 3 people. Record times.
- Ranking model learns from analyst feedback given in the dashboard (mark alert as real or false).
- Three-way choke point comparison.
- Rehearse the pitch and the demo until it runs without notes.
- Decoy placement if time allows.

### 14 to 15 November. Hackathon

Fix, polish and present. No new features unless the core demo is solid.

## Decisions still open

| Decision | Options | Needed by |
|---|---|---|
| LLM provider | To be chosen. Must work with `neo4j-graphrag`. Sarvam is a hackathon partner but we have not checked its API. | Week 2, so role E can start in week 3 |
| Size of the LANL slice | A few days around the red-team window | Week 3 |
| Edge risk weights | Our design choice, documented in `docs/schema.md` | Week 2 |
| Ranking weights | Hand-set first, learned later | Week 2 |

## Risks

| Risk | What we do |
|---|---|
| LANL access is slow to arrive | Request on day one. Build everything on ADSynth and the scripted scenario first. |
| LANL files are large | Load only a slice. Keep raw files out of git. |
| ADSynth pins an old Neo4j Python driver (4.4.10) | Run ADSynth in its own environment and import its output files. |
| Kafka setup eats time | Start with one topic and one consumer. Add topics after the pipeline works. |
| The demo breaks live | Keep a recorded demo as backup. |
| Scope creep | Anything outside "What must work by 31 October" waits. |
