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
| R5 | Linked alerts appear as one incident, ordered by MITRE ATT&CK tactic | The scripted attack's alerts form exactly one incident in the right order |
| R6 | The incident story is drafted by an LLM. Every sentence cites node IDs and any sentence citing an ID outside the incident is dropped. Without an LLM key, the incident's facts are shown as a list instead. | Feed a fake LLM answer with a wrong ID and check that the sentence is dropped |
| R7 | The analyst marks an alert as real or false and the verdict is saved on the alert | Read the alert back from Neo4j |
| R8 | The scripted attack's alerts rank in the top 5 of about 30 alerts | Seed the sample data and check the inbox order |

## 4. What it does not do

These are left out on purpose. They are not bugs.

- No Kafka streaming. Data is loaded in one batch.
- No LANL data. Only the sample organisation and scripted alerts.
- No training of the ranking model. Verdicts are saved for later training. Scores use hand-set weights.
- No plain-English question box.
- No granted vs used access view.
- No choke point comparison screen.
- No AI agents in the sample organisation.
- No logins, user accounts or roles.
- No cloud hosting. It runs on a laptop.
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
