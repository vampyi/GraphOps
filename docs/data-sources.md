# Data sources

Every dataset GraphOps uses in the demo, what kind of data it is, what it feeds, and the licence duties that come with it. Use this table when a slide, a judge or a teammate asks "is this real?".

**Kinds of data**
- **Synthetic:** written by us or generated. Nothing in it happened.
- **Controlled simulation:** a real attack run on purpose in a lab, recorded by real tools.
- **Real observed:** recorded from real machines or real public sources.
- **Derived by us:** our own rules, labels or scores computed on top of other data.

Attack or noise labels are always ours and are used only to score the ranking, never by the ranker.

**What the site shows.** The scenario picker has two choices: **APT29 attack (real lab logs)**, and **Real data (live laptops & AI agents)**, which holds only what the team's laptops and Claude Code agents report live. The demo company, the five other synthetic days and our own-rules build of the APT29 day are kept only as labelled test days for the Proof table.

## In the demo today

| Source | Kind | What it feeds in GraphOps | Licence and duties | Limits |
|---|---|---|---|---|
| Sample organisation ([network.json](../data/sample_org/network.json), [alerts.json](../data/sample_org/alerts.json)) | synthetic, hand-written | the demo company, the tuning day in the Proof table (not in the picker): 37 users, groups and machines, 30 alerts, one scripted attack; tests R1-R8 | ours | fictional and easy; see [data-and-testing-research.md](data-and-testing-research.md) |
| Cloud and AI-agent extension ([cloud_ai.json](../data/sample_org/cloud_ai.json)) | synthetic; the AI agents are illustrative, built from documented patterns | cloud resources, AI agents, an internet-facing web server and their attack routes in Explore and Attack paths | ours | no alert involves these nodes yet (see [coverage](#demo-coverage-cloud-on-premises-and-ai-agents)) |
| Real data ([real_data.json](../data/scenarios/real_data.json)) | real observed, live | "Real data (live laptops & AI agents)" in the picker: an empty day, so the graph holds only what team laptops and Claude Code agents report | the owners' consent | no labels, so not in the Proof table |
| Five held-out days ([data/scenarios](../data/scenarios)): finance breach, backup account abuse, file server ransomware, missed detections, slow burn | synthetic, hand-written | the Proof table only (not in the picker): ranking measured on days the weights were not written on | ours | written by the team to test known weaknesses; not real attacks |
| APT29 day 1, GraphOps rules ([apt29_day1.json](../data/scenarios/apt29_day1.json), [build.py](../tools/apt29/build.py)) | controlled simulation (the logs); derived by us (the alerts and labels) | the Proof table only (not in the picker): the same lab recording with 38 alerts from a dozen rules written for GraphOps; on this build GraphOps ranks worse than severity (average precision 0.71 vs 0.87), and we report it | logs: MIT, [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29/day1); keep the MIT notice with copies of the logs | 33 minutes in a lab, almost no normal activity; streams only its alerts and one logon |
| APT29 day 1, Sigma rules ([apt29_day1_sigma.json](../data/scenarios/apt29_day1_sigma.json), [sigma_day.py](../tools/apt29/sigma_day.py)) | controlled simulation (the logs); real public rules; derived by us (the labels) | "APT29 attack (real lab logs)" in the picker: the recording as its own small network (4 machines, 1 user) with alerts from public SigmaHQ rules, and the lab's own logons, process starts and connections streamed through the Kafka topics | logs: MIT (OTRF). Rules: [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License); every alert keeps its rule's id, author and link; sharing the rules themselves also needs a link to each rule and the licence text or a link to it | see [below](#apt29-day-1-with-sigma-rules) |
| Team laptops through osquery ([collectors/osquery](../collectors/osquery/README.md), [sources.py](../backend/app/sources.py)) | real observed, live | Connected sources on the Graph tab, the live graph (the machine under its host name, each account as `user-xxxx@<host>`) and triage alerts tagged REAL for changes (new admin, new listening port, sign-in, firewall or encryption off) | the laptop owner's consent; [osquery](https://osquery.io) is open source | names and settings only: masked account names, no files, command lines or IP addresses; only while the script runs |
| A Claude Code agent on a team laptop ([collectors/claude_code](../collectors/claude_code/README.md), [sources.py](../backend/app/sources.py)) | real observed, live | the AI agents tab and the graph: what the agent can reach (folders, secret files by name, the services their keys open, signed-in accounts, tools), its past-session counts, live tool calls, and routes from the open web through it | the agent owner's consent | names only, no contents or key values; AWS profiles counted, not named; files outside the project show as "a file in the home folder"; the activity is the owner's own work, not a labelled attack |
| Vulnerabilities: [NIST NVD](https://nvd.nist.gov/developers), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/) ([vulns.py](../backend/app/vulns.py)) | real observed, public | CVEs on the software each machine runs; an exploitable internet-facing CVE adds a `CanExploit` attack step | check each source's terms before redistributing; the code notes KEV as CC0 | a saved snapshot ([vuln_snapshot.json](../data/vuln_snapshot.json), fetched 28 October 2026), not live |
| [MITRE ATT&CK](https://attack.mitre.org) | real public reference | tactic and technique IDs on alerts and attack steps | [ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/): keep MITRE's copyright notice with copies | IDs only; no ATT&CK data is copied into the repository |
| Ranking results ([proof.json](../data/proof.json)) | derived by us | the Proof table on the Graph tab | ours | measured on the 8 labelled days above on 31 October 2026, with the real sources left out; the labels are ours |

Doors for a team's own data (nothing of this kind is in the repository): a BloodHound or SharpHound collection ([import_bloodhound.py](../backend/app/import_bloodhound.py)), the webhooks and the Kafka topics ([ingest.md](ingest.md)).

## Tried and not in the demo

| Source | Kind | Status on 31 October 2026 |
|---|---|---|
| AWS CloudTrail and IAM from a team account | real observed | added on `main` on 30 October, then reverted: the only account available belonged to a company, so its data must not be published. A separate demo account would be needed. |
| LANL Cyber1 (58 days of a real network with a red-team exercise) | mixed: real activity with a controlled red-team exercise | dropped: the authentication file is 7.2 GB and was not downloaded in time. The APT29 lab recording is our real-data day instead. |

## APT29 day 1 with Sigma rules

**What it is.** MITRE's ATT&CK Evaluations APT29 day 1 emulation, recorded by OTRF on four lab machines (SCRANTON, NASHUA, UTICA and the domain controller NEWYORK) between 02:55 and 03:28 UTC on 2 May 2020: 196,081 Windows Security, Sysmon and PowerShell events. The attacker opens a disguised payload on SCRANTON, bypasses User Account Control, dumps credentials, moves to NASHUA with WinRM and PsExec, compresses and steals files, and leaves persistence that fires after a reboot.

**Alerts.**
- The 2,095 Windows rules in SigmaHQ release `r2026-07-01` (the `sigma_core+` package) are converted with pySigma (Sysmon and Windows log-source pipelines, SQLite backend) and run over all 196,081 events.
- 2,083 rules convert. 12 do not. 142 queries need fields this recording does not have.
- The first match of each rule per machine becomes one alert at the real time on the real machine: 73 alerts, 21 high and 52 medium.
- Each alert keeps the rule's title, level, ATT&CK tags, id, author and link, plus the matched event in short. Command-line passwords are removed and script contents are left out.

**Labels (ours).** 55 alerts are attack and 18 are noise, following the published emulation plan:
- the attacker's process trees: the payload, the services PsExec and the persistence installed, the program the Startup-folder shortcut runs, the attacker's remote PowerShell sessions, anything that contacts the attacker's server, and everything those started;
- everything done as `pbeesly` on NASHUA (pbeesly works only on SCRANTON, so that is the lateral movement);
- the logon from SCRANTON onto NASHUA.

The noise alerts are real false alarms: Azure's own agents, Microsoft Defender changing its own settings, the domain controller's WMI and routine LSASS access checks.

**Activity streamed through Kafka.** With the attack (628 messages), and only the background without it (465):

| Topic | Messages | From |
|---|---|---|
| `identity` | 24 | Windows logons (event 4624) by the user: network logons whose source address is a lab machine become `RemoteLogon`, interactive ones `LoggedInto` |
| `flows` | 81 | Sysmon network connections between lab machines, one per machine pair, port and minute |
| `edr` | 446 | Sysmon process starts: process and parent names only, no command lines |
| `alerts` | 73 | the Sigma alerts above |
| `cmdb` | 4 | the four machines |

**Limits.**
- A lab, not a company: one user, four machines and 33 minutes, so the attack dominates and there is little normal activity.
- Left out: 600 connections to addresses outside the lab machines (including the attacker's servers), 6 network logons with no known source machine and one process start the recording cut short.
- The starting network is the one in `apt29_day1.json`; its routes before the recording are an assumption written there.
- Sigma's own `level` is used as severity, so the scale is not the same as the hand-written days'.

**Rebuild it.** pySigma is needed only for this, not by the backend.

```
python3 -m venv /tmp/sigma-venv
/tmp/sigma-venv/bin/pip install pysigma pysigma-backend-sqlite pysigma-pipeline-sysmon pysigma-pipeline-windows
# apt29_evals_day1_manual.zip from OTRF (link above), unzipped; sigma_core+.zip from the SigmaHQ r2026-07-01 release
/tmp/sigma-venv/bin/python -I tools/apt29/sigma_day.py apt29_evals_day1_manual_2020-05-01225525.json sigma_core+.zip r2026-07-01 > data/scenarios/apt29_day1_sigma.json
```

The build is repeatable: the same inputs give the same file.

## Demo coverage: cloud, on-premises and AI agents

Checked by [test_demo_coverage.py](../backend/tests/test_demo_coverage.py) on the files the demo loads.

| Area | Clear example in the demo | Kind | Gap |
|---|---|---|---|
| On-premises | The APT29 recording replayed through Kafka with Sigma alerts; the sample day's scripted attack; team laptops reporting live through osquery | controlled simulation; synthetic; real observed | none |
| Cloud | An attack route from the on-premises user `fin_1` through the synced cloud account `fin_1@cloud`, the agent `finance-agent` and the service principal `sp-finance` to the critical key vault `kv-prod`; the real Claude Code agent's keys to cloud services (AWS, Neo4j AuraDB, GitHub) | synthetic; real observed | no alert or activity on a cloud resource in a labelled day; the live AWS source was reverted |
| AI agents | An attack route from the internet through the support inbox into `support-agent` (untrusted email it reads: prompt injection), its tool `ops-mcp`, the jump host `jump-01` and on to the domain controller `dc-01`; a real Claude Code agent reporting its access and every tool call live | synthetic, illustrative; real observed | no alert on an AI agent in a labelled day |

The last test in that file is an expected failure that records the gap. It starts passing when a labelled day has an alert on a cloud resource or an AI agent; then remove its `xfail` marker.
