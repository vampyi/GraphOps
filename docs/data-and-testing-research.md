# Realistic data and testing research

Research on three questions:

1. How can GraphOps' data look more like a real company's network?
2. How should we test the website, from the ranked inbox to the analyst's verdict?
3. Where can we get realistic cybersecurity data, and how would it fit our schema?

Like [research.md](research.md), it is written for teammates who are new to cybersecurity. If a word is unfamiliar, check [glossary.md](glossary.md).

**This is research only.** Nothing in it is built. No code, data, tests or settings were changed to write it, and no tests were run. Every source was checked on 14 October 2026.

## How to read this document

- The research sections (1 to 3) end with their sources. Repository references look like [scoring.py L77-L78](../backend/app/scoring.py#L77-L78). Their line numbers were read on branch `raja` at commit `7f3e171`. The links open the current version of each file, so the lines may move as the code changes.
- **Our view** marks our own reasoning. **Our analysis** marks numbers we worked out ourselves from repository files or from published figures.
- **(re-implementation)** marks numbers from a small stand-alone script that copies GraphOps' loading, analysis and scoring rules and runs them on a copy of the sample data. It does not run GraphOps, Neo4j or the tests. Two such scripts, written separately for this research and not stored in the repository, gave the same numbers. They also match what the repository's own tests expect: 53 edges after loading the day (the 52 in `network.json` plus the attack's one new route), the R3 hop counts and the R8 top 5. Treat them as expected values to confirm with GraphOps' own tests.
- Every data source is labelled with the kind of data it holds:

| Label | Meaning | Examples |
|---|---|---|
| **Synthetic** | Made up by a program or by hand. Nothing in it happened. | our sample organisation, ADSynth, the CERT insider dataset |
| **Real observed** | Recorded from a real network during normal work, usually anonymised | LANL Cyber1 background activity, Microsoft GUIDE |
| **Controlled simulation** | Attacks run on purpose by a red team (testers who attack with permission) or an emulation tool (software that replays known attack steps), in a lab or on a real network | LANL's red-team events, DARPA OpTC, OTRF Security-Datasets |
| **Mixed** | Real background activity with simulated or red-team attacks inside it | LANL Cyber1 as a whole, the data behind the Hopper paper |

Two rules hold everywhere in this document:

1. **Identities from different datasets are never the same entity.** LANL user `U748@DOM1`, an ADSynth user and our `intern_a` are unrelated. We never join them or copy activity from one onto another.
2. **A permission is not activity.** `MemberOf`, `AdminTo`, `CanRDP` and `GenericAll` say what someone *may* do. They never prove that anything happened. `HasSession` is a snapshot of who was logged in at one moment (in ADSynth, a random guess), not a permission and not a timeline.

**Words used in this document**

| Word | Meaning here |
|---|---|
| Attack alert | One of the four scripted attack alerts, `a-01` to `a-04`. In other data, an alert caused by a real or simulated attack. |
| Noise alert | Any alert that is not an attack alert. The sample day has 26, `n-01` to `n-26`. |
| False alarm | A flag or alert on activity that is not an attack. In GraphOps' ranking measures: a noise alert ranked above a cut-off. |
| Benign positive | Real activity that looks like an attack but is allowed, such as an admin's maintenance work. Microsoft keeps it apart from a false positive, which comes from wrong alert logic or wrong data. |
| Route | One remote logon path from one computer to another, such as `laptop-42` to `server-7`, stored as a `RemoteLogon` edge |
| Never-taken path | GraphOps' check for a route that touches the alert's machine or account and was first used in the 2 hours before the alert ([scoring.py L41-L54](../backend/app/scoring.py#L41-L54)) |
| Blast radius, rings | Everything within 1, 2 and 3 hops of an alert's machine or account. The dashboard draws each hop as a ring. |
| Questions and points | GraphOps scores each alert out of 100 with hand-set weights ([scoring.py L11](../backend/app/scoring.py#L11)): "hops" (steps to a critical asset) 25, "linked" (other alerts in its incident) 20, "blast" (critical assets within 3 hops) 15, "never-taken" 15, "stages" (its incident follows attack stages in order) 15, "choke" (it sits on a choke point) 5, and the tool's own severity 5. The README calls the first six "questions". |
| R1-R8 | The eight requirements in [PROJECT_SPEC.md](../PROJECT_SPEC.md), each checked by a test in [test_requirements.py](../backend/tests/test_requirements.py) (R6 by two). For example, R5: the attack's alerts form one incident. R8: they rank in the top 5. |
| Logon, login | The same thing. Windows and LANL say "logon". |

## Contents

0. [Summary](#0-summary)
1. [How to make the data more realistic](#1-how-to-make-the-data-more-realistic)
2. [How to test the website](#2-how-to-test-the-website)
3. [Where to get realistic data](#3-where-to-get-realistic-data)
4. [Prioritised recommendations](#4-prioritised-recommendations)
5. [Things in our other documents that need correcting](#5-things-in-our-other-documents-that-need-correcting)
6. [What we could not verify](#6-what-we-could-not-verify)

---

## 0. Summary

**Data realism**

1. **The sample day makes GraphOps' questions look far easier than real data would.**
   - The everyday simulator never creates a new route or a remote logon, so the attack's first hop is the only new route of the day. The never-taken-path question therefore cannot raise a false alarm on this day.
   - 18 of the 26 noise alerts sit on users and machines with no attack path to a critical asset.
   - The attack alerts are medium or low severity, while 10 noise alerts are high or critical.
   - The whole attack takes 31 minutes and every step raises an alert. The two lateral-movement alerts carry exactly the time of their logons, and the alert IDs (`a-` for attack, `n-` for noise) give the answer away.
   - The hand-set weights have only ever been checked with R8, on these same 30 alerts. ([1.2](#12-what-makes-it-unrealistic))
2. **The sample day already shows a grouping weakness.**
   - Noise alert `n-11` shares the `it_admin` account with attack alert `a-03` within 2 hours. It joins the attack incident and ranks 2nd (re-implementation), and no test checks for this.
   - Small, realistic changes split the attack or pull in noise: a missing alert, one second of clock drift, normal reuse of a route, a multi-day attack, or a helpdesk logon on a new route. ([1.3](#13-what-the-sample-day-already-shows))
3. **Real networks look different.**
   - Default rights make everyone able to log on almost everywhere.
   - Computer accounts and busy hub machines dominate the logs.
   - Normal first-time routes are common: a first-time-login rule on LANL raised 530,082 false alarms in 18 days.
   - Most graded incidents are not attacks: of the incidents graded for Microsoft's GUIDE paper, 46% were benign positives (real activity that is allowed), 35% false positives and only 19% true positives.
   - Attacks take from seconds to years, many steps raise no alert, and data arrives late and out of order. ([1.4](#14-what-real-enterprise-data-looks-like))

**Testing**

4. **Backend tests are good, but much is missing:** browser, frontend and accessibility tests; automatic test runs; tests of the incident, story and replay endpoints; the choke-score code the hosted site uses; a check that the attack incident holds only attack alerts; latency percentiles. We recommend:
   - Playwright's Node test runner (it drives a real browser), mostly against a faked API, plus one or two full-stack runs;
   - a contract test (checks the shape of each API reply), Vitest (frontend component tests), axe (automatic accessibility checks) and Schemathesis (generated API requests);
   - GitHub Actions;
   - strict rules that keep tests away from the hosted site's shared data. ([2.1](#21-what-is-tested-today) to [2.8](#28-continuous-integration-and-test-safety))
5. **How to measure.**
   - Ranking: precision@k, recall@k, the rank of the last attack alert, false alarms per day and average precision, with ROC-AUC only as a secondary figure.
   - Grouping: split and contamination counts plus B-cubed.
   - Stories: citation measures plus human review.
   - Latency: the p50, p95 and p99 times (the times that 50%, 95% and 99% of alerts beat), from at least 100 samples, on one clock, from the intended send time.

   Sample-day values are worked examples, not evidence. ([2.9](#29-how-to-measure-ranking-grouping-the-story-and-speed), [2.10](#210-rules-for-honest-evaluation))

**Data sources**

6. **ADSynth** generates synthetic permission graphs. It needs an offline adapter (a one-off script that converts its file to our `network.json` format): its output does not load "as-is" as our schema says, and its `highvalue` flag is a poor rule for "critical". ([3.2](#32-adsynth))
7. **LANL Cyber1** is real, de-identified activity with one controlled red-team intrusion.
   - Licence and access: CC0, with a form to fill in.
   - Size: about 11 GB compressed.
   - Labels: 749 lines, a subset covering authentications by user accounts only.
   - It has no permissions, critical assets or alerts. It fits detection tests: check the pipeline on a days 1-3 slice, then evaluate on all 58 days. ([3.3](#33-lanl-cyber1))
8. **Other sources with a clear benefit:**
   - Microsoft GUIDE: real alerts in analyst-graded incidents, but no graph;
   - AIT-ADS: built for testing alert grouping;
   - PicoDomain: a tiny lab domain for testing the never-taken path;
   - OTRF Security-Datasets, Splunk attack_data and Sigma rules: realistic attack events and alert names;
   - MITRE emulation plans and Attack Flow: realistic attack sequences;
   - BloodHound CE sample data: a small permission snapshot. ([3.4](#34-other-datasets-with-a-clear-benefit))
9. **Several statements in our other documents are out of date or wrong.** Examples: "ADSynth loads as-is", and LANL detector results labelled "precision" that are average precision. ([5](#5-things-in-our-other-documents-that-need-correcting))

**Do first** (full list in [section 4](#4-prioritised-recommendations)):
- keep the sample day unchanged and build realism separately;
- run the existing tests automatically, with safety rules;
- add a test that the attack incident holds only attack alerts, and the missing endpoint tests;
- write an evaluation script and held-out scenarios (test days not used to set the weights) after freezing the weights;
- add normal novelty to the simulator;
- build a Playwright journey suite against a faked API;
- fix the documents after review.

---

## 1. How to make the data more realistic

### 1.1 What the sample organisation contains

Everything in [data/sample_org](../data/sample_org) is **synthetic** and written by hand. The network file says so: "Fictional mid-size organisation used to exercise GraphOps. All names are made up." The scripted attack is a written story. It is not a controlled simulation run by a red team or an emulation tool.

| Part | What is there | Where |
|---|---|---|
| Users | 12 accounts: 10 people and 2 service accounts (`svc_db`, `svc_backup`) | [network.json L4-L15](../data/sample_org/network.json#L4-L15) |
| Groups | 8. No group is a member of another group. Only Domain Admins is critical. | [L17-L24](../data/sample_org/network.json#L17-L24) |
| Computers | 17: 9 laptops, 7 Windows servers (one domain controller, `dc-01`: the server that runs Active Directory and checks logons) and a printer. 3 are critical: `customer-db`, `finance-db`, `dc-01`. 5 are in the `low_trust` zone. | [L26-L42](../data/sample_org/network.json#L26-L42) |
| Granted edges | 31: 12 `MemberOf`, 12 `AdminTo`, 3 `CanRDP`, 4 `HasSession`, no `GenericAll` | [L44-L78](../data/sample_org/network.json#L44-L78) |
| Observed edges | 21: 11 `LoggedInto`, 8 `RemoteLogon`, 2 `ConnectedTo`. Most were first seen on 1 September 2026. Counts run from 3 to 300. | [L79-L103](../data/sample_org/network.json#L79-L103) |
| Alerts | 30 on 20 October 2026 between 08:05 and 11:55: 4 scripted attack alerts and 26 noise alerts | [alerts.json](../data/sample_org/alerts.json) |
| New activity that day | 2 attack logons: `laptop-42` to `server-7` as `it_admin` (a route never used before), and `server-7` to `customer-db` as `svc_db` (a route in use since 1 September) | [alerts.json L420-L437](../data/sample_org/alerts.json#L420-L437) |
| Everyday activity in the live replay | 150 random events from a fixed random seed: logins on the 11 user-to-computer pairs seen before the day (mostly people's own laptops, but also `dba_1` to `customer-db` and `fin_1` to `finance-db`), traffic to the file server, and programs starting on laptops | [simulate.py L67-L95](../backend/app/simulate.py#L67-L95) |

### 1.2 What makes it unrealistic

The sample is tidy and consistent, which is right for a first demo. But it makes GraphOps' questions look easier than they would be on real data. These tables list the gaps, the evidence and why each one matters. Section [1.4](#14-what-real-enterprise-data-looks-like) gives the real-world evidence.

**Identities and groups**

| Gap | Evidence | Why it matters for GraphOps |
|---|---|---|
| No computer accounts (names ending in `$`), no built-in or local accounts, no disabled, new or departing accounts | [network.json L4-L15](../data/sample_org/network.json#L4-L15) | Real login logs are dominated by computer accounts and built-in accounts such as SYSTEM. Computer and local accounts can also carry lateral movement, so a filter that drops them hides attacks. |
| No nested groups and none of the default groups (Domain Users, Domain Computers, a computer's local Administrators, Remote Desktop Users) | [L17-L24](../data/sample_org/network.json#L17-L24), [L45-L56](../data/sample_org/network.json#L45-L56) | Each level of nesting adds a `MemberOf` hop and changes `hops_to_critical`. Default groups touch every account, so they change blast-radius sizes a lot (below). |

**Computers**

| Gap | Evidence | Why it matters |
|---|---|---|
| One domain controller and little infrastructure (a file server, a backup server and a jump host): no patch or configuration-management server, vulnerability scanner, log collector, print server or second domain controller | [L26-L42](../data/sample_org/network.json#L26-L42) | In real login graphs these are the busiest machines. Busy machines, called hubs, are where incident linking merges unrelated alerts and where 3-hop blast radii grow very large. |

**Permissions**

| Gap | Evidence | Why it matters |
|---|---|---|
| Only explicit grants. Microsoft's defaults are missing: every domain user may log on locally to workstations and member servers and make network (file-share) logons to them, and Domain Admins are local administrators on every computer. | [L44-L78](../data/sample_org/network.json#L44-L78) | 10 of the 19 observed logons have no `AdminTo`, `CanRDP` or `GenericAll` behind them, including every user's logon to their own laptop (our analysis). The planned granted-vs-used view would show normal logons as "used but not granted". Adding only the Domain Admins default grows `laptop-42`'s 1-3 hop blast radius from 14 to 21 nodes (computers from 9 to 16), while its hops to a critical asset stay at 2 (our analysis). |
| `HasSession` is stored as a granted permission | [L74-L77](../data/sample_org/network.json#L74-L77), [seed.py L58](../backend/app/seed.py#L58), [schema.md](schema.md) line 78 | A session is a snapshot of who was logged in, not a right. |
| The attack works because admin credentials sit on less-trusted machines, which breaks Microsoft's tier rules. `it_admin` (in Domain Admins and HelpDesk, and using `laptop-it1` every day) has a session on the intern's laptop; HelpDesk may administer `server-7`; and `svc_db`, a DB Admins member, has a session on `server-7`. The scripted route uses the HelpDesk right, not the Domain Admins membership. | [L53-L56](../data/sample_org/network.json#L53-L56), [L63](../data/sample_org/network.json#L63), [L66](../data/sample_org/network.json#L66), [L74-L75](../data/sample_org/network.json#L74-L75), [L88](../data/sample_org/network.json#L88), [L92](../data/sample_org/network.json#L92) | Microsoft says the Domain Admins group should hold no accounts used for daily work, and admin credentials should stay off less-trusted machines. These exposures are realistic, but they were placed so that they chain into the scripted route, so it is the attack path by design. The same session on `laptop-42` also gives a 2-hop path to Domain Admins, and HelpDesk also administers `server-files` ([L64](../data/sample_org/network.json#L64)), a server with no onward path. Say so when presenting it. |

**Activity and history**

| Gap | Evidence | Why it matters |
|---|---|---|
| Logons carry no logon type (how the account logged on: at the keyboard, over the network or by Remote Desktop), no authentication type and no success or failure. A logon edge keeps only the first account that used a machine pair. | [events.py L145](../backend/app/events.py#L145), [L153-L154](../backend/app/events.py#L153-L154) | Without logon types, file-share access and Remote Desktop look the same. "Never used before" means "no account has used this machine pair", not "this user never took this route". |
| Everyday activity never creates a new route and never sends a remote logon: "it only repeats routes already seen before the day, so it never creates a new path. remote logons are left out because the ranker reads their timing." | [simulate.py L67-L70](../backend/app/simulate.py#L67-L70) | The only route used for the first time on the sample day is the attack's. So the never-taken-path question cannot raise a false alarm, and its false-alarm rate cannot be measured. |
| The 150 everyday events are spread evenly over about 4 hours | [simulate.py L78](../backend/app/simulate.py#L78) | Real activity follows the working day and week, with automated jobs at night. |
| The starting history already holds part of the replayed day: 14 of the 21 observed edges have `last_seen` inside 08:05-11:55 on 20 October | [L80-L102](../data/sample_org/network.json#L80-L102) | Linking reads `last_seen` ([scoring.py L82](../backend/app/scoring.py#L82)), so history from "the future" can link alerts. It changes no result on the sample, but held-out scenarios (test days not used to set the weights) should not repeat it. |

**Alerts**

| Gap | Evidence | Why it matters |
|---|---|---|
| 30 alerts in about 4 hours, all on one day, with no timezone in any timestamp | [alerts.json](../data/sample_org/alerts.json) | Real teams see alerts all day, every day, from tools in different timezones. Mixed time formats break GraphOps, which compares times as text ([2.6](#26-integration-and-streaming-tests)). |
| Severities are the reverse of what scoring rewards. The 4 attack alerts are medium or low; 10 of the 26 noise alerts are high or critical. | alerts.json | Sorting by severity alone puts the attack alerts at positions 16, 17, 19 and 27 (our analysis of the dashboard's sort rule). The "severity hides the attack" moment in the demo rests on severities we chose. |
| 18 of the 26 noise alerts involve only users and machines with no attack path to any critical asset | our analysis, using [analysis.py](../backend/app/analysis.py) rules | They score 0 of the 25 "hops" points and 0 of the 15 "blast" points, so the graph questions separate them from the attack easily. Real noise also lands on servers, admins and domain controllers. |
| The same detection repeats: printer port scan 4 times, adware twice, VPN brute force twice | alerts.json | The four printer alerts form their own incident, and each earns the full 20 "linked" points from repeats alone (re-implementation). |
| Each alert has one tactic. 6 noise alerts have none; every attack alert has one. | alerts.json | Real alerts often carry several techniques, or none. |
| Alert IDs give the answer away: attack alerts are `a-01` to `a-04`, noise alerts `n-01` to `n-26`, attack events `id-atk-...` | alerts.json; [simulate.py L53](../backend/app/simulate.py#L53), [L57](../backend/app/simulate.py#L57) | IDs appear in the story panel and are sent to the LLM, so people and the model can read the label. |
| A verdict can only be "real" or "false" | [main.py L129-L130](../backend/app/main.py#L129-L130) | A benign positive cannot be recorded. That is real activity that looks like an attack but is allowed, such as an admin's maintenance work. |

**Attack timeline**

| Gap | Evidence | Why it matters |
|---|---|---|
| 4 steps in 31 minutes (10:00-10:31). Every step raises an alert, the two lateral-movement alerts carry exactly the time of their logons, the steps follow the textbook stage order, and entry is a phishing email. | [alerts.json L4-L59](../data/sample_org/alerts.json#L4-L59), [L420-L437](../data/sample_org/alerts.json#L420-L437) | Real attacks take from seconds to years, skip alerts, arrive late and out of order, and mostly do not start with email phishing. |

**Labels and evaluation**

| Gap | Evidence | Why it matters |
|---|---|---|
| The hand-set weights have only ever been checked with R8, on these same 30 alerts | [PROJECT_SPEC.md](../PROJECT_SPEC.md) line 75, [test_requirements.py L74-L76](../backend/tests/test_requirements.py#L74-L76) | Passing R8 shows the weights fit this one story, not that they work on others. R8 even passes when a single question does all the ranking: "stages" alone, or even "choke" alone with its 5 points (re-implementation). |
| Scores are judged at the end of the day | [seed.py L91-L95](../backend/app/seed.py#L91-L95) | End-of-day scores use alerts and logons that came later. `a-01` scores 26.0 and ranks 2nd of 15 when it arrives at 10:00, and 61.4 at the end of the day (re-implementation). The analyst sees the first number. |

### 1.3 What the sample day already shows

Even on this tidy day, the linking rule pulls a noise alert into the attack incident.

- Noise alert `n-11` ("Unsigned driver loaded" on `laptop-it1` and `it_admin`, 09:30) shares `it_admin` with attack alert `a-03` (10:20). They are less than 2 hours apart, so they are linked ([scoring.py L77-L78](../backend/app/scoring.py#L77-L78)). The attack incident therefore holds 5 alerts, and 4 of them are attack alerts.
- `n-11` inherits the incident's "linked" and "stages" points and `it_admin`'s choke score. It scores 71.2 and ranks 2nd, above three attack alerts. The top 5 is `a-03` 85.0, `n-11` 71.2, `a-04` 63.9, `a-01` 61.4, `a-02` 61.4 (re-implementation).
- R8 would still pass (re-implementation), because the top 5 is exactly this incident. There is little room left: any other alert that scores above 61.4 pushes an attack alert to 6th. Joining the incident gives an alert 30 points ("linked" and "stages"), so a merged alert gets there only with graph points of its own, as `n-11` does through `it_admin`. The best alert outside the incident scores 30.0.

Our view: `n-11` touches a Domain Admin account, so an analyst might want to look at it anyway. Labels must say what they record: "part of this attack?" or "worth an analyst's time?".

Small, realistic changes to the day break the current rules (re-implementation, same rules, changed data):

| Change to the sample day | What happens | Why the change is realistic |
|---|---|---|
| The lateral-movement alert `a-03` never fires | The attack splits into 2 incidents, no alert gets the never-taken points, and `n-11` outranks `a-04` | Many attack steps raise no alert |
| The two attack logons are logged 1 second after their alerts | The attack splits into 3 incidents, `a-03` loses its never-taken points and `n-11` ranks 1st. R8 would still pass, but only just: `a-04` is 5th with 33.9 points against 30.0 for the next noise alert. | Clocks and log delivery drift |
| `svc_db` makes its normal `server-7` to `customer-db` logon after the attack | `a-04` falls out of the attack incident and drops to 5th | Routes next to critical assets are used all day |
| The same four steps spread over three days | 3 incidents; `a-04` drops to 5th | Real intrusions take days |
| The attacker's first hop had been used weeks earlier | No never-taken points anywhere; `n-11` ranks 1st | Attackers reuse existing routes |
| One authorised helpdesk logon on a new route, with a low alert | It scores 85.0 and pulls four sales noise alerts into the attack incident; `a-02` drops to 6th | Allowed first-time routes are common |
| Two noise alerts on `dc-01` | A 10-alert incident that includes HR noise; `a-02` drops to 6th | Hub machines appear in many alerts |
| Eight failed-login alerts that name `dc-01` | One 28-alert incident | Same |
| Alerts created 3 minutes after the activity | No change | Late alerts are fine; late logins are not |

Treat these as expected behaviour to confirm with GraphOps' own tests. They are not bugs found by running GraphOps. They show why realistic data matters: the hand-set rules fit a day that has none of these features.

### 1.4 What real enterprise data looks like

**Users and groups**

- Every user account is in Domain Users. When a computer joins the domain, Domain Users is added to that computer's local Users group. Domain Admins is in the local Administrators group of every domain-joined computer by default. (Microsoft)
- Groups can be nested, and members inherit what their groups are granted. (Microsoft)
- Microsoft's enterprise access model splits accounts and machines into three levels: identity control (the old "Tier 0", such as Domain Admins and domain controllers), management, and everyday data and workloads. A lower level must never control a higher one, so the Domain Admins group should hold no accounts used for daily work, and admin credentials should not be left on less-trusted machines. (Microsoft)
- Service accounts come in several kinds. Virtual accounts sign in on the network as the computer account (`DOMAIN\host$`), so their activity appears under a computer account. (Microsoft)
- An account is identified by its domain plus its user name. A name ending in `$` is a computer account. A local account belongs to one computer: Administrator on `c1` is not Administrator on `c2`. (LANL's 2017 data paper)
- Without Windows LAPS (Local Administrator Password Solution), local administrator accounts often share one password across many machines, which helps attackers move between them. (Microsoft)

**Computers and hubs**

- **Dropbox's login graph** (real observed, private, from the Hopper paper):
  - 65% of machines are clients.
  - The hubs are domain controllers, printers, logging and provisioning servers, admin machines and scanners.
  - Over 90% of machines have 10 or fewer neighbours in each direction.
  - The average path is 2.12 hops.
  - 10,434 machine-to-machine edges become 27,718 once the account is part of the edge.
- **LANL's 2011 Kerberos logs** (real observed, not the public files): the busiest source machine was a configuration-checking scanner with 703 targets. The busiest target was an Active Directory server with 14,709 sources. Over four months the median ordinary user reached 18 computers and the median administrator 49.

**Permissions, sessions and activity are three different things**

| Kind | What it is | Example | Do not confuse with |
|---|---|---|---|
| Permission | A right someone holds | `AdminTo`, `CanRDP`, `GenericAll`, `MemberOf`, default logon rights | something that happened |
| Session snapshot | Who was logged on when data was collected | BloodHound's `HasSession`. Its collector, SharpHound, records sessions at one moment, or repeatedly in a loop. | a right, or a timeline |
| Activity | Something that happened at a time | Windows event 4624, a successful logon with a logon type | a right |

- **The logon type changes what an attacker can steal.** Type 2 is a logon at the keyboard, type 3 a network logon such as file-share access, and type 10 Remote Desktop. Logon types 2, 4, 5, 8, 9 and 10 leave reusable credentials on the target. Type 3 does not, unless delegation is enabled, and vulnerability scanners usually use type 3. (Microsoft)
- **Logon events are incomplete.** The source fields of event 4624 are often empty. Network logons through Kerberos, Windows' main sign-in method, usually have no workstation name, and logons through the older NTLM method usually have no IP address. (Microsoft)
- **Ticket events are not logons.** Kerberos ticket events 4768 and 4769 are logged only on domain controllers, and NTLM check event 4776 has no destination. None of them is by itself a logon on the target machine. (Microsoft)
- **BloodHound's `CanRDP` comes from the target computer's own Remote Desktop Users group**, and BloodHound also checks the Remote Desktop logon right when that data was collected. Our sample sets `CanRDP` straight from department groups. (BloodHound)

**Normal activity**

- Activity follows the working day: at LANL, most authentications fall between 07:00 and 17:00, with much less at weekends and holidays. Scheduled backups and desktop configuration management cause bursts. (real observed, LANL 2014)
- Most raw logins are machine noise. Dropbox recorded 784 million logins in 15 months. Removing printing, update and logging servers and non-admin domain-controller logins cut the data to a fortieth of its size. About 30 automated routes added more than 16 million logins. (real observed)
- **First-time routes are common in normal work.**
  - Hopper's authors estimated that alerting on first-time logins would raise over 24,000 alerts (more than 1,600 a month). The causes were on-call maintenance, new staff, staff back from long leave, and rarely used services. (real observed)
  - On LANL, Bowman et al.'s first-time-login rule, which flags every first-time authentication, caught 542 of the 749 labelled red-team events (72%) but raised 530,082 false alarms over 18 test days, about 29,000 a day (our analysis). (mixed)

**Security events and alerts**

- **Most alerts are not attacks.** In RapSheet's one-week study on 34 hosts, the EDR raised 58,096 alerts and only 1,104 (1.9%) came from the red team's attacks. These were raw alerts, not alerts an analyst had already triaged. (mixed)
- **Benign positives are the biggest class.** In the incidents that analysts graded for Microsoft's GUIDE paper, 19% were true positives, 35% false positives and 46% benign positives, averaged over the 12 regions sampled in the paper's Table 2. The released files come from Region 2, where the split was 14%, 34% and 52% (the paper's Table 2). (real observed)
- **A benign positive is real, suspicious-looking activity that is expected or allowed**, for example security testing. Sentinel calls it "suspicious but expected". When an incident is closed in Sentinel (Azure portal), one of five classifications is required: true positive, benign positive, false positive (wrong alert logic), false positive (wrong data) or undetermined. (Microsoft)
- **False positives cluster on certain entities**, such as automated identities (service principals) and deliberate security scanning from known addresses. Microsoft also notes that maintenance work can raise alerts that would be real incidents outside the maintenance window. (Microsoft)
- **Real alerts carry more structure than ours:**
  - separate times for when the alert was created and when the activity started and ended;
  - lists of ATT&CK techniques and attack categories;
  - entity roles such as attacker, compromised, contextual or scanned;
  - Microsoft's severities run from informational to high, with no "critical". (Microsoft)
- **Data arrives late and out of order.**
  - Sentinel documents that a 2-minute ingestion delay can make a rule with a 5-minute look-back miss an event completely. Widening the window then produces duplicate alerts. (Microsoft)
  - Kafka, the message queue behind GraphOps' live stream, keeps messages in order only within one partition of one topic (a named stream of messages). GraphOps sends a login and the alert about it on different topics, so the alert can arrive first. (Apache Kafka)
- **Severity depends on the tool and the rule.** Microsoft gives credential-theft tools as an example of high severity. Sigma's generic rule for dumping credentials from LSASS (the Windows process that holds logged-in users' credentials) is medium, while its more specific LSASS rules are mostly high. Sigma rules also list their expected false positives, for example "Legitimate administrative activity". (Microsoft, SigmaHQ)
- **Real correlators guard against "black hole" incidents** (one incident that swallows many unrelated alerts). (Microsoft)
  - GraphWeaver, an alert correlator built into Microsoft Defender XDR, links alerts only when they share an entity, such as a user, device or IP address. The time window depends on the entity: 24 hours for users and devices, 8 hours for IP addresses.
  - It lets alerts from different detectors link only when the detector is quiet (under 6% of all alerts and under 20 a day) and its alerts name only a few distinct entities.
  - Defender refuses merges that would push an incident above a maximum number of entities.
- **ATT&CK tags are rarely clean.** Many techniques belong to several tactics; T1078 Valid Accounts belongs to four. One behaviour can match several techniques, and not every behaviour is in ATT&CK. CISA's mapping guide also warns that tactics are not a fixed left-to-right sequence: attackers can go back and skip tactics, which matters for GraphOps' stage-order question. (MITRE, CISA)

**Suspicious behaviour and attack timelines**

| Source | Kind | What it shows |
|---|---|---|
| CrowdStrike 2026 Global Threat Report | real observed (vendor telemetry) | Average eCrime (financially motivated) breakout time of 29 minutes in 2025, fastest 27 seconds. In one intrusion, data theft began within 4 minutes. 82% of detections involved no malware. |
| Mandiant M-Trends 2026 | real observed (incident-response cases) | Global median dwell time (how long attackers stay before they are found) of 14 days in 2025, up from 11. 122 days for espionage and North Korean IT-worker cases. Entry: exploits 32%, voice phishing 11%, earlier compromise 10%, email phishing only 6%. 52% of intrusions were found by the victims themselves. |
| The DFIR Report, RansomHub case (June 2025) | real observed (one case) | About 118 hours over six days: a password spray on Remote Desktop, a first logon to the beachhead about 4 hours after the spray succeeded, Remote Desktop to two domain controllers about 2 hours after that, legitimate remote-management tools, and Rclone (a file-copying tool) used for data theft from file servers |
| CISA advisory AA24-038A (Volt Typhoon) | real observed | Access kept for at least five years, using built-in tools ("living off the land") and valid accounts, and avoiding malware that would raise alerts |
| CISA advisory AA24-193A | controlled simulation on a real network | In an eight-month red-team assessment, the red team stayed undetected through its first phase, and endpoint alerts were not reviewed every day |
| RapSheet (IEEE S&P 2020) | mixed | Its red-team runs had no normal activity between attack stages, which the authors call "less realistic". For one scenario the authors note that deployed defences often miss the first infection step. A harmless employee who compressed files and uploaded them got the highest attack-stage score. |
| DARPA OpTC red-team log, day 1 | controlled simulation | About 2 hours on the first host, then hops 11, 29 and 40 minutes apart |

Our view: no single number describes "the" attack. Scenarios should cover seconds, hours and days, and some steps should raise no alert.

### 1.5 How to model each part more realistically

Keep [data/sample_org](../data/sample_org) as it is. The tests pin its exact counts, hops and rings ([test_requirements.py L5-L32](../backend/tests/test_requirements.py#L5-L32)), and it is the demo story. Put realism into a separate dataset and simulator configuration. Every value in its parameter file should be tagged either "calibrated: dataset, statistic" or "assumption".

| Part | Model it like this | Can be calibrated from | Must be stated as our assumption |
|---|---|---|---|
| Users | Separate daily and admin accounts for each tier. A computer account (`host$`) per computer. Built-in and local accounts scoped to their computer (ID `host\name`). Service accounts by kind. Joiners, movers and leavers through the existing `MemberOf` added/removed message ([events.py L18](../backend/app/events.py#L18)). | share of computer-account events and the user-to-computer ratio, from a LANL slice | joiner and leaver rates; admins per tier |
| Groups | Nested groups. Default groups as a separate "default rights" layer, kept out of attack hops unless the team decides otherwise. | - | nesting depth; group sizes |
| Computers | At least two domain controllers, a patch or configuration server, a vulnerability scanner, a backup server, log collectors, a print server and jump hosts. A stated operating-system mix. | logins per computer, from LANL | which assets are critical; zones |
| Permissions | Explicit grants plus default rights. Tiers. Misconfigurations as a named, counted setting; the sample's admin sessions on `laptop-42` and `server-7` are examples. | - | misconfiguration rates (ADSynth's presets are generator settings, not measurements) |
| Sessions | `HasSession` as an observation with a collection time, a source (SharpHound snapshot, derived from logons, or ADSynth-generated) and an expiry. Derive it only from logon types that leave credentials (2, 4, 5, 8, 9, 10; never 3). | - | how long a session counts |
| Normal activity | Logon type, authentication type, success or failure, and source on every logon. Routes keyed by account. A working-day and weekly rhythm. Automated jobs at night. Normal remote logons and normal first-time routes (helpdesk, on-call work, new staff, staff back from leave, new machines, rarely used services) at stated rates. Failed logons that match the rights model. | the shape of the daily and weekly cycle (LANL withholds real dates, so aligning it to clock hours and weekdays is our assumption, and a weekly cycle needs more than a few days), logon-type mix, logins per user, and the daily rate of first-seen routes after a warm-up period, all from a LANL slice | every rate until LANL is measured; test at none, low and high |
| Alerts | Real rule titles, levels and ATT&CK tags (from Sigma rules). Several tactics or techniques per alert, or none. Benign positives. Duplicates and alert storms. Alerts created after the activity. UTC times with an explicit offset. Blocked or prevented alerts. Alerts that name unknown entities, such as an outside IP address. | shares of true, benign and false positives, alerts per incident and techniques per alert, from GUIDE (with its caveats, [3.4](#34-other-datasets-with-a-clear-benefit)) | daily alert volume; delays and clock skew in seconds |
| Attack timelines | A scenario library ([1.6](#16-a-scenario-library)) built from public attack sequences (MITRE emulation plans, Attack Flow, DFIR Report cases), re-enacted on our own synthetic machines and accounts, with deliberate detection gaps | the shape of single published cases only, not a distribution | which steps raise alerts; how long each scenario lasts |
| Security events other than logons | Process starts with the parent process and command line (like Sysmon event 1 or Windows event 4688), network connections with ports (like Sysmon event 3) and, from flow records, bytes, group-membership changes (events 4728, 4732 and 4756 and their removals) and failed logons (event 4625), each with the tool that produced it and a delivery delay. Today GraphOps keeps a process start only as an `Event` node and drops a connection's port and bytes ([events.py L86-L93](../backend/app/events.py#L86-L93), [L145](../backend/app/events.py#L145)). | process and flow rates per computer, from LANL; event formats from OTRF recordings ([3.4](#34-other-datasets-with-a-clear-benefit)) | the event mix and delays, until measured |
| Labels | Kept in separate evaluation files keyed by alert or event ID. Neutral IDs. True positive, benign positive, false positive or undetermined. | - | - |

Our view: start with hand-written scenario days ([1.6](#16-a-scenario-library)) and a parameterised generator for our own organisation, and make the alerts look real with Sigma rules run over lab recordings ([3.4](#34-other-datasets-with-a-clear-benefit)). Add ADSynth and a LANL slice once the first flow is stable. Keep GUIDE as a separate test of the parts of the score that do not need the graph.

### 1.6 A scenario library

Each scenario is a small, labelled day that tests one weakness. Hard positives are attacks GraphOps should rank high and group correctly. Hard negatives are harmless days it should not rank high or merge.

**Hard positives**

| ID | Scenario | Based on | What it tests |
|---|---|---|---|
| HP-1 | Fast breakout: steps seconds apart | CrowdStrike (27 s fastest), M-Trends | ordering within one second; ties |
| HP-2 | Detection gap: the middle lateral-movement alert is missing | RapSheet; CISA red team | linking without that alert; whether a new route with no alert ever reaches the analyst |
| HP-3 | Low and slow over several days | DFIR RansomHub case (118 hours); M-Trends median of 14 days | the linking windows (2 hours for a shared user or machine, 45 minutes for a logon from one alert's machine to the next); a story that spans days |
| HP-4 | Living off the land: only existing routes and admin tools; a stolen account on a machine pair that is already in use | CrowdStrike (82% malware-free); CISA guidance | never-taken scores 0; reliance on hops and blast; the route key ignores the account |
| HP-5 | Data theft from a file server that is not marked critical | DFIR (Rclone from file servers); MITRE's Data Exfiltration plan | hops, blast and choke score 0; what counts as critical |
| HP-6 | Entry without phishing: an exploited internet-facing server, a Remote Desktop password spray, or a helpdesk password reset after a phone call | M-Trends 2026 | ranking does not depend on a phishing tag |
| HP-7 | Domain controller compromise: a stolen Domain Admin session, then theft of the domain's password database | CISA AA24-193A, AA24-038A | hub handling when the attack itself touches `dc-01` |
| HP-8 | Messy telemetry on an attack scenario: clock skew, late alerts, a login that arrives after its alert, alerts with no tag or several | Sentinel ingestion delay; Microsoft alert times; Kafka ordering | time tolerance, re-scoring, stage scoring |

**Hard negatives**

| ID | Scenario | Based on | What it tests |
|---|---|---|---|
| HN-1 | An allowed helpdesk or admin remote logon on a new route | the false positive listed in Sigma's ADMIN$ share rule | never-taken false alarms; merging through `it_admin` |
| HN-2 | A penetration test or scan that raises genuine attack alerts (benign positive: label it as such and report it separately, counting it neither as an attack nor as a false alarm in ranking measures) | Microsoft's "security testing" determination | the verdict options |
| HN-3 | Normal work that follows attack-stage order: an employee archives files on several machines and uploads them to a company site | RapSheet | the "stages" question |
| HN-4 | Service-account routine next to critical assets, such as `svc_backup` to `finance-db` at night | Microsoft's false-positive guidance | hops and blast false alarms; links broken by route reuse |
| HN-5 | An alert storm from one noisy detector | GraphWeaver; Sentinel alert grouping | inflated "linked" points; inbox volume (R2 forbids hiding any alert) |
| HN-6 | Hub noise through `dc-01`, an IT admin or a file server | GraphWeaver's "black hole" incidents | incident size; noise in the story |
| HN-7 | A maintenance window: the same activity is fine inside it and suspicious outside it | Microsoft's false-positive guidance | time-bound context |
| HN-8 | A blocked threat, like the sample's critical "Drive-by download blocked" | Microsoft alert remediation status | whether blocked events dominate the inbox |
| HN-9 | Normal first-time routes at a realistic rate | Bowman et al.; Hopper | the never-taken false-alarm rate |

### Sources for section 1

- Repository files as linked, branch `raja`, commit `7f3e171`.
- Microsoft: [security groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups), [Allow log on locally](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/allow-log-on-locally), [Access this computer from the network](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/access-this-computer-from-the-network), [Allow log on through Remote Desktop Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services), [enterprise access model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model), [securing Domain Admins (Appendix F)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-f--securing-domain-admins-groups-in-active-directory), [service accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts), [LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview), [logon types and credential exposure](https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types), events [4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624), [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625) and [4776](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776), [Graph security alert](https://learn.microsoft.com/en-us/graph/api/resources/security-alert), [alert evidence](https://learn.microsoft.com/en-us/graph/api/resources/security-alertevidence), [Defender XDR correlation](https://learn.microsoft.com/en-us/defender-xdr/alerts-incidents-correlation), Sentinel [ingestion delay](https://learn.microsoft.com/en-us/azure/sentinel/ingestion-delay), [analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules), [incident triage](https://learn.microsoft.com/en-us/azure/sentinel/incident-navigate-triage) and [false positives](https://learn.microsoft.com/en-us/azure/sentinel/false-positives). Some pages are archived Windows 10 references, still Microsoft's official description of the defaults.
- BloodHound: [HasSession](https://bloodhound.specterops.io/resources/edges/has-session), [CanRDP](https://bloodhound.specterops.io/resources/edges/can-rdp), [AdminTo](https://bloodhound.specterops.io/resources/edges/admin-to), [SharpHound flags](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound-flags), [SharpHound permissions](https://bloodhound.specterops.io/collect-data/sharphound-data-permissions).
- Turcotte, Kent and Hash, [Unified Host and Network Data Set](https://arxiv.org/abs/1708.07518) (LANL, 2017).
- Ho et al., [Hopper: Modeling and Detecting Lateral Movement](https://www.usenix.org/system/files/sec21-ho.pdf), USENIX Security 2021.
- Bowman et al., [Detecting Lateral Movement in Enterprise Computer Networks with Unsupervised Graph AI](https://www2.seas.gwu.edu/~howie/publications/CyberGraph-RAID20.pdf), RAID 2020.
- Kent and Liebrock, [Differentiating User Authentication Graphs](https://ieee-security.org/TC/SPW2013/papers/data/5017a072.pdf), IEEE S&P Workshops 2013. Hagberg et al., [Connected Components and Credential Hopping in Authentication Graphs](https://aric.hagberg.org/papers/hagberg-2014-credential.pdf), SITIS 2014.
- Hassan et al., [Tactical Provenance Analysis for Endpoint Detection and Response Systems](https://dartlab.org/assets/pdf/rapsheet.pdf) (RapSheet), IEEE S&P 2020. Freitas et al., [AI-Driven Guided Response for Security Operation Centers with Microsoft Copilot for Security](https://arxiv.org/abs/2407.09017) (the GUIDE paper). [GraphWeaver: Billion-Scale Cybersecurity Incident Correlation](https://arxiv.org/html/2406.01842).
- [CrowdStrike 2026 Global Threat Report press release](https://www.crowdstrike.com/en-us/press-releases/2026-crowdstrike-global-threat-report/) and [report page](https://www.crowdstrike.com/en-us/global-threat-report/). [M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026). The DFIR Report: [RansomHub](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/). CISA [AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a), [AA24-193A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-193a), [living off the land guidance](https://www.cisa.gov/resources-tools/resources/identifying-and-mitigating-living-land-techniques) and [ATT&CK mapping guide](https://www.cisa.gov/sites/default/files/2023-01/Best%20Practices%20for%20MITRE%20ATTCK%20Mapping.pdf).
- MITRE ATT&CK [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/). SigmaHQ rules for [ADMIN$ share access](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_admin_share_access.yml) and [LSASS credential dumping](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_lsass_memdump.yml). [Kafka 4.3 introduction](https://kafka.apache.org/43/getting-started/introduction/).
- DARPA OpTC [red-team ground truth](https://github.com/FiveDirections/OpTC-data/blob/master/OpTCRedTeamGroundTruth.pdf).

---

## 2. How to test the website

### 2.1 What is tested today

The backend has good tests. They start a real Neo4j ([conftest.py L14-L24](../backend/tests/conftest.py#L14-L24)) and, for the streaming tests, a real Kafka ([test_streaming.py L23-L44](../backend/tests/test_streaming.py#L23-L44)) in Docker.

| File | What it checks (read, not run) |
|---|---|
| [test_requirements.py](../backend/tests/test_requirements.py) | One test per requirement R1-R8 (two for R6) on the sample organisation: counts after seeding, inbox order, known hop counts, blast-radius rings for `a-03`, the attack as one incident in stage order, the story checker and its fallback, a saved verdict, the attack in the top 5 |
| [test_logic.py](../backend/tests/test_logic.py) | The linking rules, stage counting and the citation checker, with no database |
| [test_break.py](../backend/tests/test_break.py) | Empty and very long input, unknown labels, a Cypher-injection attempt, bad verdicts and unknown IDs |
| [test_streaming.py](../backend/tests/test_streaming.py) | Kafka replay gives the batch result; a day without the attack; duplicates; a crash halfway; one alert visible in `/api/live` within 5 seconds; bad messages skipped; replay without Kafka; a repeatable simulator |

What is missing:

- **No frontend, browser or accessibility tests, and no automatic test runs.** [package.json](../frontend/package.json) has only dev, build and preview scripts, and there is no `.github` folder.
- **Some endpoints are never called over HTTP.** No test calls `GET /api/incidents/{id}`, `POST /api/incidents/{id}/story` or `/api/replay/*`. No test checks the blast-radius `edges` and `attack_path` fields, which the graph and the path banner draw.
- **The hosted site's choke-score code is never tested.** According to the README, AuraDB Free has no Graph Data Science library, so the hosted site computes choke scores with networkx, a Python graph library. The test container always installs Graph Data Science, so the networkx code never runs in tests ([analysis.py L44-L57](../backend/app/analysis.py#L44-L57), [conftest.py L18](../backend/tests/conftest.py#L18)).
- **Some calculations have no direct test:** `critical_within_3`, the never-taken check and the choke scores. The "known-answer" tests reuse the sample graph instead of small graphs built for the purpose.
- **R5 does not check that the attack incident holds only attack alerts** ([test_requirements.py L35-L43](../backend/tests/test_requirements.py#L35-L43)), so the `n-11` merge in [1.3](#13-what-the-sample-day-already-shows) would pass unnoticed.
- **The speed test is thinner than described.** It sends one alert and checks it appears within 5 seconds. [streaming.md](streaming.md) describes it as "at 60x", and the README describes replays at 1x, 10x and 100x speed that no test runs. There are no latency percentiles, because nothing records when a message was ingested or scored ([events.py L86-L93](../backend/app/events.py#L86-L93)).
- **Some planned evaluations have nothing to run yet:** there is no LANL evaluation and no material for the people test (the README's timed comparison of a raw alert list with GraphOps).

### 2.2 The user journey and what to check

| Step | What the analyst does and sees | What to check | Test layer |
|---|---|---|---|
| 1. Landing page | "Open the console" goes to `#/console` | the URL changes to `#/console`; the "Sample organisation · synthetic data" label shows | browser |
| 2. First-visit tour | A guided tour opens on the first visit | it opens once, Skip and Escape work, it stays closed after a reload | browser |
| 3. Alert inbox | Every alert, highest score first, with a bar showing the reasons | the row count equals `/api/alerts` (R2); the order is score, then time; the bar segments add up to the score within 0.4 points (score and segments are rounded separately: `n-11`'s segments sum to 71.3 against a score of 71.2, re-implementation); the KPI numbers | browser (mocked API) and API |
| 4. "Severity only" toggle | The list re-sorts by the tools' severity | on the sample, the attack alerts move to positions 16, 17, 19 and 27, and each shows its GraphOps rank as "#N in GraphOps"; in the default view the same alerts carry labels such as "#16 when sorted by severity" (our analysis of [Dashboard.jsx L110-L125](../frontend/src/Dashboard.jsx#L110-L125)) | browser |
| 5. Blast radius | Clicking an alert draws rings at 1, 2 and 3 hops, a shortest-path banner and a node inspector | the rings match a hand-run Cypher query (R4); the hop-button counts; the path banner; the inspector values | API (known answers), browser, a few screenshots |
| 6. Incident | Linked alerts with their attack stage | incident membership (R5) and that no noise alert is in it; alerts listed in time order with tactic tags | API and browser |
| 7. Story | "Draft the incident story with AI" | LLM path ("Drafted by AI. Needs analyst approval."), the fact-list fallback, the "removed for citing facts outside this incident" notice, the busy state | API with a fake LLM; browser with a fake response |
| 8. Verdict | "Real attack" or "False alarm" | the request body; the badge; the value saved in Neo4j (R7); what happens when saving fails | API, browser, one full-stack test |
| 9. Live updates (not built) | New alerts slide into the inbox | `/api/live` returns new and changed alerts; latency | API and streaming now; browser once built |

### 2.3 Recommended test layers

| Layer | Tool | Why it fits GraphOps | Effort | Limits |
|---|---|---|---|---|
| Backend unit | pytest (already used) plus small hand-made graphs checked against an independent networkx search | fast; catches wrong hop and ring logic | small | synthetic graphs only |
| Frontend components | Vitest and React Testing Library | Vitest reuses `vite.config.js`; React Testing Library queries the page the way users do | medium | needs Node 22.22.2 or newer on version 22, 24.15 or newer on version 24, or version 26 or newer, because of jsdom 30 (Vitest alone needs 22.12; README says 20); jsdom (the simulated browser that Vitest tests run in) has no layout and no `scrollIntoView`, so the tour and anything that depends on sizes or positions need a real browser or a stub |
| API | FastAPI `TestClient` (already used) | runs in-process, no server needed | small | - |
| API fuzzing | Schemathesis, in-process | generates many requests from FastAPI's own OpenAPI schema | small | finds crashes and schema gaps, not wrong rankings |
| Contract | pytest that checks the response shapes the dashboard reads | mocked browser tests are only as good as their fixtures | small | checks shape, not meaning |
| Integration | Testcontainers Neo4j and Kafka (already used) | real database and broker | medium | slow; pulls large images |
| Browser end to end | Playwright (Node, `@playwright/test`) | starts the servers itself, mocks the API, records traces, compares screenshots and runs accessibility scans | medium | needs care with animations and fonts |
| Accessibility | axe-core with Playwright, plus a manual keyboard and screen-reader pass | the official Playwright guide covers it | small | automated scans miss many problems |
| Evaluation | an offline script over `/api/alerts` and a separate label file | measures ranking, grouping and the story ([2.9](#29-how-to-measure-ranking-grouping-the-story-and-speed)) | medium | only as good as the labelled scenarios |
| Speed | a latency harness on one clock | gives percentiles instead of a single sample | medium | 1x and 10x replays are too long for Vercel |
| People test | a written protocol | the README promises it | medium | needs participants |

### 2.4 Browser tests

**Use the Node test runner, `@playwright/test`, inside `frontend/`.** Only the Node runner has:
- the `webServer` option, which starts the servers before the tests;
- `toHaveScreenshot` visual comparison;
- the official axe accessibility guide.

The Python plugin (pytest-playwright) has none of these. Python stays a reasonable choice for a few full-stack tests that reuse the existing Testcontainers fixtures.

**Most journey tests should fake the API inside the browser.** `page.route` intercepts the dashboard's `fetch` calls and `route.fulfill({ json })` returns a fixture. No backend, Docker or LLM is needed, and every state can be reached: an LLM story, the fact-list fallback, dropped sentences, a 500 error, a slow response.

**One or two full-stack tests should run the real stack:**

1. Start Neo4j (`docker compose up -d --wait neo4j`), seed it and build the dashboard (`npm run build`). **Seeding deletes everything in the database it reaches** ([seed.py L44](../backend/app/seed.py#L44)), and the app reads `NEO4J_URI` from `.env`, which may point at AuraDB. Always set the address to the local container in the same command, for example `NEO4J_URI=bolt://localhost:7687 python -m app.seed`, and follow the safety rules in [2.8](#28-continuous-integration-and-test-safety).
2. Start FastAPI, which then serves both the dashboard and `/api` on one origin, as on Vercel ([main.py L231-L233](../backend/app/main.py#L231-L233)). Start it without Anthropic credentials, so the story falls back to the fact list, or answer the story request in the browser with `page.route`. A test cannot patch a server running in another process.
3. In Playwright's `webServer` settings, point the backend's readiness URL at an API route such as `/openapi.json`, because `/` returns 404 until the dashboard is built.
4. Click through the inbox, blast radius, incident and verdict, then read the verdict back through the API.

Things that matter for GraphOps:
- **Close the tour first.** It opens whenever local storage lacks `graphops-tour-seen=1`, and it covers the whole page, so it intercepts clicks. Every Playwright test starts with empty storage, so set the key with `page.addInitScript` ([Tour.jsx L3-L11](../frontend/src/Tour.jsx#L3-L11)).
- **Scope locators to regions.** The eight `data-tour` attributes (sort, kpis, strip, inbox, graph, hops, why, side) are the only stable hooks today ([Dashboard.jsx](../frontend/src/Dashboard.jsx)). Playwright locators are strict: "Open the console" matches two links, and alert names appear in both the inbox and the incident timeline.
- **Some elements have no handle at all.** Inbox rows are clickable `<li>` elements. Timeline dots are `<button>`s with no text. Graph nodes are SVG `<g>` elements with no role or name. The verdict, sort and hop buttons show their state only through a CSS class.
- **Avoid flaky waits** (waits that make a test pass or fail at random). Playwright waits until an element is visible and stable before clicking, and retries assertions, so fixed sleeps are not needed. Graph nodes fade in after a short delay, and Playwright counts an element as visible even at opacity 0, so a test may click a node before it has visibly appeared. That is harmless for clicks; take screenshots with animations disabled.
- **Sort before comparing.** The blast-radius edges and start nodes come back in no fixed order. `a-03` also has two equally short attack paths, to `customer-db` and to Domain Admins, so the path banner may show either ([main.py L58-L94](../backend/app/main.py#L58-L94)).
- **Configure for CI** (continuous integration: tests that run automatically on every push). Give Vite `strictPort`, so a busy port fails instead of moving. Record traces on the first retry and use one worker on CI.
- **Test two code weaknesses with interception:**
  - `open()` does not ignore a slow, out-of-date response, so an earlier alert's blast radius can overwrite the current one.
  - `mark()` has no error handling, so a failed verdict save shows nothing ([Dashboard.jsx L54-L72](../frontend/src/Dashboard.jsx#L54-L72)).

To propose to the frontend owner (not to build now):
- `aria-label`s on the timeline dots;
- `aria-pressed` on the verdict, sort and hop buttons;
- real buttons (or `role="button"` with keyboard handling) for inbox rows;
- `data-node-id` and `data-hop` on graph nodes;
- a text alternative for the graph;
- a reduced-motion style.

These make tests simpler and also fix the accessibility gaps in [2.7](#27-accessibility-and-visual-tests).

### 2.5 API and contract tests

**Close the API gaps:**
- `GET /api/incidents/{id}`: its response shape and a 404;
- the story endpoint with a fake LLM: the LLM path, the fact-list path and dropped sentences;
- the blast-radius `edges` and `attack_path` for `a-03`;
- the replay endpoints without Kafka:
  - reset;
  - start at speed 0;
  - a 409 while a replay is running;
  - a 422 for a bad speed;
  - poll `/api/live` until it stops replaying, then compare with the batch scores.

**Fake the LLM at the right place.** `write_story`'s default model function is bound when the function is defined, and `main.py` imports `write_story` by name. An in-process API test must therefore replace `app.main.write_story` (or patch `anthropic.Anthropic`); patching `story.ask_llm` has no effect. If a test patches the wrong function, a machine logged in to Anthropic (through `ant auth login`) calls, and bills, the real model ([story.py L95](../backend/app/story.py#L95), [main.py L12](../backend/app/main.py#L12)). Later, making the story writer a FastAPI dependency would allow `app.dependency_overrides`.

**Add a contract test.** It asserts the keys and types the dashboard reads from each endpoint:
- alerts: `id`, `name`, `score`, `severity`, `involves`, `time`, `status`, `incident_id`, `source_tool`, and `breakdown` keys equal to the scoring weights;
- blast radius: `nodes`, `edges`, and `attack_path` or `null`;
- the incident, story and verdict shapes.

It should also fail if the dashboard's copy of the weights drifts from the backend's. [parts.jsx L13](../frontend/src/parts.jsx#L13) repeats [scoring.py L11](../backend/app/scoring.py#L11). Build the browser fixtures from the same seeded API, so mocks cannot drift.

**Run Schemathesis in-process.** With `schemathesis.openapi.from_asgi` it reads FastAPI's `/openapi.json` and generates many test requests from it, so no server is needed. Include only the read endpoints and the verdict; leave out replay and the story. We expect these reports at first:
- the verdict accepts any string in the schema but returns 422 for anything except `real` or `false`;
- that 422 reply carries a text `detail`, while FastAPI's published error schema expects a list;
- 404 replies that the schema does not list.

Replay, if it is ever fuzzed against a throwaway local database, would add its speed check (any number in the schema, 422 outside 0-10,000) and a 409 while a replay runs. Declared request types and documented error responses would fix these. No endpoint declares a response model, so Schemathesis cannot check the bodies of successful replies.

### 2.6 Integration and streaming tests

**Backend tests to add:**
- A test that the attack incident holds no noise alert. By our re-implementation, `n-11` would fail it today.
- Incident sizes, the share of alerts in the largest incident, and whether incident IDs stay the same across re-scores. Today every re-score deletes all incidents and renumbers them by their earliest alert ([scoring.py L146-L157](../backend/app/scoring.py#L146-L157)).
- A comparison of the Graph Data Science and networkx choke scores on the same graphs.
- Small graphs with known answers, where hops and rings are checked against an independent networkx search. `seed.load` already accepts other files.

**Streaming tests to add.** The current streaming tests either send the whole day at speed 0, in time order, or send single messages, so they cannot see these problems. Each test should state its expected outcome. The predictions below come from reading the code and need a test to confirm them.

| Test | What the code suggests today, or what to check |
|---|---|
| An alert arrives before the login that explains it, on another topic | linking depends on the order of arrival |
| A late login updates an existing route | no re-score happens until the next alert or network change ([events.py L123](../backend/app/events.py#L123), [stream.py L118-L121](../backend/app/stream.py#L118-L121)) |
| An alert with an unreadable time, or a timezone, among plain times | it is saved; every later re-score then fails, and the re-score flag never clears, so live scoring stops. Python refuses to compare times with and without a timezone, and Cypher compares the strings alphabetically ([events.py L43-L45](../backend/app/events.py#L43-L45), [scoring.py L14-L15](../backend/app/scoring.py#L14-L15), [events.py L155-L157](../backend/app/events.py#L155-L157), [stream.py L155-L161](../backend/app/stream.py#L155-L161)) |
| An alert that names only unknown machines or users | it is never scored or linked, never appears in `/api/live`, and sits at the top of `/api/alerts`, because Neo4j puts empty scores first when sorting from highest to lowest ([events.py L133-L134](../backend/app/events.py#L133-L134), [main.py L40](../backend/app/main.py#L40)) |
| Clock skew of ±1 s and ±60 s between sources | logons stamped after their alerts change grouping and never-taken points ([1.3](#13-what-the-sample-day-already-shows)); logons stamped up to 60 s earlier change nothing (re-implementation) |
| The same logon sent twice with different event IDs; a corrected version of an existing alert | the logon is counted twice, because duplicates are recognised only by event ID; the correction's fields are ignored, because only the first version of an alert is kept, but any newly named entity is still linked to it ([events.py L76-L82](../backend/app/events.py#L76-L82), [L130](../backend/app/events.py#L130)) |
| A burst of 10,000 events | measure how long it takes to catch up, and whether alerts wait behind other events |
| A hub (a shared admin account, or a group like Domain Users) | measure incident size and blast-radius time |
| A very large day | re-scoring compares every pair of alerts; AuraDB Free stores at most 200,000 nodes by Neo4j's limits page (another Neo4j page says 50,000; see [section 6](#6-what-we-could-not-verify)), and every message becomes an `Event` node |
| Two ingest loops at once | check: no duplicate incidents, an increasing change counter, no missed updates |
| An alert or login that arrives before the inventory message that creates its machine | its links are never created, and it is not retried because its event ID is already recorded ([events.py L76-L82](../backend/app/events.py#L76-L82), [L133](../backend/app/events.py#L133), [L149](../backend/app/events.py#L149)) |
| A bad label or edge type in a batch file | the loader deletes the database before it checks the file, so one bad label leaves an empty database and all verdicts are lost ([seed.py L44](../backend/app/seed.py#L44), [L52-L53](../backend/app/seed.py#L52-L53)) |
| The same events in shuffled order | check: the live result equals the batch result |

### 2.7 Accessibility and visual tests

**Accessibility.** Run `@axe-core/playwright` on the landing page and the console, with the tour open and closed, in both themes. Save today's issues as a list (rule and element for each) and fail only on new ones.

Deque, the company that makes axe, says axe finds on average 57% of WCAG issues (problems under the W3C's Web Content Accessibility Guidelines) automatically, so add a manual keyboard and screen-reader pass. From reading the code (not run), we expect:
- axe to report the unnamed timeline-dot buttons, and probably some low-contrast small text;
- axe to miss that inbox rows and graph nodes cannot be reached with a keyboard (WCAG 2.1.1); alerts can still be opened through the unlabelled timeline buttons;
- axe to miss that the graph has no text alternative;
- axe to miss that nothing stops the endlessly moving attack-path line (WCAG 2.2.2, which will also cover the live inbox).

**Visual.** A few `toHaveScreenshot` checks of the ring graph for one fixed alert, in both themes, are worth having, because the hand-drawn layout can break silently. Keep them few:
- Rendering differs by operating system, browser and fonts, so create and compare baselines only inside Playwright's Docker image.
- Animations are disabled during capture by default.
- The fonts come from Google Fonts, so self-host them (IBM Plex is under the OFL licence) or block them consistently.

### 2.8 Continuous integration and test safety

**Continuous integration.** A GitHub Actions job on a Linux runner, which has Docker installed, can run the existing backend suite unchanged:
- Pin `runs-on: ubuntu-24.04` and Python 3.12. `ubuntu-latest` starts moving to Ubuntu 26.04, with Python 3.14, on 19 October 2026.
- Set `NEO4J_PASSWORD` to a dummy value, because importing the app reads it ([db.py L24](../backend/app/db.py#L24)).
- Leave `KAFKA_BOOTSTRAP` empty.
- Each run pulls the Neo4j image (about 408 MB) and the Kafka image (about 239 MB).
- Windows runners cannot run Linux containers.
- Playwright's official workflow installs browsers, runs the tests and uploads the HTML report.

**Safety rules for every test:**

- **Never send replay, verdict, story or fuzzing requests to graph-ops.vercel.app.**
  - It has no sign-in, a replay wipes its alerts, and saved verdicts are the planned training data for the ranking model.
  - Its `/openapi.json` is public and lists the replay endpoints.
  - Checks against it should only send GET requests for pages, `/api/alerts`, `/api/alerts/{id}/blast-radius` and `/api/incidents/{id}` (the console opens the top alert automatically), enforced by a request filter (`page.route`) that aborts anything else. Even `GET /api/live` can write to the shared database, because it ingests whatever is waiting in Kafka ([main.py L210-L227](../backend/app/main.py#L210-L227)).
  - Vercel protects preview deployments by default, so automated tests against a preview need Vercel's bypass secret for automation.
- **Set `NEO4J_URI` and `KAFKA_BOOTSTRAP` explicitly** in every test setup, and refuse a `neo4j+s://` address (AuraDB). Variables that are already set win over the app's `.env` file, so setting them in the test stops a teammate's `.env` (which may point at AuraDB or Aiven) from being used.
- **Replace the story writer with a fake** (see [2.5](#25-api-and-contract-tests)).
- **Keep test clicks out of training data.** A verdict clicked by a test is not an analyst's judgement.
- **Reseed instead of adding a reset endpoint** to the deployed app.

### 2.9 How to measure ranking, grouping, the story and speed

All sample-day values below come from the re-implementation and the 30 hand-written alerts. They show how each measure works. They are not evidence of performance: the day is synthetic, easy and the only data the weights have ever been checked on.

**Ranking.** An alert is "flagged" when it is in the top *k* rows or scores at or above a cut-off.

| Measure | Plain meaning | Formula | GraphOps on the sample day | Severity-only order on the sample day |
|---|---|---|---|---|
| Precision@k | share of the top *k* that are attack alerts | attack alerts in top *k* ÷ *k* | 0.80 at *k* = 5 (4 of 5) | 0 at *k* = 5 |
| Recall@k | share of all attack alerts that are in the top *k* | attack alerts in top *k* ÷ all attack alerts | 1.00 at *k* = 5 (4 of 4) | 0 at *k* = 5 |
| Rank of the last attack alert | how far an analyst reads to see the whole attack | - | 5 (one false alarm on the way) | 27 |
| False alarms per day | the analyst's workload; report it next to recall | false alarms above the cut-off ÷ days | 1 at *k* = 5 | 5 at *k* = 5 |
| False positive rate (FPR) | share of noise alerts that get flagged | false ÷ (false + correctly unflagged) | 1 of 26 = 3.8% with the cut-off at 61.4 | |
| False discovery rate (FDR) | share of flagged alerts that are false | false ÷ all flagged = 1 - precision | 1 of 5 = 20% | |
| Average precision (AP) | precision at each attack alert's rank, averaged | mean of precision@rank over the attack alerts | 0.80 | 0.12 |
| ROC-AUC | chance that a random attack alert outranks a random noise alert | - | 0.97 | 0.34 |

FPR and FDR are easy to confuse. Papers usually report FPR, but an analyst feels FDR. Some baselines for the same day (re-implementation):

| Baseline | Result |
|---|---|
| Newest first | attack alerts at ranks 9, 11, 13 and 16 |
| Oldest first | attack alerts at ranks 15, 18, 20 and 22 |
| Random order | last attack alert expected at rank 24.8; expected AP 0.22; all four in the top 5 about 1 time in 5,481 |

The random AP of 0.22 is not the 0.13 share of attack alerts, because the inbox is small (Bestgen 2015).

Our view: report precision@k, recall@k, the rank of the last attack alert, false alarms per day and AP. Use ROC-AUC only as a secondary figure. Two published examples show why:
- **LANL re-evaluation:** two graph-based detectors kept an AUC of about 98% while their average precision fell to 0.02% and 0.09% (Larroche 2026).
- **Bowman et al.'s first-time-login rule:** a false positive rate of 4.4% still meant 530,082 false alarms. Only 0.10% of its alerts were labelled red-team events (our analysis).

**Incident grouping.** Each alert needs a true incident label: the attack it belongs to, a labelled cluster of related noise alerts, or, if it belongs with nothing else, a group of its own.

| Measure | Plain meaning | Notes |
|---|---|---|
| Split count | how many incidents one attack is spread over | per attack; easy to read |
| Contamination | how many noise alerts were merged into an attack's incident | per attack; easy to read |
| B-cubed precision and recall | for each alert, how much of its incident belongs with it, and how much of its true group was found | the only family of measures that meets all four basic requirements for grouping (Amigó et al. 2009) |
| Pairwise precision, recall and F1 | the same question over every pair of alerts | large incidents dominate |
| Adjusted Rand Index | pair agreement, corrected for chance | about 0 for random grouping, 1 for perfect |
| Homogeneity, completeness, V-measure | entropy-based versions | not corrected for chance; scikit-learn advises the Adjusted Rand Index for small samples |

On the sample day (re-implementation, each noise alert its own true group):
- **Simple counts:** the attack is in 1 incident, with 1 noise alert merged in (purity 4 of 5).
- **B-cubed:** precision 0.41, recall 1.0.
- **Pairwise:** precision 0.16, recall 1.0, F1 0.28.
- **Adjusted Rand Index:** 0.26.
- **Entropy-based:** homogeneity 0.69, completeness 1.0, V-measure 0.82.

The label choice matters a lot. If only repeats of the same detection (the printer, adware and VPN alerts) were labelled as true noise clusters, pairwise precision would be 0.38 instead of 0.16. Taking every noise group GraphOps formed as a true cluster would give 0.89, but that uses GraphOps' own output as the answer (our analysis). V-measure looks flattering here.

Our view: report the split and contamination counts for each attack, plus B-cubed precision and recall. Show the other measures only next to them.

**Stage order.** Kendall's tau-b can compare the time order of an incident's alerts with their ATT&CK stage order. Ties lower it: the sample attack scores 0.913 although no pair is out of order, because two alerts share a tactic. Report the count of out-of-order pairs next to it.

Two cautions:
- The incident API lists alerts by time, not by stage ([main.py L107](../backend/app/main.py#L107)). R5 can pass only because the script's times happen to follow the stages.
- Also measure how often noise-only incidents "follow stages in order". The sample's adware incident earns 5 stage points.

**Incident story.** The checker confirms only that each sentence cites IDs inside the incident ([story.py L64-L70](../backend/app/story.py#L64-L70)). It does not confirm that the cited facts support the sentence. The facts sent to the model also mix permissions with activity without saying which is which. For the sample attack they include the `HasSession` edges `laptop-42` to `it_admin` and `server-7` to `svc_db` next to the logons, so a story could describe a session snapshot as something that happened ([story.py L50-L55](../backend/app/story.py#L50-L55)). Passing each edge's kind to the model would help: permission, session snapshot (with its collection time) or observed activity. Today's `family` value would mark `HasSession` as granted. Measure:
- **Automatically:**
  - the share of LLM stories versus fact lists;
  - the dropped-sentence rate;
  - uncited and out-of-scope citations;
  - the share of the incident's alerts that are cited;
  - whether sentences follow time order.
- **By hand:** two reviewers label each kept sentence supported, unsupported or wrong, and rate completeness. Use the Kramer et al. codebook, and measure agreement with Cohen's kappa (a score for how far two reviewers agree beyond chance). In that Google study of 50 real incidents, unchecked AI summaries left out critical details 35% of the time and included factual errors 42% of the time.
- **Over repeats:** draft each incident at least 3 times, with neutral IDs.

**Alert-processing latency.** Measure each stage separately:
1. the event happens;
2. it is sent to Kafka;
3. it is read and written to Neo4j;
4. the alert is scored;
5. it appears in `/api/live`;
6. it appears in the inbox (not built yet).

How to measure:
- **Use one clock.** Take start and end times on the same machine with `time.monotonic()`. Comparing the producer's clock with the broker's or Neo4j's mixes in clock skew.
- **Measure from the intended send time**: replay start + (event time - day start) ÷ speed. Measuring from when the message actually went out hides slow periods, a mistake called coordinated omission.
- **Report p50, p95, p99 and the maximum, with at least 100 samples per setting.** One 30-alert day gives only 30 samples, too few for p99. Report cold and warm calls separately, with the poll interval.
- **Log consumer lag per partition** (how many messages are still waiting to be read): the latest offset (message position) in Kafka minus the offset saved in Neo4j. Standard Kafka lag tools show nothing, because GraphOps never commits offsets to Kafka ([stream.py L40-L44](../backend/app/stream.py#L40-L44)).
- **Keep simulated event times in the message body, never in the Kafka record timestamp.** By default Kafka 4.3 rejects records stamped more than an hour ahead of the broker's clock.
- **Drive 1x and 10x replays from a laptop.** The sample day lasts about 3.9 hours at 1x, 23.5 minutes at 10x and 141 seconds at 100x, and a Vercel Hobby function stops after 300 seconds.
- **Add server-side timestamps** (`ingested_at`, `scored_at`). Then latency can be computed exactly instead of by polling.

Today's numbers are not percentiles. The test sends one alert and polls every 0.2 seconds. The hosted 2.4 seconds in [hosting.md](hosting.md) is the time to drain a whole 5,000x replay, reported as a single figure with no spread.

### 2.10 Rules for honest evaluation

1. **Do not grade the weights on the data they were set on.** Freeze the weights, then write at least 10 held-out scenarios ([1.6](#16-a-scenario-library)), ideally by someone who did not set them, as Hopper's authors did. Tuning on test data inflates results (Arp et al. 2022).
2. **Hide the answers.** Use neutral alert IDs and keep labels in a separate file keyed by alert or event ID. Label noise clusters too.
3. **Score each alert when it arrives** as well as at the end of the day. End-of-day scores use later information, which Arp et al. call temporal snooping.
4. **Count small numbers honestly.** With 4 attack alerts, recall can only be 0, 0.25, 0.5, 0.75 or 1. Catching 4 of 4 is consistent with a true recall as low as 0.40 (95% Clopper-Pearson interval). Report counts with exact intervals, pooled over many scenarios.
5. **Compare with baselines and ablations.** Baselines: severity only (the dashboard's toggle), newest first, oldest first, random and alert count. Ablations: drop one question at a time. The score is the sum of the `breakdown` points (to within rounding), so dropping a question is a subtraction.
6. **Make randomness matter before averaging over seeds.** Changing the simulator's seed cannot change the ranking today, because the random events never reach the ranker. Let randomness reach alert timing, remote logons and routes, then report the mean and spread over at least 10 seeds.
7. **Follow Larroche's protocol for LANL** ([3.3](#33-lanl-cyber1)):
   - Split by time.
   - Count every remote logon, and compute measures per event, on the same test events for every detector.
   - Also report precision at a fixed daily alert budget (the number of alerts an analyst can check in a day). Hopper's authors used such a budget, reporting the share of attacks detected and false alarms per day.
   - All LANL labels come from one intrusion, so recall per intrusion is a single yes or no.
   - Never train on the labels.
   - Unlabelled red-team activity counts as a false positive, so LANL false-positive counts are upper bounds. Check a random sample by hand.
8. **Use verdicts carefully as labels.** Analysts judge mostly the top-ranked alerts, "new" does not mean "false", and every reseed wipes verdicts. Export them with a time and a reviewer first. Before verdicts become training data, propose "benign positive" and "undetermined" options to the team: today allowed but suspicious-looking activity has to be saved as "real" or "false" ([1.2](#12-what-makes-it-unrealistic)).
9. **Make the people test fair:**
   - Turn the tour off, because it tells people where the attack is.
   - Use a true raw-list baseline, because the "Severity only" view still highlights incidents.
   - Counterbalance the order (half the people start with the raw list, half with GraphOps) and use incidents of similar difficulty.
   - Record both time and accuracy.

### Sources for section 2

- Repository files as linked.
- Playwright: [web server](https://playwright.dev/docs/test-webserver), [locators](https://playwright.dev/docs/locators), [actionability](https://playwright.dev/docs/actionability), [mocking](https://playwright.dev/docs/mock), [trace viewer](https://playwright.dev/docs/trace-viewer), [visual comparisons](https://playwright.dev/docs/test-snapshots), [accessibility testing](https://playwright.dev/docs/accessibility-testing), [best practices](https://playwright.dev/docs/best-practices), [API testing](https://playwright.dev/docs/api-testing), [CI](https://playwright.dev/docs/ci), [Python test runner](https://playwright.dev/python/docs/test-runners), [release notes](https://playwright.dev/docs/release-notes).
- [Vitest](https://vitest.dev/guide/), [React Testing Library queries](https://testing-library.com/docs/queries/about/), [jsdom limits](https://github.com/jsdom/jsdom#unimplemented-parts-of-the-web-platform), [Vite server options](https://vite.dev/config/server-options).
- FastAPI: [testing](https://fastapi.tiangolo.com/tutorial/testing/), [dependency overrides](https://fastapi.tiangolo.com/advanced/testing-dependencies/), [response models](https://fastapi.tiangolo.com/tutorial/response-model/), [serving a frontend](https://fastapi.tiangolo.com/tutorial/frontend/). Schemathesis: [Python apps](https://schemathesis.readthedocs.io/en/stable/guides/python-apps/), [checks](https://schemathesis.readthedocs.io/en/stable/reference/checks/). [python-dotenv](https://github.com/theskumar/python-dotenv#readme).
- [axe-core](https://github.com/dequelabs/axe-core#readme). W3C: [WCAG 2.1.1 Keyboard](https://www.w3.org/WAI/WCAG22/Understanding/keyboard.html), [WCAG 2.2.2 Pause, Stop, Hide](https://www.w3.org/WAI/WCAG22/Understanding/pause-stop-hide.html), [complex images](https://www.w3.org/WAI/tutorials/images/complex/).
- [GitHub Actions Ubuntu 24.04 image](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md). Vercel [function limits](https://vercel.com/docs/functions/limitations). Neo4j [AuraDB FAQ](https://neo4j.com/cloud/platform/aura-graph-database/faq/) and [ORDER BY](https://neo4j.com/docs/cypher-manual/current/clauses/order-by/).
- scikit-learn: [precision](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.precision_score.html), [average precision](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.average_precision_score.html), [model evaluation](https://scikit-learn.org/stable/modules/model_evaluation.html), [clustering evaluation](https://scikit-learn.org/stable/modules/clustering.html), [adjusted Rand index](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.adjusted_rand_score.html). SciPy [Kendall's tau](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.kendalltau.html).
- Manning, Raghavan and Schütze, [Introduction to Information Retrieval, ch. 8](https://nlp.stanford.edu/IR-book/html/htmledition/evaluation-of-ranked-retrieval-results-1.html). Amigó et al., [A comparison of extrinsic clustering evaluation metrics based on formal constraints](https://link.springer.com/article/10.1007/s10791-008-9066-8), 2009. Bestgen, [Exact Expected Average Precision of the Random Baseline for System Evaluation](https://ufal.mff.cuni.cz/pbml/103/art-bestgen.pdf), 2015. Davis and Goadrich, [The Relationship Between Precision-Recall and ROC Curves](https://pages.cs.wisc.edu/~shavlik/abstracts/davis.icml06.abstract.html), 2006. Saito and Rehmsmeier, [The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets](https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0118432), 2015.
- Arp et al., [Dos and Don'ts of Machine Learning in Computer Security](https://www.usenix.org/system/files/sec22-arp.pdf), USENIX Security 2022. Larroche, [On Fair and Realistic Performance Evaluations for Graph-Based Lateral Movement Detectors](https://arxiv.org/abs/2607.29390), 2026. Bowman et al. and Hopper as in section 1.
- Gao et al., [Enabling Large Language Models to Generate Text with Citations](https://arxiv.org/abs/2305.14627) (ALCE). Kramer et al., [SOUPS 2025](https://www.usenix.org/system/files/soups2025-kramer.pdf).
- Google SRE book, [service level objectives](https://sre.google/sre-book/service-level-objectives/). [wrk2](https://github.com/giltene/wrk2) and [HdrHistogram](https://github.com/HdrHistogram/HdrHistogram) on coordinated omission. Python [time.monotonic](https://docs.python.org/3/library/time.html). Kafka 4.3 [topic configuration](https://kafka.apache.org/43/configuration/topic-configs/). librdkafka [statistics](https://github.com/confluentinc/librdkafka/blob/master/STATISTICS.md).

---

## 3. Where to get realistic data

### 3.1 Overview

| Source | Kind | What it gives GraphOps | Size | Licence | Access | Our view |
|---|---|---|---|---|---|---|
| [ADSynth](#32-adsynth) | synthetic | Active Directory (and cloud) permission graphs of any size | generated on your own machine | BSD-3-Clause (code) | GitHub | an optional second dataset, through an adapter |
| [LANL Cyber1](#33-lanl-cyber1) | mixed: real observed activity with controlled red-team events | 58 days of authentication events (logons, ticket requests and more), processes, network flows and DNS, plus 749 red-team lines | about 11.3 GB compressed | CC0 1.0 waiver | a form on the LANL page | detection tests: a days 1-3 slice to check the pipeline, then all 58 days |
| [Microsoft GUIDE](#microsoft-guide) | real observed, anonymised | 1.6 million alerts in 1 million analyst-graded incidents, plus expert priority ranks | 3.5 GB | CDLA-Permissive-2.0 | Kaggle | tests the parts of the score that do not need the graph |
| [AIT-ADS](#ait-ads) | controlled simulation | 2.66 million intrusion-detection alerts from 8 test scenarios, labelled by attack-phase time windows | 96 MB | CC BY 4.0 | Zenodo | tests incident grouping |
| [PicoDomain](#picodomain) | controlled simulation | network logs of a tiny Windows domain over 3 days, plus a red-team log | 16 MB | GPL-3.0 (as GitHub detects it) | GitHub | a fast test of the never-taken path |
| [OTRF Security-Datasets, Splunk attack_data and Sigma rules](#otrf-security-datasets-splunk-attack_data-and-sigma-rules) | controlled simulation, plus detection rules | real Windows event formats for single attack techniques, and real alert titles, levels and ATT&CK tags | kilobytes to megabytes per file | MIT (OTRF), Apache-2.0 (Splunk), Detection Rule License 1.1 (Sigma) | GitHub | templates for realistic events and alerts |
| [MITRE emulation plans and Attack Flow](#mitre-emulation-plans-and-attack-flow) | written attack descriptions, no telemetry (scenarios built from them are synthetic) | ordered, machine-readable attack steps for named threat groups | small | Apache-2.0 | GitHub | realistic attack timelines |
| [BloodHound CE sample data](#bloodhound-ce-sample-data) | synthetic (collected from fictional lab domains) | a small permission snapshot in SharpHound format | 166 KB | Apache-2.0 | download | a test file for a permission loader |

### 3.2 ADSynth

**What it is.** A program that generates synthetic Active Directory attack graphs: users, computers, groups, OUs (organisational units, folders of AD objects), GPOs (group policy objects) and the permissions between them. Newer modes add Microsoft Entra (cloud) and hybrid identities, including AI-agent identities.

| | |
|---|---|
| **Kind** | Synthetic. A program generates it from settings and random numbers. It contains no activity of any kind. |
| **Paper** | Nguyen, Falkner and Nguyen, "ADSynth: Synthesizing Realistic Active Directory Attack Graphs", DSN 2024, pp. 66-74, DOI 10.1109/DSN58291.2024.00021. The paper itself is closed access. The first author's free 2025 MPhil thesis contains an extended version as Chapter 3, and a short CC BY demo paper appeared at SIGCOMM 2024. |
| **Code** | [github.com/AUCyberLab/ADSynth](https://github.com/AUCyberLab/ADSynth). The first and only release, v2.0.0, came out on 28 September 2026. Python 3.8 or newer. |
| **Licence** | BSD-3-Clause for the code. The DSN-era archive on Zenodo is labelled CC BY 4.0. No licence is stated for generated graphs. The authors ask users to cite the DSN 2024 paper. |
| **How it runs** | Generation happens in memory and writes a file; it needs no database. Its separate `importdb` command loads the file into Neo4j through APOC, but it first deletes everything in the target database and drops all constraints and indexes. Never point it at a GraphOps database. |
| **Output** | One JSON Lines file in APOC-export style. Each node has a counter `id` ("0", "1", ...), labels starting with `Base`, and properties. The real AD identifier is `properties.objectid`. Each edge has a type label and start and end IDs. |
| **What it generates** | Node labels Domain, OU, Container, GPO, User, Computer and Group. About 20 permission and structure edge types: `MemberOf`, `AdminTo`, `CanRDP`, `CanPSRemote`, `ExecuteDCOM`, `AllowedToDelegate`, `ReadLAPSPassword`, `SQLAdmin`, `AllowedToAct`, `GenericAll`, `GenericWrite`, `WriteOwner`, `WriteDacl`, `Owns`, `AddMember`, `AddSelf`, `ForceChangePassword`, `AllExtendedRights`, `GetChanges`, `GetChangesAll`, `Contains` and `GpLink`. It also generates `HasSession` edges. |
| **How it aims for realism** | It encodes AD design practice, rather than learning from real data. Objects sit in a tiered OU structure (Tier 0 for the most privileged objects, Tier 1 for servers, Tier 2 onwards for everything else). Admin groups get rights over whole OUs, and a configurable share of tier-breaking sessions and permissions is injected as "misconfigurations". |
| **Realism evidence** | It was compared with one unnamed university's real AD (about 100,000 nodes and 1.2 million edges), which is not public. The comparison used summary measures only: graph density, sessions per user, the share of users with a path to Domain Admins, and choke points. |

**Limitations to know**

- **No activity over time.** There are no timestamped logons, flows, processes, alerts or attack timelines. `HasSession` edges are drawn at random, and some (Print and Server Operators on domain controllers) point the wrong way, User to Computer.
- **Sessions are spread unrealistically, and the authors say so.** In the university AD most users had sessions on 1-2 machines; ADSynth gives users generated sessions on many computers they are permitted to use, whatever their role. These sessions are random draws, not logons. The thesis also says its graphs contain some paths an attacker could not actually follow.
- **`highvalue` does not mean "critical".** It is true for every admin-only workstation ("privileged access workstation"), every server that is not a domain controller, most admin accounts (with ADSynth's built-in defaults about 1 in 10 is deliberately misplaced and lacks the flag; the shipped presets, `secure_1k` and `vul_1k` included, misplace none), Tier 1 and higher admin groups, nine built-in groups, the Domain node and the Group Policy Objects container. It is false for the domain controllers themselves.
- **Most rights point at OUs, not machines.** By default (`convert_to_directed_graphs = 0`, used by every shipped preset) admin rights go from a group to an OU, so a loader must expand them to the OU's contents. BloodHound treats `Contains` as an attack step for this reason. Some per-object edges are written either way.
- **IDs cannot be joined across graphs.** Every generated graph reuses the same SIDs (security identifiers, the unique IDs Windows gives accounts and groups), because the domain SID is a fixed constant and the counter restarts at 1000. Re-running with the same seed does not give an identical file.
- **Operating systems are dated.** Clients are Windows XP, 7 or 10, and domain controllers stop at Windows Server 2016.
- **The preset descriptions are wrong.** All presets use the same LAPS share and operating-system mix, and the size names are not user counts: `secure_1k` has 650 users and 150 computers.
- **The AI-agent identities are new and unreviewed.** They were added in March 2026, exist only in `generate_hybrid_v2`, use hard-coded, unsourced distributions, and their `HAS_TOOL_ACCESS` edges all point at the tenant node in that mode.
- **Setup snags.**
  - The pinned `neo4j==4.4.10` driver cannot share GraphOps' environment (which needs `neo4j>=5.28`), but generation does not need it.
  - The interactive menu also needs `openai` and `python-dotenv`, which are not in its requirements file.
  - It must run from its repository root, after creating a `generated_datasets` folder.
- **Size limits on the hosted site.** Neo4j's limits page gives AuraDB Free 200,000 nodes and 400,000 relationships, so only small graphs fit the hosted site.

**How ADSynth output maps onto GraphOps today**

| ADSynth | GraphOps | Status |
|---|---|---|
| node record `{id: counter, labels: [Base, X], properties}` | `network.json` node `{id, label, ...}` | needs a transform: drop `Base`, flatten properties, choose a readable unique ID, keep `objectid` as a property |
| User, Computer, Group | User, Computer, Group | needs a transform: map `operatingsystem` to `os`; there is no `owner` or `zone` in ADSynth |
| Domain, OU, Container, GPO | none (Domain and OU are listed in [schema.md](schema.md), Container and GPO are not; [seed.py L8-L10](../backend/app/seed.py#L8-L10) rejects all four) | no equivalent today |
| `MemberOf`, `AdminTo`, `CanRDP`, `GenericAll` to a User, Group or Computer | same names (granted) | direct; these are permissions, never evidence of activity |
| rights that point at an OU, and Domain Admins' `AdminTo` on the "DOMAIN COMPUTERS" group | `AdminTo` and the like on each object | needs a transform: expand through `Contains`, or generate with `convert_to_directed_graphs = 1` |
| other permission edges (`GenericWrite`, `WriteDacl`, `ForceChangePassword`, `GetChanges` and `GetChangesAll`, ...) | none; [seed.py L70-L72](../backend/app/seed.py#L70-L72) rejects unknown types | no equivalent; the team decides which count for attack paths ([schema.md](schema.md) open question 3) |
| `HasSession` (Computer to User) | `HasSession` | needs a transform: mark it as generated, give it no `first_seen` or `last_seen`, and flip the reversed User-to-Computer edges |
| `HasSession`, `AdminTo`, `CanRDP` | `LoggedInto`, `RemoteLogon` (observed) | **must not map**: generated permissions and sessions are not activity |
| `highvalue` | `critical` | needs a team decision: use an explicit Tier 0 rule (for example Domain Admins, Enterprise Admins, Administrators and the domain controllers), not a copy |
| AI-agent nodes and `DELEGATES_TO`, `ORCHESTRATES`, `HAS_TOOL_ACCESS` | planned in [schema.md](schema.md) | no equivalent today; the `seed.py` loader rejects them |
| ADSynth users and computers | LANL accounts or our sample organisation | **must not map** |

**How to use it safely (proposal):**
1. Keep R1-R8 on the hand-written sample. Add ADSynth only as a second, clearly labelled dataset: "synthetic, generated by ADSynth".
2. Run the interactive classic `generate`, not `run.py`. `run.py` produces no computers, permissions or sessions. Start from copies of the `secure_1k` and `vul_1k` presets with `convert_to_directed_graphs = 1` and a fixed seed. Use a separate virtual environment, and record the ADSynth commit and the settings file next to the output.
3. Write an offline, one-way adapter to the `network.json` format. It should:
   - do the transforms above;
   - tag every edge `family = granted` and `source = adsynth`;
   - print counts of everything it drops.
4. Set `critical` with an explicit Tier 0 rule and re-check R8-style results on the new graph.
5. Generate activity only with our own labelled simulator. It may choose routes that ADSynth's permissions allow, but every event is marked simulated.

### 3.3 LANL Cyber1

**What it is.** "Comprehensive, Multi-Source Cyber-Security Events": 58 consecutive days of de-identified events from five sources inside Los Alamos National Laboratory's corporate network.

| | |
|---|---|
| **Kind** | Mixed. The background activity is real and observed. The red-team events come from a controlled attack exercise run on that real network. |
| **Scale** | 1,648,275,307 events for 12,425 users, 17,684 computers and 62,974 processes. Counting full `user@domain` strings gives about 100,000 distinct account names, because these include computer accounts and local accounts on each computer. |
| **Files** | `auth.txt.gz` (7.2G as listed), `proc.txt.gz` (2.2G), `flows.txt.gz` (1.1G), `dns.txt.gz` (177M) and `redteam.txt.gz` (4.8K). LANL says "approximately 12 gigabytes compressed". The exact byte counts on the Imperial College mirror add up to 11.25 GB. The authentication file alone is about 69 GB uncompressed. |
| **Time** | Whole seconds counted from 1. The real dates are withheld, so weekdays and the timezone are unknown. |
| **Names** | Users, computers, processes and most ports are replaced consistently across all five files; `U1` is the same `U1` everywhere. SYSTEM, Local Service and well-known ports such as 443 are left as they are. |
| **Licence** | CC0 1.0: LANL waived all rights "to the extent possible under law". LANL asks you to cite Kent's 2016 book chapter (DOI 10.1142/9781786340757_0002) and the dataset (DOI 10.17021/1179829). |
| **Access** | Fill in the form on the [LANL page](https://csr.lanl.gov/data/cyber1/) with an email address and how you will use the data; it then shows download links. There is no account. LANL says it will email only if it finds problems with the dataset. The old direct links return 404. |

**Line formats** (fields are comma-separated, and `?` marks a missing value)

| File | Fields | Lines |
|---|---|---|
| auth | time, source user@domain, destination user@domain, source computer, destination computer, authentication type, logon type, authentication orientation, success/failure | 1,051,430,459 |
| proc | time, user@domain, computer, process name, start/end | 426,045,096 |
| flows | time, duration, source computer, source port, destination computer, destination port, protocol, packet count, byte count | 129,977,412 |
| dns | time, source computer, computer resolved | 40,821,591 |
| redteam | time, user@domain, source computer, destination computer | 749 |

The line counts come from a third-party load (G-Research) and add up exactly to LANL's total.

Values seen in published excerpts:
- authentication types: Negotiate, Kerberos and NTLM;
- logon types: Batch, Service, Network, Interactive, RemoteInteractive and Unlock;
- orientations: LogOn, LogOff, TGS, TGT and AuthMap;
- results: Success and Fail.

LANL publishes no complete list.

**What the red-team labels are and are not**

- 749 lines (715 after removing duplicates), all taken from the authentication data. They come from one simulated intrusion, almost all starting from computer `C17693`.
- The first labelled event is at second 150,885, in hour 42. None comes after day 30.
- The labels cover only authentications that involve user accounts, and the labelled moves use NTLM. LANL's web page says only that they "may be used as ground truth of bad behavior". Kent's chapter, LANL's official description, warns that they are a subset of the red team's activity and does not call them lateral movements; we know this only through Larroche's 2026 paper ([section 6](#6-what-we-could-not-verify)).
- No process, flow or DNS event is labelled. The data contains no security alerts.
- The labels are very rare: about 1 authentication line in 1.4 million.

**Other limits**

- **Failed logons are partial.** They are included only for users who also had a successful logon somewhere in the data.
- **Some auth lines are ticket requests, not logons.** In this release, Kerberos ticket requests (TGS) were drawn as if the user's computer authenticated to the target computer. LANL's own 2017 paper says a ticket request only grants a credential. So an auth line between two different computers is not proof of a logon on the second one.
- **Flows were collected only at central routers.** A missing flow does not prove there was no traffic.
- **A DNS lookup is only a "likely" connection.**
- **Process names are opaque tokens** such as `P16`. There is no parent process or command line.

**How LANL maps onto GraphOps**

| LANL | GraphOps | Status |
|---|---|---|
| auth, LogOn, Success, same source and destination computer | `(User)-[:LoggedInto]->(Computer)` with logon and auth types | needs a transform: aggregate by user, computer and hour, with `first_seen`, `last_seen` and `count` |
| auth, LogOn, Success, different computers | `(Computer)-[:RemoteLogon]->(Computer)` with the destination user | needs a transform: today an edge keeps only the first user per machine pair ([events.py L153-L154](../backend/app/events.py#L153-L154)), so make it per user |
| auth with TGS, TGT, AuthMap or LogOff | none | do not create logon edges |
| auth with Fail | a failure count | must not count as used access |
| `user@domain` | `User.id` | needs a transform: keep the full string, and flag computer (`$`), built-in and local accounts instead of dropping them |
| flows | `(Computer)-[:ConnectedTo]->(Computer)` | needs a transform: ports can be tokens such as `N10471`, and the stream drops port and bytes today |
| proc | a `ProcessStart` event | needs a transform: no parent; "End" lines have no matching message kind |
| dns | none | must not become `ConnectedTo` |
| redteam | a separate evaluation file | **must not map** onto alerts or edges. Match each line to one auth event on time, destination user, source and destination, as Larroche's published code does. |
| (absent) groups, permissions, critical assets, zones, alerts | none | never invent them. Any critical set or alert rule is our documented assumption. |
| LANL IDs | IDs from any other dataset, including LANL's 2014 and 2017 releases | **must not map** |

**How to use it (proposal)**
1. **Decide as a team, then use the official form.** One person fills it in honestly. An Imperial College server copies the files without the form, but we could not confirm it is official and LANL publishes no checksums, so do not use it to skip the form.
2. **Download the 4.8 KB `redteam.txt.gz` first** and profile it: lines per day, users, source and destination computers.
3. **Work on a slice outside the repository, then on the whole file.** Stream `auth.txt.gz` up to a time cut-off (LANL does not say the file is in time order, see [section 6](#6-what-we-could-not-verify), so check that times never decrease before stopping early), starting with days 1-3: about 54 million lines and 400 MB compressed (our analysis). Keep LogOn lines, aggregate them, and load them into a separate local Neo4j with batched writes. That slice holds only hours 42-72 of a red-team exercise that runs to day 30, so use it to check the pipeline; the protocol in step 4 needs all 58 days, streamed and aggregated the same way. Do not use AuraDB Free or the per-message stream. LANL averages about 210 authentication lines a second, and the stream stores one `Event` node per message, so AuraDB Free's node limit would fill in about a quarter of an hour at the 200,000 nodes on Neo4j's limits page, or about 4 minutes at the 50,000 its free-database page gives (our analysis).
4. **Evaluate with Larroche's protocol** ([2.10](#210-rules-for-honest-evaluation)):
   - Use the first 41 hours as history only and test on everything after, including days 31-58 to measure false positives.
   - Keep every remote logon and every authentication type.
   - Compare against Bowman et al.'s first-time-login rule.
5. **Make critical assets an explicit assumption.**
   - Run once with no critical assets.
   - Run once with an "assumed critical" set chosen by a written rule on the history period only, for example the top *k* computers by distinct inbound sources. Never choose it from red-team targets.
   - Show "assumed" on screen.
6. **Call LANL alerts "derived".** LANL has no alerts, so any alerts are ours. They come from our own rules run on real events, and are a synthetic layer that should be labelled that way.

**Sibling LANL releases.** Neither has labels, and their names do not match Cyber1's.
- The [2017 Unified Host and Network](https://csr.lanl.gov/data/2017/) set covers about 90 days of Windows host events (with logon types and parent processes) and netflow. It is about 194 GB compressed by the mirror's file sizes, behind the same form, CC0.
- The [2014 user-computer authentication](https://csr.lanl.gov/data/auth/) set covers 9 months of 708 million successful user-to-computer authentications (Kerberos-based, not necessarily logons) as "time, user, computer", with no source computer. It is 2.3 GB, CC0.

### 3.4 Other datasets with a clear benefit

#### Microsoft GUIDE

- **What.** Anonymised, real alerts from Microsoft Defender XDR customers (**Kind:** real observed):
  - 13 million evidence rows, 1.6 million alerts and 1 million incidents;
  - about 6,100 organisations over two weeks;
  - 9,100 detector IDs and 441 ATT&CK techniques.
- **Labels.**
  - Each incident has a triage grade set by the customer's own analysts: true positive, benign positive or false positive. The paper notes that "benign positive" is used inconsistently, and that not every kind of incident gets graded.
  - The July 2026 version adds expert priority ranks for the top 20 incidents in each of 499 organisation queues (9,980 incidents). These measure which incidents deserve attention first, not which are real. The paper's own ranker, in its publicly reproducible form (BM25 with a component cap), already reaches 98.9% precision@10 on them; plain BM25 reaches 96.3% and a plain rarity weighting (TF-IDF) 70.0%.
  - An incident is a group Microsoft's product formed through shared entities. It is the vendor's grouping, not checked truth.
- **Format.**
  - 45 CSV columns (the test file adds a 46th, `Usage`, marking public and private rows). Alert titles and entity fields are integer codes. `Category` holds tactic names. `MitreTechniques` holds semicolon-separated lists and is often empty.
  - There is no severity column, although the Kaggle text mentions severity. GraphOps' stream rejects alerts without one ([events.py L21](../backend/app/events.py#L21)), so any value filled in would be invented and must be labelled that way. The priority column is called `QueueRank`.
  - IDs were hashed, then replaced with random IDs, and timestamps carry deliberate noise. Missing entity values appear to be stored as one constant number per column. Check this before linking alerts through shared entities.
- **Size and access.** `GUIDE_Train.csv` is 2.43 GB, `GUIDE_Test.csv` 1.09 GB and the queue rankings 136 KB (version 2, 18 July 2026). The data is on [Kaggle](https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction). Kaggle's download interface works without an account, although Kaggle's own instructions still ask for one.
- **Licence.** CDLA-Permissive-2.0. Share the licence text with any copy; there are no restrictions on results.
- **Fit.**
  - GUIDE has no permissions, logins or critical assets. On it, the hops, blast, choke and never-taken questions all score 0. Only the linked and stage-order questions and incident ranking can be tested.
  - Load one organisation at a time, and never join its IDs with any other organisation or dataset.
  - First create a `User` or `Computer` node for each account or device ID in that organisation's evidence rows. GraphOps links an alert only to nodes that already exist, and IP addresses, URLs, files and e-mail messages have no GraphOps label, so an alert that names only those is never scored ([2.6](#26-integration-and-streaming-tests)). Skip each column's missing-value code (see Format): never create a node for it, and never treat two IDs as the same account because they share a row with it.
  - Keep `AccountSid`, `AccountUpn`, `AccountObjectId` and `AccountName` as separate IDs unless they appear on the same evidence row; never assume two of them are the same person.
  - Use the grades and ranks only for evaluation. Grades belong to whole incidents, so never copy them onto single alerts as "real" or "false", and do not fold benign positives into either.
  - GraphOps scores alerts, while GUIDE ranks incidents. Give each GUIDE incident the score of its highest-scoring alert, as GraphOps already does for its own incidents, and rank GUIDE's incidents, not GraphOps' groups. Report precision@5, @10 and @20 per queue, against random, time-order and alert-count baselines and against the paper's BM25-with-cap ranker (98.9% precision@10).
- **Cite.** The GUIDE paper (ACM Web Conference 2025 Companion, pp. 191-200, DOI 10.1145/3701716.3715209). For the priority labels, also cite Freitas, Gharib and Magenheim, "Adaptive Incident Prioritization for Security Operations at Scale" (2026).

#### AIT-ADS

- **What.** 2,655,821 alerts from three intrusion-detection tools (Wazuh, Suricata and AMiner) over 8 test scenarios. Each scenario has a multi-step attack and false alarms caused by simulated users. **Kind:** controlled simulation; real detection software raised the alerts on simulated activity.
- **Labels.** The start and end times of each attack phase. A false alarm that happens to fire during an attack phase therefore counts as attack-related.
- **Format.** Two JSON alert files per scenario (`<scenario>_wazuh.json` holds the Wazuh and Suricata alerts, `<scenario>_aminer.json` the AMiner alerts), whose fields differ by tool, plus one `labels.csv` with the start and end time of each attack phase. The tools do not share a severity scale, so any mapping to GraphOps' four levels is our assumption.
- **Size, licence, access.** A 96 MB zip on [Zenodo](https://zenodo.org/records/8263181), CC BY 4.0. The logs underneath (AIT-LDS v2) carry line-level attack labels but are CC BY-NC-SA 4.0, which forbids commercial use. Version 2.1 of those logs (April 2026, same licence) can also be downloaded without packet captures: about 6.4 GB in all, instead of 130.6 GB.
- **Limits.** Small test networks (mail server, file share, WordPress, VPN, firewall) with no Active Directory mentioned, and few user entities, so linking relies on hosts.
- **Fit.** Its authors describe it as the first public alert set designed for testing alert aggregation and correlation. Load one or two scenarios locally as `Alert` nodes involving computers, and compare GraphOps' incidents with the attack phases using B-cubed and pairwise measures ([2.9](#29-how-to-measure-ranking-grouping-the-story-and-speed)).

#### PicoDomain

- **What.** Zeek network logs (Zeek is an open-source network monitor) from a small Windows Active Directory lab over three days in July 2019: connections, Kerberos, NTLM, SMB, DCE-RPC, DNS and DHCP. A red-team log names machines, users and actions; its manual timestamps are accurate to about a minute. **Kind:** controlled simulation.
- **Size, licence.** About half a million records, 16 MB compressed. GitHub detects the licence as GPL-3.0.
- **Limits.**
  - About six hosts: two HR workstations, two R&D workstations, an XP machine and a domain controller.
  - Network data only, and nights are unrealistically quiet.
  - Bowman et al. found a first-time-login rule caught every labelled attack event here, with only 11 false alarms. They note this "is likely only to hold in relatively small and simulated environments".
- **Fit.** A fast, readable test of the never-taken path:
  - Build `RemoteLogon` from NTLM and SMB sessions to a machine, mapping machines by hostname rather than IP address because of DHCP. Kerberos records are ticket requests, not logons, as with LANL ([3.3](#33-lanl-cyber1)); if they are used, mark the edges they add as inferred from tickets. Network logs cannot show logons at the keyboard, so any `LoggedInto` edge built here is also an inference.
  - Treat the first day as history.
  - Count how many red-team hops show up as first-time routes, and how many harmless first-time routes appear each day.

#### OTRF Security-Datasets, Splunk attack_data and Sigma rules

- **OTRF Security-Datasets** ([GitHub](https://github.com/OTRF/Security-Datasets)) are small recordings of single attack techniques, plus multi-step sets such as the project's own re-run, in its lab, of the APT29 emulation plan from MITRE's ATT&CK Evaluations (round 2).
  - **Format:** Windows Security and Sysmon (Microsoft's free process and network logger) events as JSON, plus packet captures (and Zeek logs for some multi-step sets). About 9 in 10 single-technique files have a metadata file with ATT&CK technique and tactic IDs. Those IDs predate ATT&CK v19 (for example T1222 is still tagged TA0005), so remap them before use.
  - **Size:** tens of kilobytes to a few megabytes per single-technique file. The multi-step sets are bigger: the APT29 host logs are 14 MB and 43 MB zips, and some packet-capture zips are over 50 MB.
  - **Kind:** controlled simulation in tiny Azure lab domains, for example `THESHIRE.LOCAL` with `WORKSTATION5`, `WORKSTATION6` and `MORDORDC`.
  - **Licence:** MIT. The LICENSE file (MIT since 2021, GPL-3.0 before), the README badge and the project site say MIT; only an old footer in the README still says GPL-3.0. Keep the MIT notice with any copied files.
  - **Upkeep:** the last commit was in September 2023.
- **Splunk attack_data** ([GitHub](https://github.com/splunk/attack_data)) holds raw logs, mostly per ATT&CK technique, recorded mostly in Splunk's Attack Range lab (Splunk with Windows and Linux servers). It also has Linux, cloud, firewall and malware data, and sample Microsoft Defender alerts from a demo tenant.
  - **Size:** over 9 GB in total through Git LFS, but single technique folders can be pulled.
  - **Licence:** Apache-2.0.
  - **Kind:** controlled simulation, except one small folder of anonymised Pass-the-Hash logs described as extracted from real data.
- **SigmaHQ rules** ([GitHub](https://github.com/SigmaHQ/sigma)) are about 3,150 public detection rules. Each has a title and a level (informational, low, medium, high or critical). Almost all have ATT&CK tags such as `attack.t1550.002`, though about one in nine core rules has a tactic tag only.
  - **Licence:** the Detection Rule License 1.1. Every alert built from a rule match must keep the rule's author (its `author` field), even if nothing is shared. Sharing the rules themselves also needs a link to the rule, a statement that they are under the DRL 1.1, and the licence text or a link to it.
  - **Running them:** a runner such as Zircolite applies the rules to recorded events and outputs matches as JSON.
- **Fit:**
  - Windows event 4624 maps by logon type to `LoggedInto` or `RemoteLogon`.
  - Group-change events 4728, 4729, 4732, 4733, 4756 and 4757 map to the existing `MemberOf` added or removed message.
  - Sysmon event 1 maps to `ProcessStart`, and Sysmon event 3 to `Connection`.
  - A Sigma match becomes an `Alert` (title, level, tactic and technique); the users and machines it involves come from the matched events.
  - Copy formats and patterns only. Lab host and account names must never become nodes in our organisation.

#### MITRE emulation plans and Attack Flow

- **The emulation library.** MITRE's Center for Threat-Informed Defense publishes [adversary emulation plans](https://github.com/center-for-threat-informed-defense/adversary_emulation_library) for 11 named groups (for example APT29, FIN6 and Wizard Spider) under Apache-2.0, last updated in May 2025, nine of them with machine-readable steps: a tactic, a technique and a step number. The steps follow each scenario's own timeline, not a strict stage order. They have no timestamps, use old ATT&CK versions (for example v8) with the odd wrong tactic, and come from tiny labs (Wizard Spider's has three hosts). Newer plans, such as LockBit, Cl0p and Scattered Spider, live in [attackevals/ael](https://github.com/attackevals/ael), also Apache-2.0.
- **Attack Flow.** [Attack Flow](https://github.com/center-for-threat-informed-defense/attack-flow) (Apache-2.0) describes attack sequences in STIX 2.1, a standard JSON format for threat information. Each action can carry a tactic and technique ID and start and end times. Its corpus has 41 example flows, mostly of real incidents, but only 2 of them record times. It supplies step order, not realistic gaps between steps.
- **Kind:** not telemetry. These are written attack descriptions: the emulation plans script named groups' behaviour for small labs, and most Attack Flow examples describe real incidents from public reports. Scenarios built from them are synthetic.
- **Fit.** Use both to script the order of steps in our scenarios, re-enacted on our own machines and accounts. Add timing and detection gaps as stated assumptions. Map old tactic and technique IDs to the current ATT&CK version (v19 split Defense Evasion into Stealth and Defense Impairment), and check each step's tactic: Wizard Spider's plan tags its ransomware step (T1486) as command-and-control. Plan steps follow the scenario, not strict stage order.

#### BloodHound CE sample data

- **What.** BloodHound Community Edition's [sample AD data](https://bloodhound.specterops.io/get-started/quickstart/ce-ingest-sample-data): about 166 KB, three fictional domains, 100 users, 34 computers and 285 groups, with thousands of permission entries in SharpHound format. It is a permission snapshot like ADSynth's, with no activity over time. **Kind:** synthetic (collected from fictional lab domains). Apache-2.0.
- **Fit.** A small, realistic file for testing a permission loader before ADSynth. BloodHound documents about 40 node types and more than 130 edge types; only the subset in [seed.py L8-L10](../backend/app/seed.py#L8-L10) loads today.

**For checking ATT&CK tags:** MITRE publishes the whole of ATT&CK as [STIX data](https://github.com/mitre-attack/attack-stix-data) under a royalty-free licence. Version 19 (April 2026) renamed TA0005 "Stealth" and added TA0112 "Defense Impairment", and v20 (October 2026) is current. All 12 technique IDs in the sample alerts and the 2 extra ones in schema.md are current. GraphOps already uses the new tactic IDs ([scoring.py L6-L7](../backend/app/scoring.py#L6-L7)) and names ([tactics.js](../frontend/src/tactics.js)), so a validation check would confirm, not change, them. It would change tags taken from older sources, such as OTRF metadata, the emulation plans and the Sigma tag appendix, which predate ATT&CK v19.

### 3.5 Considered, weaker fit

| Source | Kind | Why not now |
|---|---|---|
| DARPA OpTC | controlled simulation: generated normal activity plus a red team on a 1,000-host Windows test network (500 hosts recorded) | About 1 TB of compressed JSON, with no alerts and no permission data. One 25-host block for one red-team day is about 2.3 GB. The original is public domain. A corrected version from Inria (January 2026, CC BY 4.0, about 939 GB) and third-party per-event labels now exist. Worth it later for hop timing at scale. |
| CERT Insider Threat Test Dataset | synthetic | Insider scenarios, not lateral movement, and its own authors say it is realistic only where designed to be. Its licence is contradictory: KiltHub shows CC BY 4.0, but each archive contains a 2011 ExactData end-user agreement that forbids redistribution and most derivative works. Use at most for ideas about normal behaviour, after clearing the licence. |
| Splunk Boss of the SOC (BOTS v1-v3) | controlled simulation: staged scenarios with fictional companies (the README says some evidence may come from real incidents, without saying which) | Mostly pre-indexed Splunk data (v2 is 17.6 GB), and the question-and-answer keys are only available on request. Good for demo realism, not for scoring. CC0. |
| Also checked | various | EVTX-ATTACK-SAMPLES (278 tiny Windows log files, GPL-3.0; OTRF covers the same need). AD generators and labs: adsimulator (last updated 2022), BloodHound DBCreator (targets the retired legacy BloodHound, unchanged since 2020), BadBlood and GOAD (build a real lab domain; GOAD needs about 24 GB of RAM and 115 GB of disk). Atomic Red Team and MITRE Caldera (tools that run attacks; they need an isolated lab and permission). LMDG (35 multi-step lateral-movement attacks in a 25-machine network, but the linked repository is empty, so the data is not public). |

### 3.6 Combining sources without inventing ground truth

1. **One dataset per Neo4j database**, or every ID prefixed with its dataset. GraphOps finds nodes by `id` alone ([events.py L149](../backend/app/events.py#L149), [seed.py L21](../backend/app/seed.py#L21)), so two datasets with overlapping IDs would merge silently.
2. **Never join identities across datasets.** This includes LANL's three releases and two ADSynth graphs, which reuse the same SIDs.
3. **Take permissions only from permission sources** (ADSynth, SharpHound) **and activity only from activity sources** (LANL, lab recordings, our simulator). Never turn one into the other. Our simulator may choose routes that permissions allow ([3.2](#32-adsynth)), but what it produces is simulated activity, never evidence that a permission was used.
4. **Keep labels in evaluation files**, never in the graph, in IDs or in anything the ranker reads. Never create alerts from a label file.
5. **Re-enact real attack patterns on our own synthetic machines and accounts**, labelled synthetic. Never copy a victim's or a lab's host names.
6. **Use published statistics only as orders of magnitude**, unless we recompute them on LANL with GraphOps' own definitions. Each paper uses a different network, filter and time window.
7. **Show the kind of data on screen.** The "synthetic data" label and the tour's "All 30 alerts" are hard-coded today ([Dashboard.jsx L81](../frontend/src/Dashboard.jsx#L81), [Tour.jsx L15-L21](../frontend/src/Tour.jsx#L15-L21)) and would be wrong on LANL.
8. **Keep licence duties:**
   - GUIDE's licence text travels with any copy.
   - Alerts built from Sigma matches must keep each rule's author; sharing the rules also needs a link to the rule, a DRL 1.1 notice, and the licence text or a link to it.
   - AIT-ADS and corrected OpTC need CC BY attribution, and the AIT logs are non-commercial.
   - CERT's licence conflict must be cleared first.
   - GPL licences on tools matter only if we redistribute their code, not their output. PicoDomain and EVTX-ATTACK-SAMPLES are themselves data under GPL-3.0 (as GitHub detects it), so keep copies and extracts out of our repository until the team has checked the terms.
   - Any copy of ATT&CK data must carry MITRE's copyright notice and licence.

### Sources for section 3

- ADSynth: [repository](https://github.com/AUCyberLab/ADSynth) (read at commit `d7019d0`, two commits after the v2.0.0 tag), [DSN 2024 paper](https://doi.org/10.1109/DSN58291.2024.00021), the first author's thesis, "High-Order Graph Models and their Applications in Active Directory Security" (University of Adelaide, 2025), [hdl.handle.net/2440/145256](https://hdl.handle.net/2440/145256) (the repository's page returned an error on 14 October 2026, but its [catalogue record](https://digital.library.adelaide.edu.au/server/api/core/items/3d48c5bf-e6cc-4c7b-affa-e8454e9035cd) is online), [SIGCOMM 2024 demo](https://doi.org/10.1145/3672202.3673732), [Zenodo archive](https://zenodo.org/records/10212124). BloodHound [Contains](https://bloodhound.specterops.io/resources/edges/contains) and [OpenGraph graph data format](https://bloodhound.specterops.io/opengraph/developer/graph-data). Neo4j [Aura limits](https://neo4j.com/docs/aura/products-tiers-and-limits/) and [Python driver upgrade notes](https://neo4j.com/docs/python-manual/5/upgrade/).
- LANL: [Cyber1 page](https://csr.lanl.gov/data/cyber1/), [dataset DOI](https://doi.org/10.17021/1179829), [2017 release](https://csr.lanl.gov/data/2017/), [2014 release](https://csr.lanl.gov/data/auth/), [G-Research line counts](https://github.com/G-Research/dgraph-lanl-csr/blob/master/README.md), Larroche [2026](https://arxiv.org/abs/2607.29390) and [2025](https://arxiv.org/abs/2504.13527), [LMDEval code](https://github.com/cl-anssi/LMDEval/blob/main/extract_lanl.py), [Euler (NDSS 2022)](https://www.ndss-symposium.org/wp-content/uploads/2022-107A-paper.pdf), Bowman et al. and Turcotte et al. as in section 1.
- GUIDE: [Kaggle](https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction), [paper](https://arxiv.org/abs/2407.09017) (published version DOI 10.1145/3701716.3715209), [prioritisation paper](https://arxiv.org/abs/2607.16963), [CDLA-Permissive-2.0](https://cdla.dev/permissive-2-0/), [Kaggle CLI](https://github.com/Kaggle/kaggle-cli).
- AIT-ADS [alerts](https://zenodo.org/records/8263181), [paper](https://arxiv.org/abs/2308.12627), [logs](https://zenodo.org/records/5789064). PicoDomain [repository](https://github.com/iHeartGraph/PicoDomain) and [paper](https://arxiv.org/abs/2008.09192). DARPA OpTC [repository](https://github.com/FiveDirections/OpTC-data) and [corrected version](https://entrepot.recherche.data.gouv.fr/dataset.xhtml?persistentId=doi:10.57745/UXCWOC). CERT [dataset](https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247) and [generator paper](https://www.ieee-security.org/TC/SPW2013/papers/data/5017a098.pdf). Splunk [BOTS v1](https://github.com/splunk/botsv1), [v2](https://github.com/splunk/botsv2), [v3](https://github.com/splunk/botsv3). LMDG [paper](https://arxiv.org/abs/2508.02942) and [empty repository](https://github.com/WASPLab/LMTrace).
- [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets), [Splunk attack_data](https://github.com/splunk/attack_data), [SigmaHQ](https://github.com/SigmaHQ/sigma), [Sigma specification](https://github.com/SigmaHQ/sigma-specification), [Detection Rule License](https://github.com/SigmaHQ/Detection-Rule-License), [Zircolite](https://github.com/wagga40/Zircolite), [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [Caldera](https://github.com/apache/caldera), [CTID emulation library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library), [Attack Flow](https://github.com/center-for-threat-informed-defense/attack-flow), [ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data), [ATT&CK tactics](https://attack.mitre.org/tactics/enterprise/), [adsimulator](https://github.com/nicolas-carolo/adsimulator), [BadBlood](https://github.com/davidprowe/BadBlood), [DBCreator](https://github.com/BloodHoundAD/BloodHound-Tools/tree/master/DBCreator), [GOAD](https://github.com/Orange-Cyberdefense/GOAD), [BloodHound CE sample data](https://bloodhound.specterops.io/get-started/quickstart/ce-ingest-sample-data). Microsoft [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and [security group management events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management).

---

## 4. Prioritised recommendations

These are proposals for the team. Nothing here has been built.

- **P1:** do first. High value at low cost, or needed before any honest evaluation.
- **P2:** next.
- **P3:** later.
- **Effort** is for a small hackathon team: S is under a day, M is 1-3 days, L is more than 3 days.

PROJECT_SPEC sets 20 October 2026 for the first flow, and [pitch.md](pitch.md) gives 31 October for prototype submission.

| # | Priority | Effort | Recommendation | Why |
|---|---|---|---|---|
| 1 | P1 | S | Keep `data/sample_org` unchanged as the demo and tuning day. Put realism into a separate dataset and simulator settings, with every parameter tagged "calibrated" or "assumption". | The tests pin the sample ([1.5](#15-how-to-model-each-part-more-realistically)) |
| 2 | P1 | S | Run the existing backend tests on every push with GitHub Actions on a pinned `ubuntu-24.04` runner with Python 3.12. | Nothing runs automatically today ([2.8](#28-continuous-integration-and-test-safety)) |
| 3 | P1 | S | Adopt the test safety rules: explicit database and Kafka settings, a fake LLM, and read-only checks of the hosted site. | The hosted site has shared data and no sign-in ([2.8](#28-continuous-integration-and-test-safety)) |
| 4 | P1 | S | Add a test that the attack incident holds only attack alerts (by our re-implementation it would fail today because of `n-11`), plus tests for the incident, story and replay endpoints, blast-radius edges and paths, and the networkx choke-score fallback. | Real gaps in today's tests ([2.1](#21-what-is-tested-today)) |
| 5 | P1 | M | Write an offline evaluation script with separate label files. It reports precision@k, recall@k, the rank of the last attack alert, false alarms per day, AP, the split and contamination counts and B-cubed. It includes baselines and one-question-removed ablations, and scores each alert both at arrival and at the end of the day. | No measurement of ranking or grouping exists ([2.9](#29-how-to-measure-ranking-grouping-the-story-and-speed)) |
| 6 | P1 | M | Freeze the weights, then write at least 10 held-out scenarios from the library in [1.6](#16-a-scenario-library), with neutral IDs and labelled noise clusters. | The weights have only ever been checked on the sample day ([1.2](#12-what-makes-it-unrealistic)) |
| 7 | P1 | M | Add normal novelty to the simulator: harmless remote logons, first-time routes at stated rates, and reuse of routes next to critical assets. | Today the never-taken path cannot raise a false alarm |
| 8 | P1 | M | Build a Playwright journey suite with a mocked API, plus a contract test and one or two full-stack tests. | No browser tests exist ([2.4](#24-browser-tests)) |
| 9 | P1 | S | Review and fix the statements in our other documents listed in [section 5](#5-things-in-our-other-documents-that-need-correcting). | Teammates and judges repeat them |
| 10 | P2 | M | Add the streaming robustness tests in [2.6](#26-integration-and-streaming-tests), and a latency harness on one clock with p50, p95 and p99 from at least 100 samples. Propose `ingested_at` and `scored_at` timestamps. | Today's speed figures are single measurements |
| 11 | P2 | M | Make the realistic dataset model default rights, logon types, `HasSession` as an observation, tiers, and computer, local and service accounts and infrastructure hubs. | [1.2](#12-what-makes-it-unrealistic) and [1.5](#15-how-to-model-each-part-more-realistically) |
| 12 | P2 | M | Make alerts realistic: Sigma titles, levels and tags, learned from matches on OTRF or Splunk recordings and re-enacted on our own synthetic machines and accounts (never the labs' host or account names), with every such alert labelled as derived by us; lists of tactics; true, benign and false positives (and undetermined); UTC times with separate created and activity times; duplicates. | [1.4](#14-what-real-enterprise-data-looks-like), [3.4](#34-other-datasets-with-a-clear-benefit) |
| 13 | P2 | M | Test the never-taken path on PicoDomain (16 MB) and incident grouping on AIT-ADS (96 MB). | Small downloads with labels from controlled lab attacks ([3.4](#34-other-datasets-with-a-clear-benefit)) |
| 14 | P2 | M | Test incident ranking on GUIDE (download only the 1.09 GB test file and the rankings). Report precision@5, @10 and @20 per queue against baselines, and state which questions cannot work without a graph. | The only public source of real analyst grades |
| 15 | P2 | S | Run an accessibility pass (axe plus manual), add Vitest component tests and in-process Schemathesis, and propose the selector and accessibility hooks. | [2.4](#24-browser-tests), [2.5](#25-api-and-contract-tests), [2.7](#27-accessibility-and-visual-tests) |
| 16 | P2 | M | Add ADSynth as an optional second dataset through an offline adapter, with an explicit Tier 0 rule for `critical`. | Realistic permission structure ([3.2](#32-adsynth)) |
| 17 | P2 | L | With team approval, evaluate on LANL: a days 1-3 slice first, then all 58 days under Larroche's protocol, treating critical assets as an assumption. | The only real-network test with red-team labels ([3.3](#33-lanl-cyber1)) |
| 18 | P2 | S | Propose "benign positive" and "undetermined" verdict options, and store each verdict's time and reviewer, before verdicts are used as training data. | Allowed but suspicious-looking activity cannot be recorded today ([1.2](#12-what-makes-it-unrealistic)), and every reseed wipes verdicts |
| 19 | P3 | M | Benchmark scale: graphs of about 1,000, 5,000 and 20,000 nodes and 100, 1,000 and 10,000 alerts. Time `run_all` and `score_all`, the blast radius, `/api/alerts` response size (Vercel caps responses at 4.5 MB) and ring-graph rendering. | Several queries and the linking loop grow quickly with size |
| 20 | P3 | M | Evaluate stories once API credit exists: automatic citation measures plus two human reviewers. | The checker confirms citation scope, not truth |
| 21 | P3 | M | Write a people-test protocol, and add a few screenshot checks and a read-only check of the hosted site. | [2.7](#27-accessibility-and-visual-tests), [2.10](#210-rules-for-honest-evaluation) |
| 22 | P3 | L | Later: the OpTC hop timing at scale; BOTS (CC0) only for demo realism; CERT only for ideas about normal behaviour, once its licence conflict is cleared. | [3.5](#35-considered-weaker-fit) |

---

## 5. Things in our other documents that need correcting

Found while checking sources and code. **None of these has been changed.** They are listed for the team to review.

| Where | It says | What we found |
|---|---|---|
| [research.md](research.md) line 243 | Argus's and Euler's "precision" fell to 0.09% and 0.02% | Those are average precision (AP), not precision. Both detectors kept an AUC of about 98% (Larroche 2026, Table 5). |
| research.md line 253 | a "never seen this login before" rule "caught 72% of attacks" | 72% of the 749 labelled red-team authentication events (542), not of attacks (Bowman et al., Table 3) |
| research.md line 254 | Hopper caught "94.5% of 300+ attack scenarios" | true, but on private Dropbox data with 326 synthetic attacks plus one red-team exercise run on Dropbox's network (a controlled simulation), not on LANL |
| research.md line 311 | ADSynth "exports them to Neo4j or BloodHound format" | It writes a JSON Lines file. Its Neo4j import wipes the target database. Its BloodHound zip comes only from `run.py`, which ADSynth's README calls the hybrid v2 pipeline and which produces no computers, permissions or sessions. From reading BloodHound CE's ingest code (not tried), its loader would reject most of the files in the zip. |
| research.md line 312 | LANL is "public domain"; access is "with an email form"; "58 days of real logins" for "Testing never-taken-path detection with real attacks" | CC0 1.0 waiver (in effect public domain). Access is an on-page form asking for an email address and intended use, which then shows the links. The auth file holds every authentication event, including ticket requests, not only logins. The red-team events are a controlled exercise on a real network, and their labels cover only part of it ([3.3](#33-lanl-cyber1)). |
| [README.md](../README.md) lines 217 and 227 | LANL is "Real, anonymised", with "58 days of real logins"; "Detection on real attacks" | LANL is mixed: real observed background activity with one controlled red-team exercise. Say "authentication events" and "a controlled red-team exercise", not "logins" and "real attacks". Line 227 also describes a LANL evaluation that does not exist yet. |
| research.md line 313 | "Alerts we write onto ADSynth machines" | The sample network is hand-written; no ADSynth data is in the repository. |
| research.md line 348; [schema.md](schema.md) lines 89-91 | ADSynth's AI agents use `HAS_TOOL_ACCESS` to key vaults, VMs and apps | They were added in March 2026 and are not in the reviewed paper. They exist only in `generate_hybrid_v2`. `DELEGATES_TO` starts from a cloud (Entra) user, and in that mode `HAS_TOOL_ACCESS` points at the tenant node. |
| research.md line 29 | attackers get in "often through a phishing email" | M-Trends 2026 puts email phishing at 6% of 2025 intrusions, behind exploits (32%) |
| [schema.md](schema.md) lines 7, 81, 85, 142, 196 | ADSynth output loads "as-is" with `critical` copied from `highvalue` | No such loader exists. The loader rejects ADSynth's labels and most edge types, and `highvalue` is a poor rule for critical ([3.2](#32-adsynth)). |
| schema.md line 43 | analysis refreshes every 5 minutes | There is no timer. It runs when seeding, on replay reset, and in the next re-score after a network change (from `/api/live` or the stand-alone reader). |
| schema.md line 48 | `choke_score` is "How many attack paths pass through this node" | It is betweenness over all pairs of nodes, scaled to the highest value |
| schema.md line 78 | `HasSession` is a granted edge | It is an observation (in ADSynth, a random guess) |
| schema.md lines 79, 162 | `Contains` is "not used for attack paths" | BloodHound treats `Contains` as an attack step, and ADSynth puts most rights on OUs |
| schema.md lines 107-109 | logon edges carry `logon_type` and `auth_type`, and `ConnectedTo` carries port, protocol and bytes | The code never writes logon or auth types or bytes. Port and protocol exist only where `network.json` supplies them, and the stream drops port and bytes. |
| schema.md line 149 | path search uses the cost `-log(p)` | Every path search is unweighted today |
| schema.md line 175 | T1078 belongs to TA0004 | ATT&CK lists four tactics for T1078, and `alerts.json` uses TA0001. Call it a modelling choice. |
| schema.md lines 187-192 | a LANL `RemoteLogon` whenever the computers differ; red-team labels on edges; `$` accounts flagged as service accounts | Only LogOn lines should make edges. Labels must be per event, in a separate file. `$` accounts are computer accounts, and nothing reads `is_service_account` today. |
| [glossary.md](glossary.md) lines 53-54 | critical assets are "called Tier Zero in BloodHound" | Tier Zero means control of identity (Domain Admins, domain controllers). BloodHound puts business systems such as a customer database in separate "privilege zones" (an Enterprise feature). Also add "benign positive". |
| [README.md](../README.md) line 41 and the landing page | GraphOps "flags a user reaching a system through a path they have never used" | The never-taken question adds points to an alert that already exists. It looks at machine pairs, not users. |
| README.md lines 36 and 176; PROJECT_SPEC R5 ("ordered by MITRE ATT&CK tactic"); [Landing.jsx](../frontend/src/Landing.jsx) lines 13 and 25 | incidents are "ordered by MITRE ATT&CK stage" | The incident lists alerts by time, with a tactic tag |
| README.md line 116; [streaming.md](streaming.md) line 73 | the stream "looks like a real network" | It never creates a route or a remote logon |
| README.md line 128; streaming.md line 66 | events are written with `MERGE` | The code looks events up and then uses `CREATE` under a uniqueness constraint |
| README.md line 229; streaming.md line 167 | speed is measured at 1x, 10x and 100x; the test runs "at 60x" | The test sends one alert directly, with no replay speed |
| README.md lines 226, 228, 231 and 232 | the "How we test it" table presents known-answer graphs, a checked attack path, refused write queries, a ranking-model comparison and a people test as things we do | Only part of this exists. The known-answer tests use the sample graph, not small graphs, and nothing checks the attack path or the choke scores directly. There is no question box, ranking model or people-test material yet ([2.1](#21-what-is-tested-today)). Mark these rows as planned. |
| streaming.md line 146 | scoring re-runs "for the alerts of that day" | `score_all` re-scores every alert in the database |
| streaming.md line 46 | Aiven allows "250 kb/s" | [Aiven's free-tier documentation](https://aiven.io/docs/products/kafka/free-tier/kafka-free-tier) says 250 KiB/s |
| [pitch.md](pitch.md) lines 49-52 | "one backward search"; the blast radius "visits each node once"; heavy jobs "on a timer" | The code runs a shortest-path search per pair, lists every path, and has no timer |
| [Tour.jsx](../frontend/src/Tour.jsx) line 15 | "Somewhere in here is a real attack" | It is a scripted, synthetic attack |
| [backend/requirements.txt](../backend/requirements.txt) | `fastapi>=0.115` | `app.frontend()` needs FastAPI 0.138 or newer; `pyproject.toml` already says 0.143 |
| README.md line 237 | "Node.js 20 or newer" | Vite 8.3 needs Node 20.19 or newer (but not 21 or 22.0-22.11), and Vitest with jsdom 30 would need Node 22.22.2 or newer on 22, 24.15 or newer on 24, or 26 or newer (not 23 or 25) |
| [hosting.md](hosting.md) line 61 | AuraDB Free "pauses after a period without use" | Neo4j's FAQ says free databases without activity for 30 days are deleted, so a hosted evaluation set could be lost |
| [scoring.py](../backend/app/scoring.py) line 10 | the weights are "documented in docs/schema.md" | schema.md has no ranking weights, only the unused edge-risk values |

### Sources for section 5

- Repository files as linked; other evidence as cited in sections 1 to 3.
- Aiven [Kafka free tier](https://aiven.io/docs/products/kafka/free-tier/kafka-free-tier). BloodHound [privilege zones](https://github.com/SpecterOps/bloodhound-docs/blob/main/docs/analyze-data/privilege-zones/overview.mdx). FastAPI [release notes](https://fastapi.tiangolo.com/release-notes/) (0.138.0 adds `app.frontend()`). Vite's Node requirement in its [npm metadata](https://registry.npmjs.org/vite). Neo4j [AuraDB FAQ](https://neo4j.com/cloud/platform/aura-graph-database/faq/).

---

## 6. What we could not verify

- **Kent's 2016 chapter describing LANL Cyber1** was behind a paywall. Its warning that the red-team labels are a subset is known only through Larroche's 2026 paper.
- **Gaps in the LANL release itself:**
  - the complete list of values in the authentication file;
  - whether the files are sorted by time;
  - whether day boundaries match local midnight;
  - one catalogue's unconfirmed claim that flows exist only for the first 29 days.
- **The ADSynth DSN 2024 paper itself** was behind a paywall. Its figures come from the thesis, which says it extends the paper.
- **AuraDB Free's exact limits.** Neo4j's limits page says 200,000 nodes and 400,000 relationships; its free-database page says 50,000 and 175,000.
- **Whether ADSynth runs as its code suggests**, and whether BloodHound CE accepts its zip. ADSynth was read, not run.
- **GUIDE details:** the size of its timestamp noise, which correlation engine formed its incidents, and the full lists of its entity types and evidence roles. The files were not downloaded.
- **The real behaviour behind our predictions:**
  - GraphOps' exact scores (the re-implementations match the test answers, but GraphOps itself was not run);
  - the predicted streaming failures;
  - the predicted axe findings and Schemathesis reports.
- **Whether the existing tests pass today.** By instruction, no tests were run.
- **AuraDB Free behaviour:** whether it pauses after three days without activity, as Neo4j's free-database page says (that page's size limits disagree with the limits page), and whether it lacks Graph Data Science, as the README says.
- **A per-day rate of normal first-time routes**, measured the way GraphOps defines a route. No published source gives one.
- **Statistics with no public source:**
  - typical alert volumes for a medium-sized Indian company;
  - joiner and leaver rates;
  - group nesting depth;
  - helpdesk frequency.

  These stay as assumptions.
- **Whether "ANUBIS '26" is a workshop at ESORICS 2026**, as [research.md](research.md) says. arXiv shows only "Accepted at ANUBIS '26".
