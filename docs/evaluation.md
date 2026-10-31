# Evaluation on held-out scenarios

Does GraphOps rank a real attack above the noise better than sorting alerts by the tools' own severity? We test this on labelled days the ranking weights were never tuned on: one real lab recording of the APT29 attack and six days we wrote ourselves.

The latest numbers for every day are in [data/proof.json](../data/proof.json). The Proof table at the bottom of the Graph tab reads that file.

Run it with `python -m app.evaluate_all` in `backend`. **It replaces everything in the database it points at**, so use a local or test database, never the hosted one. `backend/tests/test_no_gds.py` runs it on every push.

## The real day: APT29 lab recording

MITRE's APT29 emulation (day 1), recorded on four lab machines by the Open Threat Research Forge (OTRF Security Datasets, MIT licence). The alerts come from the public SigmaHQ detection rules (release `r2026-07-01`, Detection Rule License 1.1), not from rules we wrote. The attack or noise label on each alert is ours, taken from the published emulation plan. How the day is built: [data-sources.md](data-sources.md#apt29-day-1-with-sigma-rules).

Measured on 31 October 2026 on a local database:

| | GraphOps | Severity |
|---|---|---|
| Average precision | 0.93 | 0.87 |
| Precision@5 | 1.0 | 1.0 |
| Rank of the first attack alert | 1 | 1 |
| Rank of the last attack alert (of 73) | 71 | 69 |

The 55 attack alerts land in 1 incident, which also pulls in 9 of the 18 noise alerts.

What this shows:
- On a real recorded attack, GraphOps ranked the attack alerts slightly better than severity overall, and both put an attack alert first.
- It is a small win, not the large gap seen on our own days. The lab has one user and four machines, so most alerts sit close to the domain controller and the graph questions separate them less.
- An earlier build of the same day with a dozen rules we wrote ourselves (`apt29_day1`, kept only as a test day) went the other way: severity did better on average precision. That result is in [data/proof.json](../data/proof.json) too. We report both.

## Every day at a glance

Average precision is one number for "how high the attack alerts sit above the noise": 1.0 means every attack alert came before every false alarm. From [data/proof.json](../data/proof.json), measured on 31 October 2026:

| Day | Kind | Alerts (attack) | Average precision: GraphOps / severity |
|---|---|---|---|
| `apt29_day1_sigma` | real lab logs, public Sigma rules | 73 (55) | **0.93** / 0.87 |
| `sample` | synthetic, the demo day | 30 (4) | **1.0** / 0.12 |
| `apt29_day1` | real lab logs, our own rules | 38 (16) | 0.71 / **0.87** |
| `backup_account_abuse` | synthetic | 16 (4) | **1.0** / 0.20 |
| `file_server_ransomware` | synthetic | 16 (3) | **0.41** / 0.19 |
| `finance_breach` | synthetic | 17 (5) | **1.0** / 0.26 |
| `missed_detections` | synthetic | 13 (3) | **1.0** / 0.20 |
| `slow_burn` | synthetic | 14 (4) | **0.89** / 0.25 |

GraphOps ranked the attack above the noise better than severity on 7 of 8 days. It lost on our own-rules build of the APT29 day.

## The days we wrote

All of these days use the same sample network. The weights in `backend/app/scoring.py` were set by hand on the sample day and were **not changed** after writing the other scenarios. Each held-out day uses neutral alert IDs, so nothing in an ID hints at the answer.

| Day | What makes it hard |
|---|---|
| `sample` | The demo day the weights were set on. Not a fair test; shown for comparison. |
| `finance_breach` | A different attack on the finance database, with different alert names. |
| `backup_account_abuse` | The attacker uses the backup account's usual route, so no route is new and the never-taken-path question cannot help. Two admins and a developer take harmless first-time routes. |
| `missed_detections` | The sample attack with the credential-dumping and remote-logon alerts missing, as when tools miss steps. |
| `slow_burn` | The attack takes seven hours, longer than the two-hour window used to link alerts. |
| `file_server_ransomware` | The attack never goes near a critical asset, while harmless admin work happens next to the domain controller. |

## Results

First measured on 26 October 2026, with and without Neo4j Graph Data Science (both gave the same numbers), and unchanged when re-measured on 31 October.

| Day | Alerts | Attack alerts | Last attack alert's rank: GraphOps / severity | False alarms read before the first attack alert: GraphOps / severity | Precision@5: GraphOps / severity | Incidents the attack is split into | Noise alerts pulled into the attack's incidents |
|---|---|---|---|---|---|---|---|
| sample | 30 | 4 | 4 / 27 | 0 / 15 | 0.8 / 0.0 | 1 | 0 |
| finance_breach | 17 | 5 | 5 / 15 | 0 / 7 | 1.0 / 0.0 | 1 | 0 |
| backup_account_abuse | 16 | 4 | 4 / 15 | 0 / 9 | 0.8 / 0.0 | 1 | 0 |
| missed_detections | 13 | 3 | 3 / 12 | 0 / 6 | 0.6 / 0.0 | 2 | 0 |
| slow_burn | 14 | 4 | 5 / 14 | 0 / 6 | 0.8 / 0.0 | 4 | 1 |
| file_server_ransomware | 16 | 3 | 6 / 15 | 2 / 5 | 0.4 / 0.0 | 1 | 0 |

Severity order breaks ties by time, oldest first. Precision@5 cannot exceed the number of attack alerts divided by 5, so 0.6 is the best possible on a day with three attack alerts.

## What it shows

- On every day, GraphOps put the attack alerts higher than severity sorting did. Severity sorting never put an attack alert in its top 5.
- **The ransomware day is the weakest.** The attack never nears a critical asset, so most graph questions add nothing. Two harmless alerts on the domain controller ranked above it. This is the expected limit of ranking by closeness to critical assets.
- **Grouping breaks when steps go missing or the attack is slow.** With two alerts missing, the attack splits into 2 incidents. Over seven hours it splits into 4 and pulls in one noise alert. The ranking still puts the attack near the top, but the analyst would see it as separate incidents.

## Learning the weights from labels

GraphOps can learn how much each ranking question should count from analyst verdicts, with a small logistic regression written in plain Python (`backend/app/learn.py`). The learned weights can be compared with the hand-set ones (`GET /api/learning`) once there are at least 8 verdicts, 3 of each kind. They are not switched on automatically.

To test it, we used each day's attack labels in place of verdicts: learn from five days, rank the sixth, and repeat for every day (`python -m app.evaluate_all --learn`). Measured on 26 October 2026:

| Held-out day | Last attack rank: hand-set / learned | False alarms before first attack: hand-set / learned | Average precision: hand-set / learned |
|---|---|---|---|
| sample | 4 / 4 | 0 / 0 | 1.0 / 1.0 |
| backup_account_abuse | 4 / 5 | 0 / 0 | 1.0 / 0.887 |
| file_server_ransomware | 6 / 6 | 2 / 3 | 0.411 / 0.383 |
| finance_breach | 5 / 5 | 0 / 0 | 1.0 / 1.0 |
| missed_detections | 3 / 3 | 0 / 0 | 1.0 / 1.0 |
| slow_burn | 5 / 5 | 0 / 0 | 0.887 / 0.804 |

The learned weights were no better: equal on three days and slightly worse on three. With about 100 labelled alerts from days we wrote ourselves, that is expected. Every learned version gave the tool's own severity a weight of zero, meaning severity did not separate the attacks from the noise on these days. The learned model therefore stays off until real analyst verdicts exist.

## What it does not show

- Six of the seven days were written by us on our own small network of 37 users, groups and machines. They test known weaknesses; they are not real attacks.
- The one real day is a lab: one user, four machines and 33 minutes. It is real attacker behaviour recorded by real tools, but not a company's normal day. A supervised pilot on a real SOC's alerts is the next step.
- Severity sorting is a simple baseline. Real tools also use rarity, asset value and threat intelligence.
- Five held-out days are too few for averages or confidence intervals. Read each row as a worked example.
