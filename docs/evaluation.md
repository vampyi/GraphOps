# Evaluation on held-out scenarios

Does GraphOps rank a real attack above the noise better than sorting alerts by the tools' own severity? We test this on labelled days the ranking weights were never tuned on.

Run it with `python -m app.evaluate_all` in `backend`. **It replaces everything in the database it points at**, so use a local or test database, never the hosted one. `backend/tests/test_no_gds.py` runs it on every push.

## The days

All days use the same sample network. The weights in `backend/app/scoring.py` were set by hand on the sample day and were **not changed** after writing the other scenarios. Each held-out day uses neutral alert IDs, so nothing in an ID hints at the answer.

| Day | What makes it hard |
|---|---|
| `sample` | The demo day the weights were set on. Not a fair test; shown for comparison. |
| `finance_breach` | A different attack on the finance database, with different alert names. |
| `backup_account_abuse` | The attacker uses the backup account's usual route, so no route is new and the never-taken-path question cannot help. Two admins and a developer take harmless first-time routes. |
| `missed_detections` | The sample attack with the credential-dumping and remote-logon alerts missing, as when tools miss steps. |
| `slow_burn` | The attack takes seven hours, longer than the two-hour window used to link alerts. |
| `file_server_ransomware` | The attack never goes near a critical asset, while harmless admin work happens next to the domain controller. |

## Results

Measured on 26 October 2026, with and without Neo4j Graph Data Science. Both gave the same numbers.

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

## What it does not show

- These days were written by us on our own small network of 37 users, groups and machines. They test known weaknesses; they are not real attacks. Results on real data are untested. That needs LANL Cyber1 or a lab dataset, as described on Raja's research branch (`docs/data-and-testing-research.md` on branch `raja`).
- Severity sorting is a simple baseline. Real tools also use rarity, asset value and threat intelligence.
- Five held-out days are too few for averages or confidence intervals. Read each row as a worked example.
