# Analyst guide

GraphOps for the person on shift. The console has three views, switched from the top bar. Everything runs on
the synthetic sample organisation; the console says so.

## Triage: what needs me now

The default view. Every alert of the day, ranked by where it sits on the attacker's map, nothing hidden.

- **Inbox.** Highest score first. The number is the GraphOps score; the thin bar under each alert shows which
  of the ranking questions earned it. Switch to **Severity only** to see the order most tools use: on the
  sample day the attack sinks to the middle, which is the point.
- **Blast radius.** Click an alert to draw what an attacker on its machine or account could reach in 1, 2 and 3
  hops. The red dashed line is the shortest attack path to a critical asset. Three modes:
  - **All attack edges** — every route an attacker could follow.
  - **Granted** — only the permissions the identity holds.
  - **Used** — only the logons actually seen in the last 30 days.
  The gap between *granted* and *used* is the access least privilege would remove.
- **Mark an asset critical.** Click any machine in the graph and use the button in its details. GraphOps
  re-runs distances, choke points and every alert score at once, so the inbox reflects the new crown jewel.
- **Why it ranks here.** The six graph questions and the points each added, for the selected alert.
- **Incident.** Alerts GraphOps linked into one attack, listed by time and tagged with their ATT&CK stage. Set the incident's **status**
  (open, investigating, contained, closed) and it sticks, even as new alerts arrive. **Draft story (AI)** writes
  a plain-English account where every sentence must cite a real node, or shows the facts when AI is off.
  **Incident report** opens a containment-ready write-up you can copy into a ticket or a CERT-In notice.
- **Verdict.** Mark each alert **Real attack**, **Benign** or **False alarm**. *Benign* records real but allowed
  activity, so it is not counted as a miss. Verdicts are saved with who set them and when.

## Live: watch it happen

**Stream live** in the top bar replays the selected scenario's telemetry through Kafka as if it were happening
now. Alerts arrive one by one and the inbox re-ranks as they land. **Stop** returns to the full scenario.

## Exposure: fix it before it is used

The attack paths that exist in the network today, before any alert.

- **The number** is how many low-trust-machine to critical-asset pairs an attacker could reach, of all possible.
- **The map** draws those paths left to right: low-trust machines on the left, critical assets on the right,
  every step tagged with its MITRE ATT&CK technique, so a path reads as a kill chain.
- **Fix the choke points.** Each suggested fix shows the share of paths it actually cuts, recomputed on the
  graph with the fix applied, never estimated. Click one to see the cut edges struck out on the map. The first
  fix is usually the minimum cut: the fewest permissions or sessions whose removal severs every path.
- **Scope.** Switch between *from low-trust machines* and *from any machine or account* ("if anything at all
  were compromised").

## Access: the least-privilege gap

Every account, ranked by the access it holds but has not used in the chosen window (7, 30 or 90 days).

- **The shrinking circle.** The outer ring is everything the identity is granted; the solid disc is what it
  actually uses. The gap is unused access: risk with no benefit, and the first thing to remove.
- **Granted vs used columns.** Side by side, with unused grants highlighted and critical ones flagged.
- **Used without a grant.** Routes the logs show that no modelled permission explains. On real data this points
  at a default right not yet imported, such as a user signing in to their own laptop.

## A good first five minutes

1. Open **Triage**, read the top of the inbox. The top incident is the attack.
2. Click it, read the blast radius and the shortest path to the critical asset.
3. Open the **Incident report**, confirm it names the whole chain, copy it into the ticket.
4. Switch to **Exposure**, apply the top fix, note the share of paths it cuts.
5. Switch to **Access**, open the most over-privileged account, remove the unused critical grants.
