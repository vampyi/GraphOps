# Getting real data in

GraphOps reads one event schema, through three doors, plus a fourth for live real sources. All three end at the same `events.apply_batch`, so every
door is idempotent (an event with an id it has seen changes nothing) and tested once.

1. **Kafka** — the streaming path, five topics (`identity`, `edr`, `flows`, `alerts`, `cmdb`). See
   [streaming.md](streaming.md). This is how a tool would feed GraphOps continuously in production.
2. **HTTP webhook** — `POST /api/ingest` for events already in the schema, and `POST /api/ingest/alerts` for
   alert payloads shaped like a named SIEM or EDR product. Good for a SOAR playbook or a quick integration.
3. **File import** — a BloodHound / SharpHound collection for the permission graph.
4. **Real sources** — `POST /api/sources/{id}/inventory` and `/events`, protected by the `INGEST_TOKEN` header. Team laptops report through osquery ([collectors/osquery](../collectors/osquery/README.md)) and a Claude Code agent reports its access and actions ([collectors/claude_code](../collectors/claude_code/README.md)). These are kept apart from the labelled days and survive every reload.

The alert payloads used to test the SIEM and EDR maps are written by us. The field maps below are written from each
product's public documentation and from sample payloads we wrote. They are starting points to check against a
real tenant, not certified connectors.

## The event schema

Every event is one JSON object sharing these fields:

| Field | Meaning |
|---|---|
| `event_id` | Unique id. An event seen twice changes nothing. |
| `time` | ISO 8601, when it happened. |
| `source_tool` | The tool that produced it. |
| `kind` | `LoggedInto`, `RemoteLogon`, `MemberOf`, `ProcessStart`, `Connection`, `Alert` or `Asset`. |

The full per-kind fields are in [streaming.md](streaming.md). An `Alert` event carries `id`, `name`,
`severity`, optional `tactic_id` and `technique_id`, and `involves` (the ids of the users and machines it is
about). It may also carry `entities`, a list of `{id, label}` hints; a host or account named there that is not
in the graph yet is created, so the picture grows from telemetry.

## Webhook: events already in the schema

```bash
curl -X POST localhost:8000/api/ingest -H 'content-type: application/json' -d '{
  "events": [{
    "event_id": "ext-001", "time": "2026-10-20T11:00:00", "source_tool": "EDR", "kind": "Alert",
    "id": "ext-001", "name": "Beacon to known-bad IP", "severity": "high",
    "tactic_id": "TA0011", "technique_id": "T1105",
    "involves": ["laptop-9"], "entities": [{"id": "laptop-9", "label": "Computer"}]
  }]
}'
```

The reply says how many events were written, how many were duplicates, how many were rejected, and which alerts
re-scored. The alert is scored on the next read of `/api/alerts` or `/api/live`.

## Webhook: alerts from a SIEM or EDR

`POST /api/ingest/alerts?format=<name>` maps a vendor payload into an alert event. Supported `format` values:
`sentinel`, `splunk`, `elastic`, `wazuh`, and `graphops` (already our shape).

```bash
curl -X POST 'localhost:8000/api/ingest/alerts?format=sentinel' -H 'content-type: application/json' -d '{
  "alerts": [{
    "SystemAlertId": "sx-1", "AlertName": "Suspicious PowerShell", "AlertSeverity": "High",
    "TimeGenerated": "2026-10-20T10:45:00", "Tactics": ["TA0002"], "Techniques": ["T1059"],
    "Entities": [{"Type": "host", "HostName": "LAPTOP-F1"}, {"Type": "account", "Name": "fin_1"}]
  }]
}'
```

What each map reads (host and account names are normalised: a host loses its DNS domain, an account loses its
`DOMAIN\` or `@domain` part, both lower-cased):

| Format | Name | Severity | Time | Technique | Host / account |
|---|---|---|---|---|---|
| `sentinel` | `AlertName` | `AlertSeverity` | `TimeGenerated` | `Techniques[0]`, `Tactics[0]` | `Entities[]` with `Type` host/account |
| `splunk` | `rule_name` / `search_name` | `urgency` (number) or `severity` | `info_max_time` / `_time` | `annotations.mitre_attack[0]` | `dest`, `src`, `user` |
| `elastic` | `kibana.alert.rule.name` | `kibana.alert.severity` | `@timestamp` | `kibana.alert.rule.threat[].technique/tactic` | `host.name`, `user.name` |
| `wazuh` | `rule.description` | `rule.level` (0-15) | `timestamp` | `rule.mitre.id[0]`, `rule.mitre.tactic[0]` | `agent.name`, `data.srcuser` |

An alert with no name, or naming no host or account, is rejected with a message rather than loaded.

## File import: BloodHound / SharpHound

```bash
python -m app.import_bloodhound <dir-or-zip>
```

Reads the BloodHound Community Edition JSON shape (one file per object type, each `{"data": [...], "meta":
{"type": ...}}`) and loads users, groups and computers with the relationships that make attack paths: group
membership, local admin rights, remote-desktop rights, sessions and `GenericAll`. Objects are keyed by SID
inside the file and given a readable id (the name) in the graph, with the SID kept as a property. High-value
objects and well-known Tier Zero groups (Domain Admins, Enterprise Admins, Domain Controllers and the like) are
marked critical.

This is a pragmatic subset, not a full BloodHound loader; it takes the edges GraphOps reasons over and leaves
the rest. After import, run the analysis (`python -m app.analysis` is folded into seeding; the importer's
`__main__` runs it for you) so distances, choke points and communities are computed.
