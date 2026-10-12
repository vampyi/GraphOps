"""incident story writer (requirement R6): an llm drafts the story, a checker drops any sentence
that cites a node outside the incident, and without llm access the facts are returned as a list."""
import json

MODEL = "claude-opus-5-5"

SCHEMA = {
    "type": "object",
    "properties": {
        "sentences": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "cites": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["text", "cites"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["sentences"],
    "additionalProperties": False,
}

PROMPT = """You are helping a security analyst understand one incident. Below are the only facts you may use:
alerts, the users and machines they involve, and the connections between them. Every item has an id.

Write the incident as a short story in time order, 3 to 6 sentences, in plain English for a beginner.
Each sentence must list in "cites" the ids of the facts it is based on. Do not state anything that is not
in the facts. If something is unknown, say it is unknown.

Facts:
{facts}"""


def incident_facts(session, incident_id):
    alerts = [dict(r) for r in session.run(
        """
        MATCH (a:Alert {incident_id: $inc})-[:Involves]->(e)
        RETURN a.id AS id, a.time AS time, a.name AS name, a.tactic_id AS tactic,
               a.technique_id AS technique, collect(e.id) AS involves
        ORDER BY a.time
        """, inc=incident_id)]
    entity_ids = sorted({e for a in alerts for e in a["involves"]})
    entities = [dict(r) for r in session.run(
        "MATCH (e) WHERE e.id IN $ids RETURN e.id AS id, labels(e)[0] AS kind, e.critical AS critical",
        ids=entity_ids)]
    edges = [dict(r) for r in session.run(
        """
        MATCH (s)-[r]->(d) WHERE s.id IN $ids AND d.id IN $ids AND NOT type(r) IN ['Involves', 'PartOf']
        RETURN s.id + '-' + type(r) + '-' + d.id AS id, s.id AS src, type(r) AS type, d.id AS dst,
               r.user AS user, r.first_seen AS first_seen, r.last_seen AS last_seen
        """, ids=entity_ids)]
    return {"alerts": alerts, "entities": entities, "connections": edges}


def allowed_ids(facts):
    return ({a["id"] for a in facts["alerts"]} | {e["id"] for e in facts["entities"]}
            | {c["id"] for c in facts["connections"]})


def check_citations(sentences, allowed):
    """keep a sentence only if it cites at least one id and every cited id is in the incident."""
    kept, dropped = [], []
    for s in sentences:
        cites = s.get("cites") or []
        (kept if cites and all(c in allowed for c in cites) else dropped).append(s)
    return kept, dropped


def fact_list(facts):
    return [{"text": f"{a['time'][11:16]}: {a['name']} on {', '.join(a['involves'])}", "cites": [a["id"]]}
            for a in facts["alerts"]]


def ask_llm(facts):
    import anthropic
    client = anthropic.Anthropic()  # uses the `ant auth login` profile, no key in the code
    response = client.beta.messages.create(
        model=MODEL,
        max_tokens=4000,
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        output_config={"effort": "medium", "format": {"type": "json_schema", "schema": SCHEMA}},
        messages=[{"role": "user", "content": PROMPT.format(facts=json.dumps(facts, indent=2))}],
    )
    if response.stop_reason == "refusal":
        raise RuntimeError("the model declined this request")
    text = next(b.text for b in response.content if b.type == "text")
    return json.loads(text)["sentences"]


def write_story(session, incident_id, llm=ask_llm):
    facts = incident_facts(session, incident_id)
    if not facts["alerts"]:
        return None
    try:
        sentences = llm(facts)
        source = "llm"
    except Exception as exc:  # no login, network error or refusal: fall back to the plain fact list
        return {"source": "facts", "reason": str(exc)[:200], "sentences": fact_list(facts), "dropped": []}
    kept, dropped = check_citations(sentences, allowed_ids(facts))
    return {"source": source, "status": "needs analyst approval", "sentences": kept, "dropped": dropped}
