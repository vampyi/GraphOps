"""the ask tab: plain-language questions answered only from graphops' own read-only lookups.

1. the llm sees the question and a fixed list of tools (top alerts, one alert, blast radius, an incident,
   attack paths, the access gap, the evaluation, entity search). it can call them for up to MAX_ROUNDS rounds.
   tools only read; there is no tool that writes and no free-form database query.
2. it then writes the answer as sentences, each citing the ids it is based on.
3. a checker drops any sentence that cites an id the tools did not return, like the incident story.
the answer can be translated into indian languages with sarvam's translation api."""
import json

from . import llm

MAX_ROUNDS = 4
MAX_QUESTION = 500
MAX_HISTORY = 6
MAX_TOOL_CHARS = 6000

TOOLS = [
    ("top_alerts", "The highest-ranked alerts today, highest score first, with their reasons. Use for 'what should I look at first'.",
     {"limit": {"type": "integer", "description": "how many, 1 to 15"},
      "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"], "description": "only this severity"}}, []),
    ("alert_details", "One alert: its score, the points each ranking question added, its reasons, rank by GraphOps and by severity, and its incident.",
     {"alert_id": {"type": "string"}}, ["alert_id"]),
    ("blast_radius", "What an attacker could reach in 1, 2 and 3 steps from an alert's machines and accounts, or from one user, group or machine, plus the shortest path to a critical asset.",
     {"alert_id": {"type": "string", "description": "an alert id, or leave empty and give entity_id"},
      "entity_id": {"type": "string", "description": "a user, group or machine id"}}, []),
    ("incident", "One incident: its linked alerts in time order with attack stages, status, and whether it spans activity groups.",
     {"incident_id": {"type": "string"}}, ["incident_id"]),
    ("attack_paths", "Attack paths from low-trust machines to critical assets that exist before any attack, the choke points they share, and the fixes that cut the most paths.", {}, []),
    ("access_gap", "Access held but not used in the last 30 days: for one identity if entity_id is given, otherwise every account ranked by unused access.",
     {"entity_id": {"type": "string"}}, []),
    ("ranking_quality", "How well GraphOps ranked the loaded day's attack compared with sorting by severity.", {}, []),
    ("find_entities", "Find users, groups and machines whose id or name contains some text. Use it to turn a name like 'raja' or 'finance laptop' into ids.",
     {"text": {"type": "string"}}, ["text"]),
]

SYSTEM = """You are GraphOps' assistant for security analysts who may be new to security.
Answer ONLY from the results of the tools. Never invent alerts, users, machines, numbers or ids.
If the tools do not answer the question, say so plainly.
Call tools to gather facts first. Use find_entities when the question names a person or machine loosely."""

ANSWER_PROMPT = """Now answer the analyst's question using only the tool results above.
Write 1 to 6 short sentences in plain English for a beginner. Every sentence must list in "cites" the ids
(alert ids like a-03, incident ids, or user/machine/group ids) from the tool results that it is based on.
If the tool results do not answer the question, write one sentence saying so, citing nothing."""

ANSWER_SCHEMA = {
    "type": "object",
    "properties": {"sentences": {"type": "array", "items": {
        "type": "object",
        "properties": {"text": {"type": "string"}, "cites": {"type": "array", "items": {"type": "string"}}},
        "required": ["text", "cites"], "additionalProperties": False}}},
    "required": ["sentences"], "additionalProperties": False,
}


def tool_specs():
    return [{"type": "function", "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object", "properties": props, "required": req}}} for name, desc, props, req in TOOLS]


def ids_in(value, out=None):
    """every string in a tool result. citations must be one of these."""
    out = set() if out is None else out
    if isinstance(value, dict):
        for v in value.values():
            ids_in(v, out)
    elif isinstance(value, list):
        for v in value:
            ids_in(v, out)
    elif isinstance(value, str) and len(value) <= 80:
        out.add(value)
    return out


def check(sentences, allowed):
    """keep sentences whose citations all came from the tools. a sentence with no citations is kept only when
    it is the whole answer, the "the tools do not answer this" case; otherwise an uncited sentence is dropped."""
    kept, dropped = [], []
    lone = len(sentences) == 1
    for s in sentences:
        cites = s.get("cites") or []
        ok = all(c in allowed for c in cites) if cites else lone
        (kept if ok else dropped).append(s)
    return kept, dropped


def answer(question, tools_impl, history=(), lang="en-IN", chat=None):
    """run the tool loop and return {sentences, dropped, tools_used, language}."""
    chat = chat or llm.chat
    question = (question or "").strip()[:MAX_QUESTION]
    if not question:
        raise ValueError("ask a question")
    messages = [{"role": "system", "content": SYSTEM}]
    for turn in list(history)[-MAX_HISTORY:]:
        if turn.get("role") in ("user", "assistant") and isinstance(turn.get("content"), str):
            messages.append({"role": turn["role"], "content": turn["content"][:1000]})
    messages.append({"role": "user", "content": question})

    used, allowed = [], set()
    for _ in range(MAX_ROUNDS):
        reply = chat(messages, tools=tool_specs())
        calls = reply.get("tool_calls") or []
        if not calls:
            break
        messages.append({"role": "assistant", "content": reply.get("content") or "", "tool_calls": calls})
        for call in calls:
            name = call["function"]["name"]
            try:
                args = json.loads(call["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            if name in tools_impl:
                try:
                    result = tools_impl[name](**{k: v for k, v in args.items() if v not in (None, "")})
                except Exception as exc:  # a bad id or argument: tell the model, keep going
                    result = {"error": str(exc)[:200]}
            else:
                result = {"error": f"unknown tool {name}"}
            used.append({"tool": name, "args": args})
            allowed |= ids_in(result)
            messages.append({"role": "tool", "tool_call_id": call.get("id"), "content": json.dumps(result, default=str)[:MAX_TOOL_CHARS]})

    messages.append({"role": "user", "content": ANSWER_PROMPT})
    # sarvam requires the tool list whenever tool messages are present, so send it but forbid more calls
    final = chat(messages, tools=tool_specs(), schema=ANSWER_SCHEMA, tool_choice="none")
    sentences = llm.parse_json(final.get("content"))["sentences"]
    kept, dropped = check(sentences, allowed)
    result = {"sentences": kept, "dropped": dropped, "tools_used": used, "language": "en-IN"}
    if lang and lang != "en-IN" and kept:
        try:
            result["sentences"] = [{**s, "text": llm.translate_keeping(s["text"], allowed, lang), "text_en": s["text"]} for s in kept]
            result["language"] = lang
        except Exception as exc:
            result["translation_error"] = str(exc)[:200]
    return result
