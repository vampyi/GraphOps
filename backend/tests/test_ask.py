"""the ask tab: the tool loop with a scripted fake llm, every read-only lookup on the seeded sample, and the
citation check. no real llm is called."""
import json

import pytest

from app import ask


def scripted(*replies):
    """a fake chat function that returns the given replies in order and records what it was sent."""
    sent, queue = [], list(replies)

    def chat(messages, tools=None, schema=None, **kw):
        sent.append({"messages": [dict(m) for m in messages], "tools": tools, "schema": schema})
        return queue.pop(0)
    chat.sent = sent
    return chat


def tool_call(name, **args):
    return {"role": "assistant", "content": None,
            "tool_calls": [{"id": f"call-{name}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}


def final(*sentences):
    return {"role": "assistant", "content": json.dumps({"sentences": [{"text": t, "cites": c} for t, c in sentences]})}


@pytest.fixture()
def tools(api):
    from app import main
    return main._ask_tools()


def test_every_lookup_works_on_the_sample(tools):
    assert tools["top_alerts"](limit=3)[0]["id"] == "a-03"
    assert tools["alert_details"](alert_id="a-03")["rank_graphops"] == 1
    reach = tools["blast_radius"](alert_id="a-03")
    assert "customer-db" in reach["critical_reachable"]
    assert tools["blast_radius"](entity_id="laptop-42")["shortest_path_to_critical"]["nodes"][0] == "laptop-42"
    assert len(tools["incident"](tools["alert_details"](alert_id="a-03")["incident_id"])["alerts"]) >= 4
    assert tools["attack_paths"]()["pairs"]["reachable"] > 0
    assert tools["access_gap"](entity_id="it_admin")["summary"]["granted"] > 0
    assert tools["ranking_quality"]()["graphops"]["last_attack_rank"] <= 5
    assert any(e["id"] == "laptop-42" for e in tools["find_entities"](text="laptop-4"))


def test_tool_loop_answers_from_lookups_and_drops_invented_ids(tools):
    chat = scripted(
        tool_call("top_alerts", limit=3),
        {"role": "assistant", "content": "done"},
        final(("The top alert is a remote logon on server-7.", ["a-03", "server-7"]),
              ("It also hit the payroll server.", ["payroll-99"]),
              ("Everything is fine.", [])))
    out = ask.answer("what should I look at first?", tools, chat=chat)
    assert [s["cites"] for s in out["sentences"]] == [["a-03", "server-7"]]
    assert {tuple(s["cites"]) for s in out["dropped"]} == {("payroll-99",), ()}
    assert out["tools_used"] == [{"tool": "top_alerts", "args": {"limit": 3}}]
    tool_msg = [m for m in chat.sent[-1]["messages"] if m["role"] == "tool"][0]
    assert tool_msg["tool_call_id"] == "call-top_alerts" and "a-03" in tool_msg["content"]
    assert chat.sent[-1]["schema"] is ask.ANSWER_SCHEMA and chat.sent[-1]["tools"] is None


def test_a_bad_id_is_reported_to_the_model_not_raised(tools):
    chat = scripted(tool_call("alert_details", alert_id="nope"), {"role": "assistant", "content": ""},
                    final(("I could not find that alert.", [])))
    out = ask.answer("explain alert nope", tools, chat=chat)
    tool_msg = [m for m in chat.sent[-1]["messages"] if m["role"] == "tool"][0]
    assert "error" in tool_msg["content"]
    assert out["sentences"][0]["text"] == "I could not find that alert."


def test_there_is_no_tool_that_writes():
    names = {t["function"]["name"] for t in ask.tool_specs()}
    assert names == {"top_alerts", "alert_details", "blast_radius", "incident", "attack_paths", "access_gap",
                     "ranking_quality", "find_entities"}


def test_empty_question_is_refused(tools):
    with pytest.raises(ValueError):
        ask.answer("   ", tools, chat=scripted())


def test_endpoint_explains_when_no_key(api, monkeypatch):
    monkeypatch.delenv("SARVAM_API_KEY", raising=False)
    r = api.post("/api/ask", json={"question": "what is first?"})
    assert r.status_code == 503 and "SARVAM_API_KEY" in r.json()["detail"]
