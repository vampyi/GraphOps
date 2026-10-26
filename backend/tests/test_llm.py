"""the sarvam client and the story's sarvam path, against a fake sarvam server. no real key or network."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app import llm
from app.story import write_story


class FakeSarvam:
    """records each request and answers with whatever the test queued for that path."""
    def __init__(self):
        self.requests, self.replies = [], {}
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
                status, reply = fake.replies[self.path].pop(0) if isinstance(fake.replies[self.path], list) else fake.replies[self.path]
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(reply).encode())

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"


@pytest.fixture()
def fake(monkeypatch):
    f = FakeSarvam()
    monkeypatch.setattr(llm, "BASE", f.url)
    monkeypatch.setenv("SARVAM_API_KEY", "test-key")
    yield f
    f.server.shutdown()


def chat_reply(content):
    return 200, {"choices": [{"message": {"role": "assistant", "content": content}}]}


def test_chat_sends_key_model_and_explicit_settings(fake):
    fake.replies["/v1/chat/completions"] = chat_reply("hello")
    msg = llm.chat([{"role": "user", "content": "hi"}], schema={"type": "object"})
    req = fake.requests[0]
    assert msg["content"] == "hello"
    assert req["headers"]["api-subscription-key"] == "test-key"
    assert req["body"]["model"] == "sarvam-105b"
    assert req["body"]["reasoning_effort"] is None and req["body"]["temperature"] == 0.2
    assert req["body"]["response_format"]["json_schema"]["strict"] is True


def test_errors_become_llm_errors(fake):
    fake.replies["/v1/chat/completions"] = (403, {"error": {"message": "invalid key"}})
    with pytest.raises(llm.LLMError, match="403"):
        llm.chat([{"role": "user", "content": "hi"}])


def test_parse_json_accepts_fenced_json():
    assert llm.parse_json('```json\n{"a": 1}\n```') == {"a": 1}
    with pytest.raises(llm.LLMError):
        llm.parse_json("not json")


def test_story_through_sarvam_drops_invented_citations_and_translates(neo4j_driver, seeded, fake):
    story = {"sentences": [{"text": "A phishing link was clicked.", "cites": ["a-01"]},
                           {"text": "The payroll server was hit.", "cites": ["payroll-99"]}]}
    fake.replies["/v1/chat/completions"] = chat_reply(json.dumps(story))
    fake.replies["/translate"] = (200, {"translated_text": "एक फ़िशिंग लिंक पर क्लिक किया गया।", "request_id": "x"})
    with neo4j_driver.session() as s:
        inc = s.run("MATCH (a:Alert {id: 'a-01'}) RETURN a.incident_id AS i").single()["i"]
        result = write_story(s, inc, lang="hi-IN")
    assert result["provider"] == "sarvam" and result["language"] == "hi-IN"
    assert [x["cites"] for x in result["sentences"]] == [["a-01"]]
    assert result["sentences"][0]["text_en"] == "A phishing link was clicked."
    assert result["dropped"][0]["cites"] == ["payroll-99"]
    translate = [r for r in fake.requests if r["path"] == "/translate"][0]["body"]
    assert translate["target_language_code"] == "hi-IN" and translate["model"] == "sarvam-translate:v1"


def test_story_falls_back_to_facts_when_sarvam_fails(neo4j_driver, seeded, fake):
    fake.replies["/v1/chat/completions"] = (500, {"error": {"message": "down"}})
    with neo4j_driver.session() as s:
        inc = s.run("MATCH (a:Alert {id: 'a-01'}) RETURN a.incident_id AS i").single()["i"]
        result = write_story(s, inc)
    assert result["source"] == "facts" and len(result["sentences"]) >= 4
