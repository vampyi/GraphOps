"""sarvam ai client for the two llm features (incident story and the ask tab), using only the standard library.

docs checked 26 october 2026 (docs.sarvam.ai): chat completions at POST /v1/chat/completions, key in the
`api-subscription-key` header, model sarvam-105b. the docs disagree on the default reasoning effort and
temperature, so both are always set here. translation at POST /translate with sarvam-translate:v1."""
import json
import os
import re
import urllib.error
import urllib.request

BASE = "https://api.sarvam.ai"
CHAT_MODEL = "sarvam-105b"
TRANSLATE_MODEL = "sarvam-translate:v1"
TIMEOUT = 60

# languages offered in the dashboard. sarvam's translate api takes these codes.
LANGUAGES = {
    "en-IN": "English", "hi-IN": "हिन्दी (Hindi)", "bn-IN": "বাংলা (Bengali)", "ta-IN": "தமிழ் (Tamil)",
    "te-IN": "తెలుగు (Telugu)", "mr-IN": "मराठी (Marathi)", "gu-IN": "ગુજરાતી (Gujarati)",
    "kn-IN": "ಕನ್ನಡ (Kannada)", "ml-IN": "മലയാളം (Malayalam)", "pa-IN": "ਪੰਜਾਬੀ (Punjabi)", "od-IN": "ଓଡ଼ିଆ (Odia)",
}


class LLMError(RuntimeError):
    pass


def available():
    return bool(os.environ.get("SARVAM_API_KEY"))


def _post(path, body):
    key = os.environ.get("SARVAM_API_KEY")
    if not key:
        raise LLMError("SARVAM_API_KEY is not set")
    req = urllib.request.Request(
        BASE + path, data=json.dumps(body).encode(), method="POST",
        headers={"api-subscription-key": key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as res:
            return json.loads(res.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:300]
        raise LLMError(f"sarvam returned {exc.code}: {detail}") from None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise LLMError(f"could not reach sarvam: {exc}") from None


def chat(messages, tools=None, schema=None, max_tokens=1500, temperature=0.2, tool_choice="auto"):
    """one chat completion. returns the assistant message dict (content and possibly tool_calls)."""
    body = {"model": CHAT_MODEL, "messages": messages, "max_tokens": max_tokens,
            "temperature": temperature, "reasoning_effort": None}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = tool_choice
    if schema:
        body["response_format"] = {"type": "json_schema", "json_schema": {"name": "answer", "schema": schema, "strict": True}}
    data = _post("/v1/chat/completions", body)
    try:
        return data["choices"][0]["message"]
    except (KeyError, IndexError, TypeError):
        raise LLMError("unexpected reply from sarvam") from None


def parse_json(text):
    """json from a model reply, tolerating a ```json fence around it."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("\n") + 1:] if "\n" in text else text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise LLMError("the model did not return valid json") from None


def translate(text, target):
    """translate english text into one of LANGUAGES with sarvam-translate."""
    if target == "en-IN" or not text:
        return text
    if target not in LANGUAGES:
        raise LLMError(f"unsupported language {target}")
    data = _post("/translate", {"input": text[:2000], "source_language_code": "en-IN",
                                "target_language_code": target, "model": TRANSLATE_MODEL})
    return data.get("translated_text") or text


def translate_keeping(text, ids, target):
    """translate, but keep ids such as laptop-42 or customer-db exactly as they are. each id is swapped for a
    <n> placeholder, which sarvam-translate leaves alone (checked 26 october 2026), and put back afterwards."""
    if target == "en-IN" or not text:
        return text
    found = sorted({i for i in ids if i and i in text}, key=len, reverse=True)
    masked = text
    for n, i in enumerate(found, 1):
        masked = re.sub(rf"(?<![\w-]){re.escape(i)}(?![\w-])", f"<{n}>", masked)
    out = translate(masked, target)
    if not all(f"<{n}>" in out for n in range(1, len(found) + 1) if f"<{n}>" in masked):
        return translate(text, target)  # a placeholder was lost: translate without protection rather than drop ids
    for n, i in enumerate(found, 1):
        out = out.replace(f"<{n}>", i)
    return out
