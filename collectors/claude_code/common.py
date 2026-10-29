"""shared settings for the claude code collector: where GraphOps is and the ingest token.

read from ~/.graphops/config.json, which stays on the laptop and out of the repository:
    {"url": "https://graph-ops.vercel.app", "token": "...", "source": "claude-code-deepthi", "host": "Deepthi's MacBook"}
the token must match INGEST_TOKEN on the GraphOps server."""
import json
import os
import urllib.request
from pathlib import Path

CONFIG = Path(os.environ.get("GRAPHOPS_CONFIG", Path.home() / ".graphops" / "config.json"))


def config():
    return json.loads(CONFIG.read_text())


def post(path, body, timeout=10):
    cfg = config()
    req = urllib.request.Request(
        cfg["url"].rstrip("/") + path, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", "X-GraphOps-Token": cfg["token"],
                 "User-Agent": "graphops-collector"})
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return json.loads(res.read())
