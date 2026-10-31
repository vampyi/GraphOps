"""shared settings for the claude code collector: where GraphOps is and the ingest token.

read from ~/.graphops/config.json, which stays on the laptop and out of the repository:
    {"url": "https://graph-ops.vercel.app", "token": "...", "source": "claude-code-deepthi", "host": "Deepthi's MacBook"}
the token must match INGEST_TOKEN on the GraphOps server."""
import json
import os
import platform
import ssl
import subprocess
import urllib.request
from pathlib import Path

CONFIG = Path(os.environ.get("GRAPHOPS_CONFIG", Path.home() / ".graphops" / "config.json"))


def config():
    return json.loads(CONFIG.read_text())


def tls():
    """python from python.org on a mac ships with no root certificates, so https fails until someone runs its
    Install Certificates script. use the mac's own system roots instead (same as collectors/osquery/collect.py)."""
    ctx = ssl.create_default_context()
    if ctx.cert_store_stats()["x509_ca"] == 0 and platform.system() == "Darwin":
        roots = subprocess.run(["security", "find-certificate", "-a", "-p",
                                "/System/Library/Keychains/SystemRootCertificates.keychain"],
                               capture_output=True, text=True).stdout
        if roots:
            ctx.load_verify_locations(cadata=roots)
    return ctx


def post(path, body, timeout=10):
    cfg = config()
    req = urllib.request.Request(
        cfg["url"].rstrip("/") + path, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", "X-GraphOps-Token": cfg["token"],
                 "User-Agent": "graphops-collector"})
    with urllib.request.urlopen(req, timeout=timeout, context=tls()) as res:
        return json.loads(res.read())
