"""access scan: what Claude Code on this laptop CAN reach, sent to GraphOps as an inventory.

reads names only. it never opens a secret file: it notes that the file exists, and for a .env file it learns
which services the keys are for from the variable names in the .env.example next to it. account names come
from the signed-in command line tools; tool names from claude code's own settings and `claude mcp list`.

usage: python3 collectors/claude_code/scan.py <working folder> [--dry-run]"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from common import config, post

HOME = Path.home()
SKIP_DIRS = {"node_modules", ".venv", "venv", ".git", "dist", "build", "__pycache__", ".next", "Library"}
SECRET_NAME = re.compile(r"^(\.env(\.(?!example$|sample$|template$)[\w.-]+)?|.*\.pem|.*\.key|.*\.p12|id_(rsa|ed25519|ecdsa)"
                         r"|credentials(\.json)?|.*\.tfstate|service-account.*\.json)$")
# well-known places where command line tools keep credentials, relative to the home folder
HOME_SECRETS = {
    ".aws/credentials": ["svc:aws"], ".config/gh/hosts.yml": ["svc:github"], ".docker/config.json": ["svc:docker"],
    ".npmrc": ["svc:npm"], ".netrc": [], ".kube/config": ["svc:kubernetes"],
    ".ssh/id_rsa": ["svc:ssh"], ".ssh/id_ed25519": ["svc:ssh"], ".ssh/id_ecdsa": ["svc:ssh"],
}
# which service a .env variable belongs to, by its name
VAR_SERVICE = [("NEO4J", "svc:neo4j"), ("KAFKA", "svc:kafka"), ("SARVAM", "svc:sarvam"), ("AWS_", "svc:aws"),
               ("ANTHROPIC", "svc:anthropic"), ("OPENAI", "svc:openai"), ("INGEST_TOKEN", "svc:graphops"),
               ("RESEND", "svc:resend"), ("GITHUB", "svc:github")]
SERVICES = {
    "svc:neo4j": ("Neo4j database (GraphOps graph)", True), "svc:kafka": ("Aiven Kafka (event stream)", False),
    "svc:sarvam": ("Sarvam AI API", False), "svc:aws": ("AWS account", True), "svc:anthropic": ("Anthropic API", False),
    "svc:openai": ("OpenAI API", False), "svc:graphops": ("GraphOps ingest", False), "svc:resend": ("Resend email", False),
    "svc:github": ("GitHub (code; a push to main deploys the live site)", True), "svc:docker": ("Docker registry", False),
    "svc:npm": ("npm registry", False), "svc:kubernetes": ("Kubernetes cluster", True), "svc:ssh": ("SSH servers", True),
}


def settings():
    """claude code's permission settings: user-wide, then the working folder's own (later files win)."""
    merged = {"allow": [], "deny": [], "ask": [], "additionalDirectories": [], "defaultMode": None,
              "blockReadsOutsideWorkingDirectories": None}
    for p in [HOME / ".claude/settings.json"]:
        if p.exists():
            perms = json.loads(p.read_text()).get("permissions", {})
            for k in ("allow", "deny", "ask", "additionalDirectories"):
                merged[k] += perms.get(k, [])
            for k in ("defaultMode", "blockReadsOutsideWorkingDirectories"):
                if k in perms:
                    merged[k] = perms[k]
    return merged


def env_services(env_file):
    example = env_file.with_name(env_file.name + ".example")
    if not example.exists():
        example = env_file.parent / ".env.example"
    if not example.exists():
        return []
    names = [ln.split("=", 1)[0].strip() for ln in example.read_text().splitlines() if "=" in ln and not ln.startswith("#")]
    return sorted({svc for name in names for prefix, svc in VAR_SERVICE if name.startswith(prefix)})


def find_secrets(root, depth=4):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = Path(dirpath).relative_to(root)
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not (d.startswith(".") and d not in (".aws", ".ssh"))]
        if len(rel.parts) >= depth:
            dirnames[:] = []
        for f in filenames:
            if SECRET_NAME.match(f):
                found.append(Path(dirpath) / f)
    return found


def run(cmd, timeout=45):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def scan(root):
    cfg = config()
    root = Path(root).resolve()
    perms = settings()
    home_readable = perms["blockReadsOutsideWorkingDirectories"] is not True
    agent_id = cfg["source"]
    folders = [{"id": f"folder:{root.name}", "name": f"{root.name} (working folder)", "path": str(root).replace(str(HOME), "~")}]
    if home_readable:
        folders.append({"id": "folder:home", "name": "Home folder (reads outside the working folder are not blocked)", "path": "~"})
    secrets, used_services = [], set()
    for path in find_secrets(root):
        svcs = env_services(path) if path.name.startswith(".env") else []
        rel = str(path.relative_to(root))
        secrets.append({"id": f"secret:{root.name}/{rel}", "name": rel, "path": f"{root.name}/{rel}",
                        "folder": f"folder:{root.name}", "services": svcs})
        used_services.update(svcs)
    if home_readable:
        for rel, svcs in HOME_SECRETS.items():
            if (HOME / rel).exists():
                secrets.append({"id": f"secret:~/{rel}", "name": f"~/{rel}", "path": f"~/{rel}", "folder": "folder:home",
                                "services": svcs})
                used_services.update(svcs)
    accounts = []
    gh = run(["gh", "auth", "status"])
    gh_accounts = re.findall(r"Logged in to github\.com account (\S+)", gh)
    if gh_accounts:
        accounts.append({"service": "svc:github", "account": gh_accounts[0],
                         "others": len(gh_accounts) - 1})
        used_services.add("svc:github")
    tools = [{"id": "tool:bash", "name": "Shell (runs commands)"},
             {"id": "tool:files", "name": "Read and edit files"},
             {"id": "tool:webfetch", "name": "Web fetch and search", "untrusted_input": True}]
    if (HOME / ".claude/chrome").exists():
        tools.append({"id": "tool:chrome", "name": "Chrome browser control", "untrusted_input": True})
    for line in run(["claude", "mcp", "list"]).splitlines():
        m = re.match(r"^(.+?):\s+\S+.*-\s+[✔✓!✗]", line)
        if m:
            name = m.group(1).strip()
            tools.append({"id": "tool:mcp:" + re.sub(r"[\W_]+", "-", name.lower()).strip("-"), "name": f"{name} (MCP)", "mcp": True})
    services = [{"id": s, "name": SERVICES.get(s, (s, False))[0], "critical": SERVICES.get(s, (s, False))[1]}
                for s in sorted(used_services)]
    return {
        "agent": {"id": agent_id, "name": "Claude Code", "platform": "Anthropic Claude Code", "host": cfg.get("host"),
                  "mode": f"settings default: {perms['defaultMode'] or 'asks before acting'} (a session can start in another mode)",
                  "allow": perms["allow"], "deny": perms["deny"],
                  "home_readable": home_readable},
        "folders": folders, "secrets": secrets, "services": services, "accounts": accounts, "tools": tools,
    }


if __name__ == "__main__":
    inv = scan(sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else os.getcwd())
    if "--dry-run" in sys.argv:
        print(json.dumps(inv, indent=1))
    else:
        print(post(f"/api/sources/{config()['source']}/inventory", {"kind": "ai_agent", "inventory": inv}, timeout=120))
