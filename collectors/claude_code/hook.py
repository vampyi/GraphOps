"""claude code PostToolUse hook: tells GraphOps what the agent just did, as one small event.

claude code runs this after every tool call and passes the call as JSON on stdin. we send only the tool name
and what it touched, mapped to the same ids the access scan uses: a folder, a secret file, a service or a tool.
no file contents, command output or arguments beyond the first word of a command. it sends in the background
and never blocks or fails the agent."""
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path

HOME = str(Path.home())
CMD_SERVICE = {"git": "svc:github", "gh": "svc:github", "aws": "svc:aws", "vercel": "svc:github",
               "cypher-shell": "svc:neo4j", "docker": "tool:bash"}


def target(tool, inp, root):
    if tool in ("Read", "Edit", "Write", "MultiEdit", "NotebookEdit"):
        p = inp.get("file_path") or inp.get("notebook_path") or ""
        name = os.path.basename(p)
        rp = os.path.realpath(p)
        if root and rp.startswith(root + os.sep):
            rel = os.path.relpath(rp, root)
            if re.match(r"^\.env($|\.(?!example$|sample$|template$))|.*\.(pem|key)$", name):
                return f"secret:{os.path.basename(root)}/{rel}", f"{tool} {rel}"
            return f"folder:{os.path.basename(root)}", f"{tool} {rel}"
        if rp.startswith(HOME):
            rel = "~" + rp[len(HOME):]
            for s in (".aws/credentials", ".config/gh/hosts.yml", ".docker/config.json", ".npmrc", ".ssh/"):
                if s in rel:
                    return f"secret:{rel}", f"{tool} {rel}"
            return "folder:home", f"{tool} {name}"
        return None, None
    if tool == "Bash":
        word = (inp.get("command") or "").strip().split(" ")[0].split("/")[-1]
        return CMD_SERVICE.get(word, "tool:bash"), f"ran {word}"
    if tool in ("WebFetch", "WebSearch"):
        return "tool:webfetch", tool
    if tool.startswith("mcp__"):
        server = tool.split("__")[1]
        if "chrome" in server:
            return "tool:chrome", "browser"
        return "tool:mcp:" + re.sub(r"[\W_]+", "-", server.replace("claude_ai_", "claude.ai ").lower()).strip("-"), tool.split("__")[-1]
    if tool in ("Grep", "Glob"):
        return (f"folder:{os.path.basename(root)}" if root else None), tool
    return None, None


def main():
    try:
        call = json.load(sys.stdin)
    except ValueError:
        return
    root = os.path.realpath(os.environ.get("CLAUDE_PROJECT_DIR") or call.get("cwd") or "")
    tgt, detail = target(call.get("tool_name", ""), call.get("tool_input") or {}, root)
    if not tgt:
        return
    event = {"time": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
             "tool": call.get("tool_name"), "target": tgt, "detail": detail}
    # send from a child process so the agent never waits on the network
    if os.fork() == 0:
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from common import config, post
            post(f"/api/sources/{config()['source']}/events", {"events": [event]}, timeout=5)
        except Exception:
            pass
        os._exit(0)


if __name__ == "__main__":
    main()
