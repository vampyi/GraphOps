# Connect a Claude Code agent to GraphOps

GraphOps treats an AI coding agent as an identity, like a person or a machine. This collector shows a real one: Claude Code on a team laptop. It appears in the **AI agents** tab and in the graph, with what it **can** reach, what it **did**, and the routes an attacker could take through it (for example a web page with hidden instructions, read by the agent, which holds a key to a production service).

Two scripts:

| Script | What it sends | When |
|---|---|---|
| `scan.py` | What the agent can reach: its working folder (and the home folder, unless reads outside the folder are blocked), secret files by **name only** and which services their keys are for, the accounts its command-line tools are signed in to, and the tools it can call (built-in and MCP servers). Also counts from its past sessions: how many web pages it read, AWS commands, git pushes. | When you run it |
| `hook.py` | One small event per action: the tool name and what it touched (a folder, a secret file, a service or a tool) | After every tool call, as a Claude Code hook |

## What it never sends

- File contents, command output or command arguments (only the first word of a command, such as `git`).
- The value of any key or password. A `.env` file is noted as existing; which services it holds keys for comes from the variable names in the `.env.example` next to it.
- AWS profile names: they are counted, never named, because they can be client companies.
- Names of files outside the project: they show as "a file in the home folder".
- Project names or file names from past sessions: the history keeps only counts per category.

## Setup

1. Create `~/.graphops/config.json` (it stays on your laptop, never in the repository):

   ```json
   {"url": "https://graph-ops.vercel.app", "token": "<the ingest token, from Deepthi, privately>",
    "source": "claude-code-<yourname>", "host": "<Your name>'s laptop"}
   ```

   The token must match `INGEST_TOKEN` on the server.

2. Check what would be sent, without sending it:

   ```
   python3 collectors/claude_code/scan.py <your working folder> --dry-run
   ```

3. Send the access scan:

   ```
   python3 collectors/claude_code/scan.py <your working folder>
   ```

4. Turn on live activity: add a `PostToolUse` hook to `.claude/settings.json` in the folder you work in:

   ```json
   {"hooks": {"PostToolUse": [{"matcher": "*", "hooks": [{"type": "command",
     "command": "python3 <path to>/GraphOps/collectors/claude_code/hook.py 2>/dev/null || true", "timeout": 5}]}]}}
   ```

   The hook sends from a background process, so it never slows the agent down or makes a tool call fail.

On a Mac with Python from python.org, which ships without root certificates, the collector uses the Mac's own system certificates for HTTPS. Nothing to install.

## Stop

Remove the hook from `.claude/settings.json`, or point `url` in `~/.graphops/config.json` at `http://localhost:8000` so nothing reaches the public site.
