# Connect your laptop and your Claude Code to GraphOps

About 15 minutes. You don't run the backend, a database or anything else from this repo. Two small Python scripts on your laptop send reports straight to the live site, **graph-ops.vercel.app**. Your laptop then appears in the graph, and its changes appear as alerts in Triage. Your Claude Code appears in the **AI agents** tab.

There are two parts. Do one or both:

| Part | What shows up on GraphOps | Needs |
|---|---|---|
| **A. Your laptop** (osquery) | Your laptop as a machine in the graph. Each change (firewall off, a new admin, a new open port, someone signing in) becomes an alert tagged REAL. | osquery and Python 3 |
| **B. Your Claude Code** | Your Claude Code as an AI agent: what it can reach, what it does live, and the routes an attacker could take through it | Claude Code and Python 3 |

## Before you start

1. **Python 3**: check with `python3 --version`. On Windows, use `python` instead of `python3` everywhere below.
2. **The repo**: `git clone https://github.com/vampyi/GraphOps.git`, or `git pull` on `main` if you already have it. Note the full path of the folder, for example `/Users/you/GraphOps`.
3. **The ingest token**: Deepthi sends it to you privately. **Never post it in a group, a commit, an issue or a screenshot.** It is the only thing stopping strangers from writing to the live site.
4. **Pick your name tag** in lowercase with no spaces, for example `vatanesh`. You'll use it as `laptop-<name>` and `claude-code-<name>`.

## What is sent, and what never is

| Sent | Never sent |
|---|---|
| Laptop: local account names, masked as `user-1a2b`; which ones are admins; who is signed in; listening ports and their program; firewall and disk encryption on or off; OS version | Files or their contents, browsing, open apps, command lines, passwords, keys, IP addresses, network traffic |
| Claude Code: the folders it works in; secret files by **name** (like `.env`); which services their keys are for (read from `.env.example`, never `.env`); your GitHub username; the tools and MCP servers it can use; how many AWS profiles you have (counted, never named) | The content of any file, the value of any key, AWS profile names, command arguments, names of files outside the project |
| Claude Code history: **counts only** from your past sessions (for example "read 300 web pages, ran 20 git pushes") | Project names, file names or anything you typed |

The public site shows your laptop's label and these facts. If you're not comfortable with that, use a label like "Team laptop 2", or skip a part.

---

## Part A: your laptop (osquery)

### A1. Install osquery
- **Mac:** `brew install --cask osquery`. It asks for your Mac password. If macOS asks whether osquery may "find devices on local networks", click **Don't Allow**; it isn't needed.
- **Windows:** download the `.msi` from https://osquery.io/downloads/official and install it.
- **Linux:** download the `.deb` from https://osquery.io/downloads/official, then run `sudo dpkg -i osquery_*.deb`.

Check it worked: `osqueryi --version`.

### A2. Create your config
Create the folder `.graphops` in your home folder (`~/.graphops/` on Mac and Linux, `C:\Users\<you>\.graphops\` on Windows). In it, make a file named `endpoint.json`:

```json
{
  "url": "https://graph-ops.vercel.app",
  "token": "PASTE-THE-TOKEN-HERE",
  "source": "laptop-<name>",
  "label": "<Name>'s laptop",
  "owner": "<Name>",
  "mask_users": true
}
```

### A3. Check what would be sent, without sending it
From the GraphOps folder:
```
python3 collectors/osquery/collect.py --dry-run
```
Read the output. It is exactly what the site will receive.

### A4. Start it
```
python3 collectors/osquery/collect.py
```
It prints one line a minute. Leave the terminal open; press Ctrl+C to stop. Within a minute, your laptop appears in **Graph → Connected sources** on graph-ops.vercel.app, and its alerts appear in **Triage**.

**Try it:** turn your firewall off for a minute and back on. Triage shows "Firewall turned off", tagged REAL.

---

## Part B: your Claude Code

### B1. Create your config
In the same `.graphops` folder, make a file named `config.json`:

```json
{
  "url": "https://graph-ops.vercel.app",
  "token": "PASTE-THE-TOKEN-HERE",
  "source": "claude-code-<name>",
  "host": "<Name>'s laptop"
}
```

### B2. Check what the access scan would send
From the GraphOps folder (use your own full path):
```
python3 collectors/claude_code/scan.py /full/path/to/GraphOps --dry-run
```
Read it: folders, secret file names, services, tools, and history counts. If anything there shouldn't be public, stop here and tell Deepthi.

### B3. Send the access scan
```
python3 collectors/claude_code/scan.py /full/path/to/GraphOps
```
It prints `{'status': 'ok'}`. Your agent now appears in the **AI agents** tab. When several people are connected, there's a switcher at the top.

### B4. Turn on live activity: only for your GraphOps sessions
Inside your GraphOps folder, create the file `.claude/settings.local.json`. This file is personal: git ignores it, and it only affects Claude Code sessions you start **in this folder**, so nothing from your other work is reported. Put in it:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /full/path/to/GraphOps/collectors/claude_code/hook.py 2>/dev/null || true",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

On Windows, use `"command": "python C:\\full\\path\\to\\GraphOps\\collectors\\claude_code\\hook.py"`.

Start Claude Code in the GraphOps folder and ask it anything, such as "read the README". Each action appears under **Live activity** on the AI agents tab within a few seconds. The hook never slows Claude down or makes a tool call fail; if the site is unreachable, it silently does nothing.

---

## Let your Claude Code do the setup

You can paste this into Claude Code, opened in your GraphOps folder. **Enter the token in the config files yourself;** don't paste it into the chat.

> Read docs/connect-your-laptop.md and set me up for Part A and Part B. My name tag is `<name>` and my label is "<Name>'s laptop". Create ~/.graphops/endpoint.json and ~/.graphops/config.json with the token value left as PASTE-THE-TOKEN-HERE, and tell me when to paste it in. Then run the dry runs and show me the output before sending anything. Write the hook into .claude/settings.local.json in this folder with this folder's absolute path. Don't install osquery yourself; tell me the command to run.

You'll still need to type your password for the osquery install, and paste the token into the two files yourself.

---

## Stop or remove

- **Laptop:** press Ctrl+C. To remove everything, delete `~/.graphops/endpoint.json` and `~/.graphops/endpoint-state.json`, and uninstall osquery if you like.
- **Claude Code:** delete `.claude/settings.local.json` in your GraphOps folder (stops live activity), and `~/.graphops/config.json`.

## If something goes wrong

| You see | Do this |
|---|---|
| `401 wrong or missing X-GraphOps-Token` | The token is mistyped. Copy it again, with no spaces or quotes around it. |
| `CERTIFICATE_VERIFY_FAILED` | Pull the latest `main`: the scripts handle this on Mac now. |
| `osquery is not installed` | Do A1 again, then check `osqueryi --version`. |
| Nothing under Live activity | Check that Claude Code was started in the GraphOps folder, and that the path in `settings.local.json` is correct and absolute. |
| Your laptop says "last report 2 h ago" | `collect.py` isn't running. Start it again (A4). |
