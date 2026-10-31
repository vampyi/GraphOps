# Connect your laptop to GraphOps

Your laptop reports to GraphOps once a minute through **osquery**, the open-source endpoint agent. It then shows up in the live graph, and changes on it show up as alerts in Triage.

## What it sends, and what it never sends

| Sent | Never sent |
|---|---|
| Local accounts, masked as `user-1a2b`, and which ones are admins | Your files or their contents |
| Who is signed in right now | Browsing history, open apps or windows |
| Network ports listening for connections, and the program behind each one | Command lines, passwords or keys |
| Whether disk encryption (FileVault on a Mac, BitLocker on Windows) and the firewall are on | IP addresses or network traffic |
| Your OS name and version | Anything at all after you stop the script |

Each change, such as a new admin account, a new listening port, someone signing in, or the firewall being turned off, becomes one alert on the public demo site. Stop the script (Ctrl+C) and reporting stops.

## Setup (about 10 minutes)

### 1. Install osquery

- **Mac:** `brew install --cask osquery`. It asks for your Mac password.
- **Windows:** download the `.msi` from https://osquery.io/downloads/official and install it.
- **Linux (Ubuntu/Debian):** download the `.deb` from https://osquery.io/downloads/official, then run `sudo dpkg -i osquery_*.deb`.

To check it worked, run `osqueryi --version`.

### 2. Get the files

Pull the latest `main`: `git switch main && git pull`. Or download `collectors/osquery/collect.py` from the repo.

### 3. Create your config

Make the folder `~/.graphops/` (on Windows, `C:\Users\<you>\.graphops\`) and put a file named `endpoint.json` in it:

```json
{
  "url": "https://graph-ops.vercel.app",
  "token": "<ask Deepthi for the ingest token; do not post it anywhere>",
  "source": "laptop-<yourname>",
  "label": "<Your name>'s laptop",
  "owner": "<Your name>",
  "mask_users": true
}
```

### 4. Check what would be sent, without sending it

```
python3 collectors/osquery/collect.py --dry-run
```

Read the output. It's exactly what GraphOps will receive.

### 5. Start reporting

```
python3 collectors/osquery/collect.py
```

Leave it running in a terminal. It prints one line per report. Your laptop shows in the graph under its host name, and each account as `user-xxxx@<host>`.

On a Mac with Python from python.org, which ships without root certificates, the script uses the Mac's own system certificates for HTTPS. Nothing to install. Open https://graph-ops.vercel.app → **Graph** tab → **Connected sources**, and your laptop appears within a minute.

## For a demo moment

Try one of these while someone watches GraphOps:
- turn the firewall off, then back on;
- start a small web server: `python3 -m http.server 8765`.

Within a minute, Triage shows a new alert from your laptop, tagged **real**.

## Stop

Press Ctrl+C. To remove everything: delete `~/.graphops/endpoint.json` and `~/.graphops/endpoint-state.json`, and uninstall osquery if you like.
