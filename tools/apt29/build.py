"""build the GraphOps 'APT29 day 1' scenario from the public lab recording.

source: MITRE ATT&CK Evaluations APT29 day 1, recorded by the Open Threat Research Forge (OTRF) Security Datasets
project, MIT licence. download apt29_evals_day1_manual.zip from
https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29/day1 and unzip it.

usage: python3 -I tools/apt29/build.py <path to apt29_evals_day1_manual_*.json> > data/scenarios/apt29_day1.json

what it does: reads the 196,081 real Windows, Sysmon and PowerShell events, applies a dozen detection rules written
for GraphOps (not copied from any rule set) and keeps the first hit of each rule per machine and cause as an alert,
at the real time on the real machine. the network (machines, the user, logons) is built only from what the logs show.
each alert is labelled attack or noise by us, from the published emulation plan (center-for-threat-informed-defense
adversary_emulation_library, apt29 scenario 1) and the payload's process tree; the label is used only to score the
ranking, never by it. command-line passwords are removed."""
import json
import re
import sys

SY = "Microsoft-Windows-Sysmon/Operational"
RLO = ("\u202e", "\u00e2\u20ac\u00ae")  # the right-to-left override character, also as it appears mis-decoded in the file
INTERNAL = ("10.", "172.", "127.", "::1")
SYSTEM_LSASS = {"svchost.exe", "csrss.exe", "wininit.exe", "services.exe", "lsm.exe", "wmiprvse.exe", "msmpeng.exe"}
NOISE_LSASS = {"windowsazuretelemetryservice.exe", "antimalwareconfig.exe"}  # azure's own agents on the lab machines


def host(e):
    return (e.get("Hostname") or "").split(".")[0].lower()


def t(e):
    u = e.get("UtcTime")
    return (u.replace(" ", "T")[:19] if u else e["@timestamp"][:19])


def base(path):
    name = (path or "").replace("/", "\\").split("\\")[-1]
    for r in RLO:
        name = name.replace(r, "")
    return name


def run(path):
    alerts, seen = [], set()
    procs, payload_tree = {}, set()

    def add(key, e, rule, name, sev, tactic, tech, involves, label, why):
        if key in seen:
            return
        seen.add(key)
        alerts.append({"time": t(e), "name": name, "severity": sev, "source_tool": "Sysmon" if e.get("Channel") == SY else "Windows Security",
                       "tactic_id": tactic, "technique_id": tech, "involves": involves, "scenario": label,
                       "rule": rule, "evidence": why})

    for line in open(path):
        e = json.loads(line)
        ch, eid, h = e.get("Channel"), e.get("EventID"), host(e)
        img = e.get("Image") or ""
        if ch == SY and eid == 1:
            g, parent = e.get("ProcessGuid") or e.get("ProcessGUID"), e.get("ParentProcessGuid")
            procs[g] = parent
            if any(r in img for r in RLO):
                payload_tree.add(g)
                add(("rlo", h), e, "rlo", "File with a hidden right-to-left character in its name started", "high",
                    "TA0002", "T1204.002", [h, "pbeesly"], "attack", "the file shows as rcs.3aka3.doc but is cod.3aka3.scr")
            elif parent in payload_tree:
                payload_tree.add(g)
            cmd = (e.get("CommandLine") or "")
            low = cmd.lower()
            if base(e.get("ParentImage")).lower() == "sdclt.exe" and base(img).lower() == "control.exe":
                add(("uac", h), e, "uac", "User Account Control bypassed through sdclt.exe", "high", "TA0004", "T1548.002",
                    [h, "pbeesly"], "attack", "sdclt.exe started control.exe with a hijacked registry key")
            if base(img).lower() == "powershell.exe" and ("-ep bypass" in low or ("-nop" in low and "-w hi" in low)):
                add(("pshidden", h, cmd[:30]), e, "ps_hidden", "Hidden PowerShell that bypasses execution policy", "medium",
                    "TA0002", "T1059.001", [h, "pbeesly"], "attack", "powershell with -ep bypass / -nop -w hidden")
            if base(img).lower().startswith("sdelete"):
                add(("sdelete", h), e, "sdelete", "Secure-delete tool wiped files", "medium", "TA0005", "T1070.004",
                    [h, "pbeesly"], "attack", "sdelete64.exe removed the dropped files")
            if base(img).lower().startswith("psexec") and " -p " in cmd:
                target = (re.search(r"\\\\\\\\?(\w+)", cmd) or re.search(r"\\\\(\w+)", cmd))
                tgt = target.group(1).lower() if target else ""
                add(("psexec", h), e, "psexec", "PsExec run with a password on the command line", "high", "TA0008", "T1021.002",
                    [h, tgt, "pbeesly"] if tgt else [h, "pbeesly"], "attack", f"PsExec to {tgt.upper()} as pbeesly (password removed)")
        elif ch == SY and eid == 3:
            dst, port = e.get("DestinationIp") or "", str(e.get("DestinationPort"))
            if dst.startswith(INTERNAL):
                continue
            b = base(img).lower()
            if ("\\programdata\\" in img.lower() or "\\windows\\temp\\" in img.lower()) and port not in ("80", "443"):
                add(("c2", h, b), e, "odd_port", f"{base(img)[-24:]} connected out to an unusual port", "high", "TA0011", "T1571",
                    [h], "attack", f"{dst}:{port}")
            if b == "powershell.exe" and port == "80" and dst.startswith("192.168.0.4"):
                add(("webdav", h), e, "webdav", "PowerShell sent data to an outside web server", "high", "TA0010", "T1048.003",
                    [h, "pbeesly"], "attack", f"{dst}:{port}, the attacker's WebDAV share")
        elif ch == SY and eid == 10 and "lsass" in (e.get("TargetImage") or "").lower():
            src = base(e.get("SourceImage")).lower()
            if src in SYSTEM_LSASS:
                continue
            label = "noise" if src in NOISE_LSASS else "attack"
            add(("lsass", h, src), e, "lsass", "LSASS memory opened by a non-system process", "high", "TA0006", "T1003.001",
                [h], label, f"{base(e.get('SourceImage'))} opened lsass.exe" + (" (Azure's own agent)" if label == "noise" else ""))
        elif ch == SY and eid == 11 and "\\start menu\\programs\\startup\\" in (e.get("TargetFilename") or "").lower():
            add(("startup", h), e, "startup", "Program added to the Startup folder", "medium", "TA0003", "T1547.001",
                [h, "pbeesly"], "attack", base(e.get("TargetFilename")))
        elif (ch == "System" and eid == 7045) or (ch in ("Security", "security") and eid == 4697):
            name = e.get("ServiceName") or ""
            image = (e.get("ImagePath") or e.get("ServiceFileName") or "")
            # windows creates per-user copies of its own services (name_<hex>) when someone signs in: noise
            attacker = any(x in image.lower() for x in ("javamtsup", "psexesvc"))
            add(("svc", h, image.lower() if attacker else name), e, "service", f"New Windows service installed: {name}", "medium",
                "TA0003", "T1543.003", [h], "attack" if attacker else "noise", image[:80])
        elif ch in ("Security", "security") and eid == 4624:
            user, lt, ip = e.get("TargetUserName") or "", str(e.get("LogonType")), e.get("IpAddress") or ""
            if user.endswith("$") or user.upper().startswith(("DWM-", "UMFD-")) or user in ("SYSTEM", "ANONYMOUS LOGON"):
                continue
            if lt == "3" and ip.startswith("10.0.1.") and h != "newyork":
                add(("netlogon", h, ip), e, "netlogon", "Network logon from another workstation", "low", "TA0008", "T1021.002",
                    [h, user.lower()], "attack", f"{user} from {ip}")
            if lt == "3" and h == "newyork":
                add(("dclogon", h), e, "netlogon", "Network logon from another workstation", "low", "TA0008", "T1021.002",
                    [h, user.lower()], "noise", f"{user} from {ip}: routine sign-in traffic to the domain controller")
            if lt == "10":
                add(("rdp", h), e, "rdp", "Remote desktop logon", "low", "TA0008", "T1021.001", [h, user.lower()], "noise",
                    f"{user} signed back in over remote desktop after the reboot")
    alerts.sort(key=lambda a: a["time"])
    for n, a in enumerate(alerts, 1):
        a["id"] = f"apt-{n:02d}"
    return alerts


NETWORK = {
    "nodes": [
        {"id": "scranton", "label": "Computer", "name": "SCRANTON", "os": "Windows 10", "zone": "normal", "owner": "pbeesly", "critical": False, "location": "onprem"},
        {"id": "nashua", "label": "Computer", "name": "NASHUA", "os": "Windows 10", "zone": "normal", "critical": False, "location": "onprem"},
        {"id": "utica", "label": "Computer", "name": "UTICA", "os": "Windows 10", "zone": "normal", "critical": False, "location": "onprem"},
        {"id": "newyork", "label": "Computer", "name": "NEWYORK", "os": "Windows Server", "zone": "server", "critical": True, "location": "onprem",
         "note": "domain controller: the only machine issuing Kerberos tickets in the recording"},
        {"id": "pbeesly", "label": "User", "name": "pbeesly", "location": "onprem"},
    ],
    # only what the logs show: pbeesly signs in to scranton and nashua, scranton reaches nashua and the domain
    # controller over the network, and pbeesly could install services on both workstations (so holds admin rights)
    "granted": [
        {"src": "pbeesly", "type": "AdminTo", "dst": "scranton", "note": "UAC bypass and service install as pbeesly"},
        {"src": "pbeesly", "type": "AdminTo", "dst": "nashua", "note": "PsExec service installed on NASHUA as pbeesly"},
        {"src": "scranton", "type": "HasSession", "dst": "pbeesly"},
    ],
    "observed": [
        {"src": "pbeesly", "type": "LoggedInto", "dst": "scranton", "first_seen": "2020-05-02T02:40:00", "last_seen": "2020-05-02T03:20:49", "count": 3},
        {"src": "pbeesly", "type": "LoggedInto", "dst": "nashua", "first_seen": "2020-05-02T03:09:24", "last_seen": "2020-05-02T03:15:00", "count": 8},
        {"src": "scranton", "type": "RemoteLogon", "dst": "newyork", "first_seen": "2020-05-02T02:40:00", "last_seen": "2020-05-02T03:20:48", "count": 6},
    ],
}

if __name__ == "__main__":
    alerts = run(sys.argv[1])
    events = [{"src": "scranton", "type": "RemoteLogon", "dst": "nashua", "user": "pbeesly", "time": "2020-05-02T03:09:24", "scenario": "attack"}]
    print(json.dumps({
        "name": "APT29 day 1 (real lab recording)",
        "description": "Real Windows, Sysmon and PowerShell logs of MITRE's APT29 emulation, from OTRF Security Datasets (MIT licence). "
                       "Alerts are GraphOps detection rules applied to the real events; attack or noise labels are ours, from the "
                       "published emulation plan.",
        "source": "https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29/day1",
        "network": NETWORK, "events": events, "alerts": alerts}, indent=1))
