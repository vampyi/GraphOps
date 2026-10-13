"""data simulator: plays one day at the sample organisation as if it were happening now.

    python -m app.simulate                 # the normal day, at 60x speed, into kafka
    python -m app.simulate --attack        # the same day with the scripted attack mixed in
    python -m app.simulate --speed 0       # no waiting between events
    python -m app.simulate --dry-run       # print the messages instead of sending them

the alerts and attack come from data/sample_org. the everyday activity around them is random but uses a
fixed seed, so the same options always give the same stream."""
import argparse
import json
import random
import sys
import time
from datetime import datetime, timedelta

from .seed import SAMPLE

DAY_START = "2026-10-20T08:05:00"
DAY_END = "2026-10-20T11:55:00"
INVENTORY_TIME = "2026-10-20T08:00:00"
TOPIC_ORDER = ["cmdb", "identity", "flows", "edr", "alerts"]
EVERYDAY_EVENTS = 150
EVERYDAY_APPS = [("chrome.exe", "explorer.exe"), ("excel.exe", "explorer.exe"), ("teams.exe", "explorer.exe"),
                 ("outlook.exe", "explorer.exe"), ("svchost.exe", "services.exe")]
# the attacker's programs on laptop-42, seen by the edr before it raises its alert
ATTACK_PROCESSES = [("2026-10-20T10:01:10", "rundll32.exe", "outlook.exe"),
                    ("2026-10-20T10:11:40", "procdump64.exe", "cmd.exe")]


def build(attack=False, seed=7, sample=SAMPLE):
    """the whole day as a time-ordered list of (topic, key, message)."""
    network = json.loads((sample / "network.json").read_text())
    day = json.loads((sample / "alerts.json").read_text())
    rng = random.Random(seed)
    out = []

    for n, node in enumerate(x for x in network["nodes"] if x["label"] == "Computer"):
        msg = {"event_id": f"cm-{n + 1:06d}", "time": INVENTORY_TIME, "source_tool": "CMDB", "kind": "Asset",
               "id": node["id"], "label": "Computer"}
        msg.update({k: node[k] for k in ("name", "os", "zone", "owner", "critical") if k in node})
        out.append(("cmdb", node["id"], msg))

    for alert in day["alerts"]:
        if alert["scenario"] == "attack" and not attack:
            continue
        msg = {"event_id": f"al-{alert['id']}", "kind": "Alert",
               **{k: v for k, v in alert.items() if k != "scenario"}}
        out.append(("alerts", alert["involves"][0], msg))

    if attack:
        for n, ev in enumerate(e for e in day["events"] if e["scenario"] == "attack"):
            msg = {"event_id": f"id-atk-{n + 1:03d}", "time": ev["time"], "source_tool": "Active Directory",
                   "kind": ev["type"], "src": ev["src"], "dst": ev["dst"], "user": ev.get("user")}
            out.append(("identity", ev["src"], msg))
        for n, (t, proc, parent) in enumerate(ATTACK_PROCESSES):
            out.append(("edr", "laptop-42", {"event_id": f"edr-atk-{n + 1:03d}", "time": t, "source_tool": "EDR",
                                             "kind": "ProcessStart", "host": "laptop-42", "user": "intern_a",
                                             "process": proc, "parent": parent}))

    out.extend(everyday(network, rng))
    # at the same second, inventory and activity come before the alert they explain
    out.sort(key=lambda x: (x[2]["time"], TOPIC_ORDER.index(x[0]), x[2]["event_id"]))
    return out


def everyday(network, rng, count=EVERYDAY_EVENTS):
    """normal activity: people logging into their own laptops, programs starting, file share traffic.
    it only repeats routes already seen before the day, so it never creates a new path. remote logons
    are left out because the ranker reads their timing."""
    logins = [e for e in network["observed"] if e["type"] == "LoggedInto"]
    flows = [e for e in network["observed"] if e["type"] == "ConnectedTo"]
    laptops = [n for n in network["nodes"] if n["label"] == "Computer" and n.get("owner") and n["id"].startswith("laptop-")]
    start, end = datetime.fromisoformat(DAY_START), datetime.fromisoformat(DAY_END)
    span = int((end - start).total_seconds())
    out = []
    for n in range(count):
        t = (start + timedelta(seconds=rng.randrange(span))).isoformat()
        pick = rng.random()
        if pick < 0.35:
            e = rng.choice(logins)
            out.append(("identity", e["src"], {"event_id": f"id-{n + 1:06d}", "time": t, "source_tool": "Active Directory",
                                               "kind": "LoggedInto", "src": e["src"], "dst": e["dst"]}))
        elif pick < 0.55:
            e = rng.choice(flows)
            out.append(("flows", e["src"], {"event_id": f"fl-{n + 1:06d}", "time": t, "source_tool": "Firewall",
                                            "kind": "Connection", "src": e["src"], "dst": e["dst"],
                                            "dst_port": e.get("port", 445), "bytes": rng.randrange(2_000, 900_000)}))
        else:
            host = rng.choice(laptops)
            proc, parent = rng.choice(EVERYDAY_APPS)
            out.append(("edr", host["id"], {"event_id": f"edr-{n + 1:06d}", "time": t, "source_tool": "EDR",
                                            "kind": "ProcessStart", "host": host["id"], "user": host["owner"],
                                            "process": proc, "parent": parent}))
    return out


def play(stream, send, speed=60.0, stop=None):
    """send each message, waiting the simulated gap divided by `speed`. speed 0 sends without waiting."""
    prev = None
    for topic, key, msg in stream:
        if stop is not None and stop.is_set():
            return
        t = datetime.fromisoformat(msg["time"])
        if speed and prev is not None and t > prev:
            wait = (t - prev).total_seconds() / speed
            if stop is not None:
                if stop.wait(wait):
                    return
            else:
                time.sleep(wait)
        prev = t
        send(topic, key, msg)


def kafka_sender(prod):
    def send(topic, key, msg):
        prod.produce(topic, key=key.encode(), value=json.dumps(msg).encode())
        prod.poll(0)
    return send


def main(argv=None):
    p = argparse.ArgumentParser(description="play a simulated day at the sample organisation into kafka")
    p.add_argument("--attack", action="store_true", help="mix in the scripted attack")
    p.add_argument("--speed", type=float, default=60, help="how many times faster than real time; 0 means no waiting")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--dry-run", action="store_true", help="print messages instead of sending them")
    args = p.parse_args(argv)
    stream = build(attack=args.attack, seed=args.seed)

    if args.dry_run:
        play(stream, lambda topic, key, msg: print(topic, json.dumps(msg)), speed=args.speed)
        return
    from .stream import create_topics, kafka_config, producer
    conf = kafka_config() or sys.exit("set KAFKA_BOOTSTRAP in .env, for example localhost:9092")
    create_topics(conf)
    prod = producer(conf)
    print(f"sending {len(stream)} messages at {args.speed:g}x", file=sys.stderr)
    play(stream, kafka_sender(prod), speed=args.speed)
    prod.flush(30)


if __name__ == "__main__":
    main()
