#!/usr/bin/env python3
"""Require each declared WS5 root and all executed children to pass, with no skip."""
import argparse
from collections import Counter
import json
from pathlib import Path


def verify(events, inventory):
    prefix = "github.com/example/autostream-observability/"
    expected = set()
    for line in inventory.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        package, test = line.split()
        pair = (prefix + package, test)
        if pair in expected:
            raise ValueError("duplicate required WS5 root")
        expected.add(pair)
    if len(expected) != 14:
        raise ValueError("WS5 root denominator changed")
    roots, cases, actions = {}, set(), Counter()
    for line in events.splitlines():
        event = json.loads(line)
        action, package, test = (event.get(k, "") for k in ("Action", "Package", "Test"))
        if action in {"fail", "skip", "build-fail"}:
            raise ValueError("failure/skip in required WS5 execution")
        if not test:
            continue
        root = test.split("/", 1)[0]
        if (package, root) not in expected:
            continue
        actions[action] += 1
        cases.add((package, test))
        if test == root:
            roots.setdefault((package, root), Counter())[action] += 1
    if set(roots) != expected:
        raise ValueError("missing required WS5 roots")
    if any(counts["run"] != 1 or counts["pass"] != 1 for counts in roots.values()):
        raise ValueError("required WS5 roots did not each execute and pass once")
    if actions["run"] != actions["pass"]:
        raise ValueError("unfinished WS5 child test")
    return {"required_roots": len(roots), "root_and_subcases": len(cases), "skip": 0, "fail": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path)
    args = parser.parse_args()
    inventory = Path(__file__).with_name("ws5-required-tests.txt")
    print(json.dumps(verify(args.events.read_text(encoding="utf-8"), inventory.read_text(encoding="utf-8"))))
