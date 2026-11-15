#!/usr/bin/env python3
"""Verify the frozen pin, fixture-only seam and unchanged production startup."""
from collections import Counter
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
BASE = "c2daf86c3ae621372dfde1c5afc3bfb54164ed62"
PIN = "github.com/Kome-Lab/Autostream-Contracts/v3lifecycle v0.0.0-20261115145906-d32ea3514b1c"
SUMS = {PIN + " h1:HfswOPIR7VcFoko8a5LL0YqtRP1UGc6wfuFyggBOIXo=",
        PIN + "/go.mod h1:4mdtG844J5jWEQgB78LBHQEjzbhK+qc0ACLS7+Vlmzw="}


def baseline(path):
    return subprocess.check_output(["git", "show", f"{BASE}:{path}"], cwd=ROOT).decode("utf-8").replace("\r\n", "\n")


def main():
    module = (ROOT / "go.mod").read_text(encoding="utf-8")
    if module.count(PIN) != 1 or module.replace("\t" + PIN + "\n", "") != baseline("go.mod"):
        raise ValueError("old module pins changed")
    current = (ROOT / "go.sum").read_text(encoding="utf-8").splitlines()
    if any(current.count(line) != 1 for line in SUMS):
        raise ValueError("missing exact lifecycle checksum")
    if Counter(line for line in current if line not in SUMS) != Counter(baseline("go.sum").splitlines()):
        raise ValueError("old dependency sums changed")
    product = [ROOT / "internal/notifications" / name for name in (
        "effect_participation.go", "effect_result.go", "effect_fixture_journal.go")]
    for path in product:
        text = path.read_text(encoding="utf-8")
        for forbidden in ('"net/http"', '"net/smtp"', '"os/exec"', "os.Getenv(", "control.FromEnv("):
            if forbidden in text:
                raise ValueError("provider/environment fallback crossed Effect participant boundary")
    startup = (ROOT / "cmd/observability/main.go").read_text(encoding="utf-8")
    if "NewFixtureEffect" in startup:
        raise ValueError("fixture mounted by normal startup")
    participation = product[0].read_text(encoding="utf-8")
    if 'const EffectFixtureProfile = "IU-WS5-SYNTHETIC-ONLY-1"' not in participation:
        raise ValueError("explicit synthetic label missing")
    if "ProductionQualified() bool { return false }" not in participation:
        raise ValueError("fixture qualification changed")
    profile = json.loads((ROOT / "internal/notifications/testdata/effect-profile.json").read_text(encoding="utf-8"))
    if profile["Ref"] != {"ProfileID": "G0-P-EFFECT-OUTCOME", "Revision": 1}:
        raise ValueError("effect profile changed")
    for name in ("provider-accepted-local-known", "provider-ack-unknown", "provider-accepted-local-unknown"):
        record = json.loads((ROOT / f"internal/notifications/testdata/{name}.json").read_text(encoding="utf-8"))
        if record["Header"]["ContractRef"]["ModuleCommitRef"] != "d32ea3514b1c1010391caae0348b0ff9e751f447" or record["Inspection"]["Observations"]["Gate"] != "NOT_QUALIFIED":
            raise ValueError("consumer vector qualified fixture or changed shared revision")
    print(json.dumps({"source_boundary": "PASS", "old_pins": "PRESERVED", "production_qualified": False}))


if __name__ == "__main__":
    main()
