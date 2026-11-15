#!/usr/bin/env python3
"""Reconstruct every reviewed WS5 addition/change from its fixed starting tree."""
import hashlib
import json
import pathlib
import subprocess

BASELINE = "c2daf86c3ae621372dfde1c5afc3bfb54164ed62"
MANIFEST = "scripts/ci/ws5-source-patches.json"


def git(*args):
    return subprocess.check_output(["git", *args])


def canonical(data):
    return data.replace(b"\r\n", b"\n")


def digest(data):
    return hashlib.sha256(canonical(data)).hexdigest()


def main():
    manifest = json.loads(pathlib.Path(MANIFEST).read_text(encoding="utf-8"))
    assert manifest["schema"] == 1 and manifest["baseline"] == BASELINE
    new, patches = manifest["new"], manifest["patches"]
    owned = set(new) | set(patches) | {MANIFEST}
    assert not set(new).intersection(patches) and MANIFEST not in new and MANIFEST not in patches
    for path in owned:
        parsed = pathlib.PurePosixPath(path)
        assert not parsed.is_absolute() and ".." not in parsed.parts and "\\" not in path, "unsafe source path"
    changes = {}
    for line in git("diff", "--name-status", BASELINE, "HEAD").decode().splitlines():
        status, path = line.split("\t", 1)
        assert status in {"A", "M"}, "legacy source removed/renamed"
        assert not (path.endswith(".sql") and status != "A"), "existing Migration changed"
        changes[path] = status
    assert set(changes) == owned, "reviewed source path inventory differs"
    git("merge-base", "--is-ancestor", BASELINE, "HEAD")
    git("diff", "--exit-code", "HEAD", "--")
    for path, expected in new.items():
        assert changes[path] == "A" and digest(pathlib.Path(path).read_bytes()) == expected, "new source digest differs: " + path
    for path, patch in patches.items():
        assert changes[path] == "M", "preserved source classification changed"
        expected = canonical(git("show", BASELINE + ":" + path)).decode("utf-8")
        assert digest(expected.encode()) == patch["before_sha256"]
        for edit in patch["edits"]:
            assert edit["old"] and expected.count(edit["old"]) == 1, "patch anchor differs: " + path
            expected = expected.replace(edit["old"], edit["new"], 1)
        actual = canonical(pathlib.Path(path).read_bytes())
        assert actual == expected.encode() and digest(actual) == patch["after_sha256"], "unreviewed source change: " + path
    print(git("log", "-1", "--format=WS5 tested commit: %H%nWS5 tested tree: %T").decode().strip())
    print(f"WS5 exact source boundary: PASS added={len(new)} modified={len(patches)} metadata=1")


if __name__ == "__main__":
    main()
