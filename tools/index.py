#!/usr/bin/env python3
"""Writes <dist>/index.json, the plugin index ADR-0090 (hyaloslabs/hyalos) defines, from <dist>/DIGESTS.

Each skill is listed at the version this release built, with its digest, its archive and its
Sigstore bundle beside the index. A release's index lists only its own versions; an earlier version
stays installable from the release that built it (its tag's download location).

With --previous <index.json>, the index of the release before this one, a skill whose version is
unchanged but whose digest is not is refused: a changed skill needs a new version.

The index is written before the sign job, which signs it as the pipeline so that every version and
digest it lists is signed (hyaloslabs/hyalos#378). `signed` then checks, before publishing, that the
index and every archive it lists have their bundles.

    index.py <dist> [--previous <index.json>]
    index.py signed <dist>
"""

import json
import os
import sys


def digests(dist):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "versions.json")) as f:
        by_artifact = {f"{n}-{v}.skill": (n, v) for n, v in json.load(f).items()}
    entries = {}
    with open(os.path.join(dist, "DIGESTS")) as f:
        for line in f:
            digest, artifact = line.rstrip("\n").split("  ", 1)
            name, version = by_artifact[artifact]
            entries[name] = {
                "version": version,
                "digest": digest,
                "artifact": artifact,
                "bundle": f"{artifact}.sigstore.json",
            }
    return entries


def changed_without_a_version(entries, previous):
    """Names whose version is the previous release's but whose digest is not."""
    out = []
    for name, entry in sorted(entries.items()):
        for old in previous.get("plugins", {}).get(name, []):
            if old["version"] == entry["version"] and old["digest"] != entry["digest"]:
                out.append(name)
    return out


def unsigned(dist):
    """The bundles the index at `dist` needs and does not have, its own first."""
    with open(os.path.join(dist, "index.json")) as f:
        index = json.load(f)
    wanted = ["index.json.sigstore.json"] + [
        entry["bundle"] for versions in index["plugins"].values() for entry in versions
    ]
    return [b for b in wanted if not os.path.isfile(os.path.join(dist, b))]


def main(argv):
    if len(argv) == 3 and argv[1] == "signed":
        missing = unsigned(argv[2])
        for bundle in missing:
            print(f"index: {bundle} is missing: the index and every archive are signed", file=sys.stderr)
        return 1 if missing else 0
    if len(argv) not in (2, 4) or (len(argv) == 4 and argv[2] != "--previous"):
        print("usage: index.py <dist> [--previous <index.json>] | index.py signed <dist>", file=sys.stderr)
        return 2
    entries = digests(argv[1])
    if len(argv) == 4:
        with open(argv[3]) as f:
            previous = json.load(f)
        stale = changed_without_a_version(entries, previous)
        if stale:
            print(
                f"index: {', '.join(stale)} changed but kept its version; give it a new one in versions.json",
                file=sys.stderr,
            )
            return 1
    index = {"version": 1, "plugins": {n: [e] for n, e in sorted(entries.items())}}
    with open(os.path.join(argv[1], "index.json"), "x") as f:
        json.dump(index, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"index: {len(entries)} skill(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
