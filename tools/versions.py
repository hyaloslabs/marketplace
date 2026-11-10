#!/usr/bin/env python3
"""Fails if a skill changed but kept its version.

Takes two DIGESTS files (base, then head) as tools/build.py writes them. An archive is named
<name>-<version>.skill, so the same name with another digest is a skill whose bytes changed under a
version already released, which an update check (ADR-0092 in hyaloslabs/hyalos) would never see.

    versions.py <base-DIGESTS> <head-DIGESTS>
"""

import sys


def read(path):
    with open(path) as f:
        return dict(reversed(line.rstrip("\n").split("  ", 1)) for line in f if line.strip())


def main(argv):
    if len(argv) != 3:
        print("usage: versions.py <base-DIGESTS> <head-DIGESTS>", file=sys.stderr)
        return 2
    base, head = read(argv[1]), read(argv[2])
    stale = sorted(a for a in head if a in base and base[a] != head[a])
    for artifact in stale:
        print(f"versions: {artifact} changed; give it a new version in versions.json", file=sys.stderr)
    if not stale:
        print("versions: ok")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
