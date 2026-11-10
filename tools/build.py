#!/usr/bin/env python3
"""Builds every skill under skills/ into <out>/<name>-<version>.skill and writes <out>/DIGESTS.

A build reads only the repository: no clock, no network, no environment, so two builds of one
commit write the same bytes (S7.1). The release pipeline builds twice on different runner images and
signs only when the two agree.

Each directory under skills/ is one skill, named by its SKILL.md and listed in versions.json with its
version. A skill missing from versions.json, a version for no skill, or a directory named other than
its skill is refused.

    build.py <out-dir>
"""

import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pack  # noqa: E402

VERSION = re.compile(r"[A-Za-z0-9.+-]{1,64}\Z")


def build(root, out):
    """[(name, version, artifact, digest)], sorted by name, with each archive written to `out`."""
    with open(os.path.join(root, "versions.json"), "rb") as f:
        versions = json.load(f)
    if not isinstance(versions, dict):
        raise pack.Refused("versions.json is not an object of name to version")
    skills_dir = os.path.join(root, "skills")
    names = sorted(e.name for e in os.scandir(skills_dir) if e.is_dir(follow_symlinks=False))
    if sorted(versions) != names:
        raise pack.Refused(
            f"versions.json lists {sorted(versions)}, skills/ holds {names}: each needs the other"
        )
    built = []
    for directory in names:
        name, data = pack.pack(os.path.join(skills_dir, directory))
        if name != directory:
            raise pack.Refused(f"skills/{directory} names itself {name}")
        version = versions[name]
        if not isinstance(version, str) or not VERSION.match(version):
            raise pack.Refused(f"{name}: a version is 1 to 64 letters, digits, '.', '+' and '-'")
        artifact = f"{name}-{version}.skill"
        with open(os.path.join(out, artifact), "xb") as f:
            f.write(data)
        built.append((name, version, artifact, hashlib.sha256(data).hexdigest()))
    return built


def main(argv):
    if len(argv) != 2:
        print("usage: build.py <out-dir>", file=sys.stderr)
        return 2
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(argv[1], exist_ok=False)
    try:
        built = build(root, argv[1])
    except (pack.Refused, OSError, ValueError) as e:
        print(f"build: {e}", file=sys.stderr)
        return 1
    with open(os.path.join(argv[1], "DIGESTS"), "x") as f:
        for name, version, artifact, digest in built:
            f.write(f"{digest}  {artifact}\n")
            print(f"{name} {version} {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
