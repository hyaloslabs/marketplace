#!/usr/bin/env python3
"""Packs a skill directory into a Hyalos skill archive and prints its digest.

The archive is the format ADR-0090 (hyaloslabs/hyalos) defines, and its SHA-256 is the digest a
Hyalos install checks: the domain tag `hyalos.skill.v1\\n`, then for each file in path order the
path's length (4 bytes, big-endian), the path, 1 if it is executable or 0, the length of its bytes
(8 bytes, big-endian) and the bytes.

A directory is read with Hyalos's rules: plain names only, no links or special files, at most 256
files, 8 MiB and 8 levels, a SKILL.md naming the skill. What this packs, Hyalos reads byte for byte;
tests/test_pack.py holds the two to the same digest for a reference skill.

    pack.py <skill-dir> [<out-file>]
"""

import hashlib
import json
import os
import re
import stat
import struct
import sys

DOMAIN = b"hyalos.skill.v1\n"
MAX_FILES = 256
MAX_BYTES = 8 << 20
MAX_DEPTH = 8
MAX_PATH = 1024
PLAIN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}\Z")
MAX_NAME = 64
NAME = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*\Z")


class Refused(Exception):
    """A directory that is not a skill Hyalos would read."""


def read(root):
    """The skill's files as {path: (executable, bytes)}, refusing what Hyalos refuses."""
    if not stat.S_ISDIR(os.lstat(root).st_mode):
        raise Refused(f"{root}: not a directory")
    files = {}
    total = 0

    def walk(directory, prefix, depth):
        nonlocal total
        if depth >= MAX_DEPTH:
            raise Refused("deeper than a skill may be")
        with os.scandir(directory) as entries:
            for entry in entries:
                if not PLAIN.match(entry.name):
                    raise Refused(f"{prefix}{entry.name!r}: not a plain name")
                path = prefix + entry.name
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    walk(entry.path, path + "/", depth + 1)
                elif stat.S_ISREG(mode):
                    if len(files) >= MAX_FILES:
                        raise Refused("more files than a skill may hold")
                    if len(path) > MAX_PATH:
                        raise Refused(f"{path}: a path too long")
                    with open(entry.path, "rb") as handle:
                        data = handle.read(MAX_BYTES - total + 1)
                    total += len(data)
                    if total > MAX_BYTES:
                        raise Refused("larger than a skill may be")
                    files[path] = (bool(mode & 0o100), data)
                else:
                    raise Refused(f"{path}: a link or a special file")

    walk(root, "", 0)
    return files


def name_of(skill_md):
    """The `name` in SKILL.md's front matter, as Hyalos reads it."""
    lines = skill_md.decode("utf-8").splitlines()
    if not lines or lines[0].rstrip() != "---":
        raise Refused("SKILL.md has no front matter")
    for line in lines[1:]:
        line = line.rstrip()
        if line == "---":
            break
        if line.startswith("name:"):
            name = line[len("name:"):].strip()
            for quote in ('"', "'"):
                if len(name) >= 2 and name[0] == quote and name[-1] == quote:
                    name = name[1:-1]
                    break
            if NAME.match(name) and len(name) <= MAX_NAME:
                return name
            break
    raise Refused("SKILL.md's front matter names no skill in lowercase letters, digits and hyphens")


def archive(files):
    out = bytearray(DOMAIN)
    # Hyalos orders paths by their bytes; every name here is ASCII, so this is the same order.
    for path in sorted(files, key=lambda p: p.encode()):
        executable, data = files[path]
        encoded = path.encode()
        out += struct.pack(">I", len(encoded)) + encoded
        out += bytes([1 if executable else 0])
        out += struct.pack(">Q", len(data)) + data
    return bytes(out)


def pack(root):
    """(name, archive bytes) for the skill in `root`."""
    files = read(root)
    if "SKILL.md" not in files:
        raise Refused("no SKILL.md")
    name = name_of(files["SKILL.md"][1])
    if "capabilities.json" in files:
        asks = json.loads(files["capabilities.json"][1])
        if not isinstance(asks, dict) or asks.get("version") != 1:
            raise Refused("capabilities.json is not a capabilities document of version 1")
    return name, archive(files)


def main(argv):
    if len(argv) not in (2, 3):
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        return 2
    try:
        name, data = pack(argv[1])
    except (Refused, OSError, ValueError) as e:
        print(f"pack: {e}", file=sys.stderr)
        return 1
    if len(argv) == 3:
        with open(argv[2], "xb") as out:
            out.write(data)
    print(f"{name} {hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
