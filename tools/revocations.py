#!/usr/bin/env python3
"""The revocation list (S7.7, ADR-0098 in hyaloslabs/hyalos): the releases proven malicious.

revocations.json, in this repository, lists each revoked archive by its digest, with a reason code:

    {"revoked": [{"digest": "<sha256 hex>", "reason": "malware.exfiltration"}], "version": 1}

Adding an entry is a pull request to main, so a code owner decides it. An entry is never removed: a
revocation is for good, and a pull request that drops one fails. Every release carries the list,
wrapped as

    {"kind": "hyalos.revocation_list", "revoked": [...], "version": 1}

and signed by release.yml as the pipeline, so its signed time is its issue time. Hyalos refuses to
install a revoked digest and disables an installed copy of one.

    revocations.py write <dist>               writes <dist>/revocations.json from the repository's
    revocations.py kept <base.json> <head.json>   exit 1 if <head> drops an entry <base> holds
    revocations.py due <new> [<old>]          exit 0 if <new> differs from the last release's <old>
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(ROOT, "revocations.json")
FILE = "revocations.json"
KIND = "hyalos.revocation_list"
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
# A reason is a code, as Hyalos's reason codes are: never free text.
REASON = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")


class Refused(Exception):
    pass


def check(doc):
    """The entries of a revocations.json document, sorted by digest, or Refused."""
    if not isinstance(doc, dict) or set(doc) != {"revoked", "version"} or doc["version"] != 1:
        raise Refused('revocations.json is {"revoked": [...], "version": 1}')
    if not isinstance(doc["revoked"], list):
        raise Refused("revoked is a list")
    seen = set()
    for entry in doc["revoked"]:
        if not isinstance(entry, dict) or set(entry) != {"digest", "reason"}:
            raise Refused('each entry is {"digest": ..., "reason": ...}')
        if not isinstance(entry["digest"], str) or not DIGEST.match(entry["digest"]):
            raise Refused("a digest is 64 lowercase hexadecimal characters")
        if not isinstance(entry["reason"], str) or not REASON.match(entry["reason"]):
            raise Refused("a reason is a code: a lowercase letter, then letters, digits, '_', '.' or '-'")
        if entry["digest"] in seen:
            raise Refused(f"{entry['digest']} is listed twice")
        seen.add(entry["digest"])
    return sorted(doc["revoked"], key=lambda e: e["digest"])


def load(path=SOURCE):
    with open(path) as f:
        return check(json.load(f))


def revoked(path=SOURCE):
    """The revoked digests."""
    return {e["digest"] for e in load(path)}


def wrap(entries):
    """The list as a release carries it: the same bytes for the same entries."""
    body = {"kind": KIND, "revoked": entries, "version": 1}
    return json.dumps(body, sort_keys=True, indent=2) + "\n"


def dropped(base, head):
    """Digests `base` revokes that `head` no longer does."""
    return sorted({e["digest"] for e in base} - {e["digest"] for e in head})


def main(argv):
    try:
        if len(argv) == 3 and argv[1] == "write":
            with open(os.path.join(argv[2], FILE), "x") as f:
                f.write(wrap(load()))
            print(f"revocations: {len(load())} revoked")
            return 0
        if len(argv) == 4 and argv[1] == "kept":
            gone = dropped(load(argv[2]), load(argv[3]))
            if gone:
                print(f"revocations: {', '.join(gone)} dropped; a revocation is for good", file=sys.stderr)
                return 1
            print("revocations: none dropped")
            return 0
        if len(argv) in (3, 4) and argv[1] == "due":
            with open(argv[2]) as f:
                new = f.read()
            if len(argv) == 3 or not os.path.exists(argv[3]):
                print("revocations: the last release has none")
                return 0
            with open(argv[3]) as f:
                old = f.read()
            if json.loads(new) != json.loads(old):
                print("revocations: changed since the last release")
                return 0
            print("revocations: unchanged")
            return 1
    except (Refused, OSError, ValueError) as e:
        print(f"revocations: {e}", file=sys.stderr)
        return 2
    print(__doc__.split("\n\n")[-1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
