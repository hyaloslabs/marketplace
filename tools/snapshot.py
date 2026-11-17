#!/usr/bin/env python3
"""Sigstore's trusted root, fetched through TUF, as the snapshot Hyalos imports (ADR-0007, ADR-0097
in hyaloslabs/hyalos).

    snapshot.py fetch <dir>           writes <dir>/trusted-root.json
    snapshot.py due <new> [<old>]     exit 0 if <new> should be published: <old> is missing, holds
                                      another trusted root, or is older than REFRESH_DAYS by the
                                      SNAPSHOT_PUBLISHED_AT environment variable (ISO 8601); 1 if not

fetch needs python-tuf (tools/requirements-snapshot.txt). It starts from trust/sigstore-tuf-root.json,
Sigstore's TUF root version 16, and walks forward through each newer root Sigstore has signed. TUF
refuses a root that does not chain, metadata that has expired or rolled back, and a target whose
length or hashes are not the ones its signed metadata gives. What it downloads must then be a trusted
root at all, and is wrapped as

    {"kind": "hyalos.trusted_root_snapshot", "trusted_root": {...}, "version": 1}

release.yml signs that file as the pipeline. The signature's signed time is the snapshot's issue
time, which Hyalos compares to decide which of two snapshots is newer and how old one is.
"""

import datetime
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TUF_ROOT = os.path.join(ROOT, "trust", "sigstore-tuf-root.json")
TUF_URL = "https://tuf-repo-cdn.sigstore.dev"
TARGET = "trusted_root.json"
FILE = "trusted-root.json"
KIND = "hyalos.trusted_root_snapshot"
MEDIA_TYPE = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

# A snapshot unchanged for this long is published again, so its signed time stays well inside the
# 90 days Hyalos accepts by default.
REFRESH_DAYS = 30


def check(root):
    """`root` if it is a Sigstore trusted root Hyalos reads, listing every kind of authority."""
    if not isinstance(root, dict) or root.get("mediaType") != MEDIA_TYPE:
        raise ValueError(f"not a Sigstore trusted root of media type {MEDIA_TYPE}")
    for field in ("tlogs", "certificateAuthorities", "ctlogs"):
        if not isinstance(root.get(field), list) or not root[field]:
            raise ValueError(f"the trusted root lists no {field}")
    return root


def wrap(root):
    """The snapshot file for `root`: the same bytes for the same root."""
    body = {"kind": KIND, "trusted_root": check(root), "version": 1}
    return json.dumps(body, sort_keys=True, indent=2) + "\n"


def unwrap(text):
    """The trusted root a snapshot file holds."""
    body = json.loads(text)
    if not isinstance(body, dict) or body.get("kind") != KIND or body.get("version") != 1:
        raise ValueError("not a trusted-root snapshot of version 1")
    return check(body.get("trusted_root"))


def fetch(directory):
    """Fetches the trusted root through TUF and writes the snapshot into `directory`."""
    from tuf.ngclient import Updater

    with tempfile.TemporaryDirectory() as tmp:
        metadata = os.path.join(tmp, "metadata")
        targets = os.path.join(tmp, "targets")
        os.makedirs(metadata)
        os.makedirs(targets)
        shutil.copyfile(TUF_ROOT, os.path.join(metadata, "root.json"))
        updater = Updater(
            metadata_dir=metadata,
            metadata_base_url=TUF_URL,
            target_dir=targets,
            target_base_url=f"{TUF_URL}/targets/",
        )
        updater.refresh()
        info = updater.get_targetinfo(TARGET)
        if info is None:
            raise ValueError(f"Sigstore's TUF repository lists no {TARGET}")
        with open(updater.download_target(info)) as f:
            root = json.load(f)
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, FILE), "w") as f:
        f.write(wrap(root))


def due(new, old, published_at, now):
    """Whether the snapshot `new` should be published, against the last one published, `old`, at
    `published_at`."""
    if old is None or published_at is None:
        return True
    if unwrap(new) != unwrap(old):
        return True
    return now - published_at >= datetime.timedelta(days=REFRESH_DAYS)


def main(argv):
    if len(argv) == 3 and argv[1] == "fetch":
        fetch(argv[2])
        print(f"snapshot: wrote {os.path.join(argv[2], FILE)}")
        return 0
    if len(argv) in (3, 4) and argv[1] == "due":
        with open(argv[2]) as f:
            new = f.read()
        old = None
        if len(argv) == 4 and os.path.exists(argv[3]):
            with open(argv[3]) as f:
                old = f.read()
        at = os.environ.get("SNAPSHOT_PUBLISHED_AT")
        published_at = datetime.datetime.fromisoformat(at.replace("Z", "+00:00")) if at else None
        now = datetime.datetime.now(datetime.timezone.utc)
        if due(new, old, published_at, now):
            print("snapshot: due to be published")
            return 0
        print("snapshot: unchanged and recent")
        return 1
    print(__doc__.split("\n\n")[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
