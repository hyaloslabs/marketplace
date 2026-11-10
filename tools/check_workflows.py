#!/usr/bin/env python3
"""Fails if a workflow could sign as the release pipeline other than as intended.

Hyalos trusts what .github/workflows/release.yml signs when it runs for main (ADR-0094 in
hyaloslabs/hyalos). There is no key to guard, so this guards how that workflow can run and who in it
can ask for a signing token:

- release.yml runs only on a push to main: no pull request, no other repository calling it, no
  manual run with inputs;
- by default its jobs read contents only, and only its `sign` job can ask for an id-token;
- no other workflow can ask for an id-token or runs on pull_request_target;
- every action is pinned to a full commit.

    check_workflows.py [<workflows-dir>]
"""

import os
import re
import sys

import yaml

PINNED = re.compile(r"[^@\s]+@[0-9a-f]{40}\Z")


def problems(directory):
    out = []
    for file in sorted(os.listdir(directory)):
        if not file.endswith((".yml", ".yaml")):
            continue
        with open(os.path.join(directory, file)) as f:
            flow = yaml.safe_load(f)
        # YAML 1.1 reads the key `on` as true.
        triggers = flow.get("on", flow.get(True))
        jobs = flow.get("jobs", {})
        tokens = [
            name
            for name, job in jobs.items()
            if (
                isinstance(job.get("permissions"), dict)
                and job["permissions"].get("id-token") == "write"
            )
            or job.get("permissions") == "write-all"
        ]
        top = flow.get("permissions")
        if top == "write-all" or (isinstance(top, dict) and top.get("id-token") == "write"):
            tokens.append("(every job)")
        if triggers == "pull_request_target" or (
            isinstance(triggers, (dict, list)) and "pull_request_target" in triggers
        ):
            out.append(f"{file}: runs on pull_request_target")
        for name, job in jobs.items():
            if "uses" in job and not PINNED.match(job["uses"]) and not job["uses"].startswith("./"):
                out.append(f"{file}: job {name} calls {job['uses']}, not pinned to a commit")
            for step in job.get("steps", []):
                uses = step.get("uses")
                if uses and not PINNED.match(uses):
                    out.append(f"{file}: job {name} uses {uses}, not pinned to a commit")
        if file == "release.yml":
            if triggers != {"push": {"branches": ["main"]}}:
                out.append(f"release.yml: triggers are {triggers!r}, not only a push to main")
            if top != {"contents": "read"}:
                out.append(f"release.yml: default permissions are {top!r}, not contents: read")
            if tokens != ["sign"]:
                out.append(f"release.yml: {tokens} can ask for an id-token, not only sign")
        elif tokens:
            out.append(f"{file}: {tokens} can ask for an id-token")
    if "release.yml" not in os.listdir(directory):
        out.append("no release.yml")
    return out


def main(argv):
    directory = argv[1] if len(argv) > 1 else ".github/workflows"
    found = problems(directory)
    for p in found:
        print(f"check_workflows: {p}", file=sys.stderr)
    if not found:
        print("check_workflows: ok")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
