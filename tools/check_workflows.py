#!/usr/bin/env python3
"""Fails if a workflow could sign as the release pipeline other than as intended.

Hyalos trusts what .github/workflows/release.yml signs when it runs for main (ADR-0094 in
hyaloslabs/hyalos). There is no key to guard, so this guards how that workflow can run and who in it
can ask for a signing token:

- release.yml runs only on a push to main and on its schedule: no pull request, no other repository
  calling it, no manual run with inputs;
- by default its jobs read contents only, and only its `sign` job can ask for an id-token;
- no other workflow can ask for an id-token or runs on pull_request_target;
- every action is pinned to a full commit;
- only settings.yml's check job names the settings app's key, its client ID, the token minted from
  them or their environment, and settings.yml runs only on its schedule or by hand (ADR-0095).

    check_workflows.py [<workflows-dir>]
"""

import os
import re
import sys

import yaml

# What only settings.yml's check job may name (ADR-0095).
SETTINGS_NAMES = ("SETTINGS_APP_KEY", "SETTINGS_APP_CLIENT_ID", "SETTINGS_READ_TOKEN", "settings-check")

PINNED = re.compile(r"[^@\s]+@[0-9a-f]{40}\Z")


def release_triggers_ok(triggers):
    """A push to main, and optionally a schedule of cron lines and nothing else (ADR-0097). A
    scheduled run runs the default branch's own file, so it signs as the same identity; anything
    that lets another ref or caller run the file does not."""
    if not isinstance(triggers, dict) or set(triggers) - {"push", "schedule"}:
        return False
    if triggers.get("push") != {"branches": ["main"]}:
        return False
    schedule = triggers.get("schedule", [])
    return isinstance(schedule, list) and all(
        isinstance(s, dict) and set(s) == {"cron"} and isinstance(s["cron"], str) for s in schedule
    )


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
        # The settings token reaches one job, which runs only on its schedule or by hand (ADR-0095).
        for name, job in jobs.items():
            if file == "settings.yml" and name == "check":
                continue
            text = yaml.safe_dump(job)
            if any(n in text for n in SETTINGS_NAMES):
                out.append(f"{file}: job {name} names the settings app, its token or its environment")
        outside = yaml.safe_dump({k: v for k, v in flow.items() if k != "jobs"})
        if any(n in outside for n in SETTINGS_NAMES):
            out.append(f"{file}: names the settings app, its token or its environment outside a job")
        if file == "settings.yml":
            if not isinstance(triggers, dict) or set(triggers) - {"schedule", "workflow_dispatch"}:
                out.append(f"settings.yml: triggers are {triggers!r}, not only its schedule and by hand")
            if triggers.get("workflow_dispatch") if isinstance(triggers, dict) else None:
                out.append("settings.yml: a manual run takes no inputs")
        if file == "release.yml":
            if not release_triggers_ok(triggers):
                out.append(
                    f"release.yml: triggers are {triggers!r}, not only a push to main and a schedule"
                )
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
