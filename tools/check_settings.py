#!/usr/bin/env python3
"""Compares the repository's live protection settings with settings/expected.json.

With keyless signing there is no key: what reaches main is what the release pipeline signs, so the
settings that decide what reaches main are the trust anchor's protection (ADR-0095 in
hyaloslabs/hyalos). They live in GitHub, not in this repository, so nothing else notices one being
loosened. This reads them and names every one that differs:

- every ruleset on the repository, with its rules and conditions, and the time it was last changed;
- the Actions settings: which actions may run, the default token permissions, whether a workflow may
  approve a pull request, and which other repositories may use these workflows;
- who holds admin, the visibility, forking, and the environments.

It only reads. A setting it cannot read is an error, never a match.

GitHub shows a ruleset's bypass list only to a reader that can write to rulesets, which this check's
read-only token cannot. So each ruleset's last change time is pinned too: any edit to a ruleset,
its bypass list included, moves it and is drift. When the bypass list is visible (an admin's token,
as with --print), it is compared as well.

    check_settings.py <owner/repo>            exit 1 on drift, printing each difference
    check_settings.py <owner/repo> --print    print the live settings as expected.json holds them

The token is SETTINGS_READ_TOKEN. In settings.yml it is minted from the check's own GitHub App,
installed on this repository alone, with Actions, Administration and Metadata read-only and nothing
else. By hand, an admin's own token reads the same settings.
"""

import datetime
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"
EXPECTED = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "settings", "expected.json")


class Unreadable(Exception):
    """A setting that could not be read: never treated as a match."""


def get(path, token):
    request = urllib.request.Request(
        f"{API}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        # The status only, never the body or the token.
        status = getattr(e, "code", None)
        raise Unreadable(f"{path}: {'HTTP ' + str(status) if status else type(e).__name__}") from None


def changed_at(value):
    """A ruleset's updated_at in UTC. GitHub writes it in the reader's own offset."""
    try:
        at = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        raise Unreadable("a ruleset's last change time") from None
    if at.tzinfo is None:
        raise Unreadable("a ruleset's last change time") from None
    return at.astimezone(datetime.timezone.utc).isoformat(timespec="milliseconds")


def ruleset(full):
    """One ruleset as expected.json holds it. Its bypass list only when the token can see it."""
    out = {
        "name": full["name"],
        "source_type": full.get("source_type"),
        "target": full["target"],
        "enforcement": full["enforcement"],
        "conditions": full.get("conditions"),
        "rules": sorted(full["rules"], key=lambda rule: rule["type"]),
        # Every edit moves this, including one to the bypass list a read-only token cannot see.
        "updated_at": changed_at(full.get("updated_at")),
    }
    if "bypass_actors" in full:
        out["bypass_actors"] = sorted(
            full["bypass_actors"], key=lambda a: (a["actor_type"], str(a["actor_id"]))
        )
    return out


def comparable(expected, actual):
    """expected, less the bypass lists the token could not see. Their rulesets' change times stay."""
    hidden = {s["name"] for s in actual.get("rulesets", []) if "bypass_actors" not in s}
    out = json.loads(json.dumps(expected))
    for s in out.get("rulesets", []):
        if s.get("name") in hidden:
            s.pop("bypass_actors", None)
    return out


def live(repo, token):
    """The settings, in the shape expected.json holds them."""
    r = f"/repos/{repo}"
    rulesets = []
    for summary in get(f"{r}/rulesets?includes_parents=true&per_page=100", token):
        rulesets.append(ruleset(get(f"{r}/rulesets/{summary['id']}", token)))
    repository = get(r, token)
    admins = get(f"{r}/collaborators?affiliation=all&permission=admin&per_page=100", token)
    return {
        "repository": {
            "visibility": repository["visibility"],
            "allow_forking": repository.get("allow_forking"),
            "default_branch": repository["default_branch"],
        },
        "admins": sorted(a["login"] for a in admins),
        "rulesets": sorted(rulesets, key=lambda s: s["name"]),
        "actions": {
            "permissions": get(f"{r}/actions/permissions", token),
            "workflow": get(f"{r}/actions/permissions/workflow", token),
            "access": get(f"{r}/actions/permissions/access", token),
        },
        # An environment's branch rule is what keeps its secret from a pull request's workflow.
        "environments": sorted(
            (
                {
                    "name": e["name"],
                    "deployment_branch_policy": e.get("deployment_branch_policy"),
                    "protection_rules": sorted(p["type"] for p in e.get("protection_rules", [])),
                    "branches": sorted(
                        f"{p['type']}:{p['name']}"
                        for p in get(
                            f"{r}/environments/{e['name']}/deployment-branch-policies?per_page=100",
                            token,
                        ).get("branch_policies", [])
                    ),
                }
                for e in get(f"{r}/environments?per_page=100", token).get("environments", [])
            ),
            key=lambda e: e["name"],
        ),
    }


def differences(expected, actual, at=""):
    """Each path where the two differ, with both values."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        out = []
        for key in sorted(set(expected) | set(actual)):
            path = f"{at}.{key}" if at else key
            if key not in actual:
                out.append(f"{path}: expected {json.dumps(expected[key])}, now absent")
            elif key not in expected:
                out.append(f"{path}: not expected, now {json.dumps(actual[key])}")
            else:
                out.extend(differences(expected[key], actual[key], path))
        return out
    if isinstance(expected, list) and isinstance(actual, list) and len(expected) == len(actual):
        out = []
        for i, (e, a) in enumerate(zip(expected, actual)):
            out.extend(differences(e, a, f"{at}[{i}]"))
        return out
    if expected != actual:
        return [f"{at}: expected {json.dumps(expected)}, now {json.dumps(actual)}"]
    return []


def main(argv):
    if len(argv) not in (2, 3) or (len(argv) == 3 and argv[2] != "--print"):
        print("usage: check_settings.py <owner/repo> [--print]", file=sys.stderr)
        return 2
    token = os.environ.get("SETTINGS_READ_TOKEN", "")
    if not token:
        print("check_settings: SETTINGS_READ_TOKEN is not set, so nothing was checked", file=sys.stderr)
        return 1
    try:
        actual = live(argv[1], token)
    except Unreadable as e:
        print(f"check_settings: cannot read {e}, so nothing was checked", file=sys.stderr)
        return 1
    if len(argv) == 3:
        print(json.dumps(actual, indent=2, sort_keys=True))
        return 0
    with open(EXPECTED) as f:
        expected = json.load(f)
    found = differences(comparable(expected, actual), actual)
    for d in found:
        print(f"drift: {d}")
    if any(".updated_at" in d for d in found):
        print(
            "drift: a ruleset changed. Its bypass list may be what changed, and this token cannot see it: "
            "read it with an admin's token and --print"
        )
    if not found:
        print("check_settings: the settings are as expected")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
