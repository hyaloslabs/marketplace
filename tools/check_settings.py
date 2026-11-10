#!/usr/bin/env python3
"""Compares the repository's live protection settings with settings/expected.json.

With keyless signing there is no key: what reaches main is what the release pipeline signs, so the
settings that decide what reaches main are the trust anchor's protection (ADR-0095 in
hyaloslabs/hyalos). They live in GitHub, not in this repository, so nothing else notices one being
loosened. This reads them and names every one that differs:

- every ruleset on the repository, with its rules, conditions and bypass list;
- the Actions settings: which actions may run, the default token permissions, whether a workflow may
  approve a pull request, and which other repositories may use these workflows;
- who holds admin, the visibility, forking, and the environments.

It only reads. A setting it cannot read is an error, never a match.

    check_settings.py <owner/repo>            exit 1 on drift, printing each difference
    check_settings.py <owner/repo> --print    print the live settings as expected.json holds them

The token is SETTINGS_READ_TOKEN: a fine-grained token for this repository alone, with
Administration and Metadata read-only and nothing else.
"""

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


def live(repo, token):
    """The settings, in the shape expected.json holds them."""
    r = f"/repos/{repo}"
    rulesets = []
    for summary in get(f"{r}/rulesets?includes_parents=true&per_page=100", token):
        full = get(f"{r}/rulesets/{summary['id']}", token)
        if "bypass_actors" not in full:
            # GitHub leaves the bypass list out for a reader without admin read.
            raise Unreadable(f"ruleset {full.get('name')}: its bypass list is not visible to this token")
        rulesets.append(
            {
                "name": full["name"],
                "source_type": full.get("source_type"),
                "target": full["target"],
                "enforcement": full["enforcement"],
                "conditions": full.get("conditions"),
                "bypass_actors": sorted(
                    full["bypass_actors"], key=lambda a: (a["actor_type"], str(a["actor_id"]))
                ),
                "rules": sorted(full["rules"], key=lambda rule: rule["type"]),
            }
        )
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
    found = differences(expected, actual)
    for d in found:
        print(f"drift: {d}")
    if not found:
        print("check_settings: the settings are as expected")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
