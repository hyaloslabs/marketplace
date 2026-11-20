#!/usr/bin/env python3
"""Compares the repository's live protection settings with settings/expected.json.

With keyless signing there is no key: what reaches main is what the release pipeline signs, so the
settings that decide what reaches main are the trust anchor's protection (ADR-0095 in
hyaloslabs/hyalos). They live in GitHub, not in this repository, so nothing else notices one being
loosened. This reads them and names every one that differs:

- every ruleset on the repository, with its rules and conditions, and the time it was last changed;
- the Actions settings: which actions may run, the default token permissions, whether a workflow may
  approve a pull request, and which other repositories may use these workflows;
- who holds admin, the visibility, forking, and the environments;
- the check's own App: its permissions and events, and for each installation, its grant and the
  repositories it covers (ADR-0096 in hyaloslabs/hyalos), so a widened App is drift too.

It only reads. A setting it cannot read is an error, never a match.

GitHub shows a ruleset's bypass list only to a reader that can write to rulesets, which this check's
read-only token cannot. So each ruleset's last change time is pinned too: any edit to a ruleset,
its bypass list included, moves it and is drift. When the bypass list is visible (an admin's token,
as with --print), it is compared as well.

    check_settings.py <owner/repo>            exit 1 on drift, printing each difference
    check_settings.py <owner/repo> --print    print the live settings as expected.json holds them

The token is SETTINGS_READ_TOKEN. In settings.yml it is minted from the check's own GitHub App,
installed on this repository alone, with Actions, Administration and Metadata read-only, and the
organization's Members read-only so that organization owners show among the admins, and nothing
else. By hand, an admin's own token reads the same settings.

The App is read as the App, from SETTINGS_APP_CLIENT_ID and SETTINGS_APP_KEY. Without them the
check cannot read it, which is an error. --print without them keeps the file's `app` section and
says so.
"""

import base64
import datetime
import json
import os
import subprocess
import time
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"
EXPECTED = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "settings", "expected.json")


class Unreadable(Exception):
    """A setting that could not be read: never treated as a match."""


def get(path, token, method="GET", body=None):
    request = urllib.request.Request(
        f"{API}{path}",
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else None
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


def app_jwt(client_id, key):
    """A ten-minute JWT for the App, signed by openssl. The key reaches openssl through a pipe only."""
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=")

    now = int(time.time())
    signing = part({"alg": "RS256", "typ": "JWT"}) + b"." + part({"iat": now - 60, "exp": now + 540, "iss": client_id})
    read, write = os.pipe()
    try:
        os.write(write, key.encode())
        os.close(write)
        write = None
        signed = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", f"/dev/fd/{read}"],
            input=signing,
            capture_output=True,
            pass_fds=(read,),
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        raise Unreadable("the App: its key could not be used") from None
    finally:
        os.close(read)
        if write is not None:
            os.close(write)
    if signed.returncode != 0 or not signed.stdout:
        # openssl's own message could quote the key's file; say only that it failed.
        raise Unreadable("the App: its key could not be used")
    return (signing + b"." + base64.urlsafe_b64encode(signed.stdout).rstrip(b"=")).decode()


def app(client_id, key):
    """The App's own grant: what it asks for, and what each installation gave it, where."""
    jwt = app_jwt(client_id, key)
    me = get("/app", jwt)
    installations = []
    for i in get("/app/installations?per_page=100", jwt):
        # A token for this installation that can read metadata and nothing else, only to list the
        # repositories it covers, revoked at once.
        token = get(
            f"/app/installations/{i['id']}/access_tokens", jwt, "POST", {"permissions": {"metadata": "read"}}
        )["token"]
        try:
            repositories = get("/installation/repositories?per_page=100", token)["repositories"]
        finally:
            try:
                get("/installation/token", token, "DELETE")
            except Unreadable:
                pass  # It expires within the hour anyway.
        installations.append(
            {
                "account": i["account"]["login"],
                "repository_selection": i["repository_selection"],
                "permissions": i["permissions"],
                "events": sorted(i.get("events", [])),
                "repositories": sorted(r["full_name"] for r in repositories),
            }
        )
    return {
        "owner": me["owner"]["login"],
        "permissions": me["permissions"],
        "events": sorted(me.get("events", [])),
        "installations": sorted(installations, key=lambda i: i["account"]),
    }


def live(repo, token):
    """The settings, in the shape expected.json holds them."""
    r = f"/repos/{repo}"
    rulesets = []
    for summary in get(f"{r}/rulesets?includes_parents=true&per_page=100", token):
        rulesets.append(ruleset(get(f"{r}/rulesets/{summary['id']}", token)))
    repository = get(r, token)
    admins = get(f"{r}/collaborators?affiliation=all&permission=admin&per_page=100", token)
    if not admins:
        # A repository always has an admin. None means the token cannot see them, which for an
        # organization's owners takes Members read.
        raise Unreadable("the repository's admins: none are visible to this token")
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
            # GitHub keeps an access level only for a private or internal repository, and refuses
            # to read one for a public repository. Visibility is compared too, so a switch back
            # to private is drift and the access level is read again.
            "access": (
                None
                if repository["visibility"] == "public"
                else get(f"{r}/actions/permissions/access", token)
            ),
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
    printing = len(argv) == 3
    token = os.environ.get("SETTINGS_READ_TOKEN", "")
    if not token:
        print("check_settings: SETTINGS_READ_TOKEN is not set, so nothing was checked", file=sys.stderr)
        return 1
    client_id = os.environ.get("SETTINGS_APP_CLIENT_ID", "")
    key = os.environ.get("SETTINGS_APP_KEY", "")
    with open(EXPECTED) as f:
        expected = json.load(f)
    if not printing and not (client_id and key):
        print(
            "check_settings: SETTINGS_APP_CLIENT_ID and SETTINGS_APP_KEY are not both set, so nothing was checked",
            file=sys.stderr,
        )
        return 1
    try:
        actual = live(argv[1], token)
        if client_id and key:
            actual["app"] = app(client_id, key)
        elif "app" in expected:
            actual["app"] = expected["app"]
            print("check_settings: the App was not read (no SETTINGS_APP_KEY); its section is the file's", file=sys.stderr)
    except Unreadable as e:
        print(f"check_settings: cannot read {e}, so nothing was checked", file=sys.stderr)
        return 1
    except (KeyError, TypeError, IndexError):
        # An answer of a shape this does not know. Not its contents: they may hold a token.
        print("check_settings: cannot read an answer of an unexpected shape, so nothing was checked", file=sys.stderr)
        return 1
    if printing:
        print(json.dumps(actual, indent=2, sort_keys=True))
        return 0
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
