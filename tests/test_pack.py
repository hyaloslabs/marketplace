"""The packer, the build and the workflow check.

REFERENCE_DIGEST is pinned in Hyalos too (core/plugin/tests/reference_skill.rs, with the same
reference skill), so the two archive writers cannot drift apart: a change to either fails one side.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import build  # noqa: E402
import check_workflows  # noqa: E402
import pack  # noqa: E402

REFERENCE = os.path.join(ROOT, "tests", "reference", "hyalos-reference")
REFERENCE_DIGEST = "0d085c2a398d33d47f0d1e7143cd460e5bad558cf5b77a9137147a8e6f66f429"


class Pack(unittest.TestCase):
    def test_the_reference_skill_has_the_digest_hyalos_pins(self):
        name, data = pack.pack(REFERENCE)
        self.assertEqual(name, "hyalos-reference")
        self.assertEqual(hashlib.sha256(data).hexdigest(), REFERENCE_DIGEST)

    def test_what_hyalos_refuses_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = os.path.join(tmp, "s")
            shutil.copytree(REFERENCE, skill)
            os.symlink("/etc/passwd", os.path.join(skill, "passwd"))
            with self.assertRaises(pack.Refused):
                pack.pack(skill)
            os.remove(os.path.join(skill, "passwd"))
            open(os.path.join(skill, ".hidden"), "w").close()
            with self.assertRaises(pack.Refused):
                pack.pack(skill)
            os.remove(os.path.join(skill, ".hidden"))
            with open(os.path.join(skill, "SKILL.md"), "w") as f:
                f.write("---\nname: Not_Plain\n---\n")
            with self.assertRaises(pack.Refused):
                pack.pack(skill)

    def test_the_executable_bit_is_part_of_the_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = os.path.join(tmp, "s")
            shutil.copytree(REFERENCE, skill)
            os.chmod(os.path.join(skill, "scripts", "check.sh"), 0o644)
            _, data = pack.pack(skill)
            self.assertNotEqual(hashlib.sha256(data).hexdigest(), REFERENCE_DIGEST)


class Build(unittest.TestCase):
    def test_two_builds_write_the_same_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = os.path.join(tmp, "a"), os.path.join(tmp, "b")
            for out in (a, b):
                os.makedirs(out)
                build.build(ROOT, out)
            self.assertEqual(sorted(os.listdir(a)), sorted(os.listdir(b)))
            for file in os.listdir(a):
                with open(os.path.join(a, file), "rb") as x, open(os.path.join(b, file), "rb") as y:
                    self.assertEqual(x.read(), y.read(), file)


class Workflows(unittest.TestCase):
    def test_this_repositorys_workflows_pass(self):
        self.assertEqual(check_workflows.problems(os.path.join(ROOT, ".github", "workflows")), [])

    def check(self, release):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "release.yml"), "w") as f:
                f.write(release)
            return check_workflows.problems(tmp)

    def test_another_trigger_or_token_is_refused(self):
        good = (
            "on:\n  push:\n    branches: [main]\npermissions:\n  contents: read\n"
            "jobs:\n  sign:\n    permissions:\n      id-token: write\n    steps: []\n"
        )
        self.assertEqual(self.check(good), [])
        for bad in (
            good.replace("  push:\n    branches: [main]\n", "  workflow_call:\n"),
            good.replace("branches: [main]", "branches: [main, dev]"),
            good + "  build:\n    permissions:\n      id-token: write\n    steps: []\n",
            good.replace("  contents: read\n", "  contents: read\n  id-token: write\n"),
            good.replace("steps: []", "steps:\n      - uses: actions/checkout@v7"),
        ):
            self.assertNotEqual(self.check(bad), [], bad)


class SettingsToken(unittest.TestCase):
    def problems(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(os.path.join(ROOT, ".github", "workflows", "release.yml"), tmp)
            for name, text in files.items():
                with open(os.path.join(tmp, name), "w") as f:
                    f.write(text)
            return check_workflows.problems(tmp)

    def test_only_the_settings_check_holds_the_token_and_only_on_schedule(self):
        with open(os.path.join(ROOT, ".github", "workflows", "settings.yml")) as f:
            settings = f.read()
        self.assertEqual(self.problems({"settings.yml": settings}), [])
        borrowed = (
            "on: [pull_request]\npermissions:\n  contents: read\njobs:\n  leak:\n"
            "    environment: settings-check\n    steps:\n      - run: echo ${{ secrets.SETTINGS_READ_TOKEN }}\n"
        )
        self.assertNotEqual(self.problems({"settings.yml": settings, "ci.yml": borrowed}), [])
        for name in ("secrets.SETTINGS_APP_KEY", "vars.SETTINGS_APP_CLIENT_ID"):
            minted = (
                "on: [push]\npermissions:\n  contents: read\njobs:\n  leak:\n"
                f"    steps:\n      - run: echo ${{{{ {name} }}}}\n"
            )
            self.assertNotEqual(self.problems({"settings.yml": settings, "ci.yml": minted}), [], name)
        on_pr = settings.replace("  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request:\n")
        self.assertNotEqual(self.problems({"settings.yml": on_pr}), [])


class Settings(unittest.TestCase):
    def test_a_loosened_setting_is_named(self):
        import check_settings

        with open(check_settings.EXPECTED) as f:
            expected = json.load(f)
        self.assertEqual(check_settings.differences(expected, expected), [])
        loosened = json.loads(json.dumps(expected))
        loosened["rulesets"][0]["bypass_actors"].append(
            {"actor_id": 1, "actor_type": "Integration", "bypass_mode": "always"}
        )
        loosened["actions"]["workflow"]["default_workflow_permissions"] = "write"
        loosened["rulesets"][0]["rules"] = [r for r in loosened["rulesets"][0]["rules"] if r["type"] != "pull_request"]
        found = check_settings.differences(expected, loosened)
        self.assertTrue(any("bypass_actors" in d for d in found), found)
        self.assertTrue(any("default_workflow_permissions" in d for d in found), found)
        self.assertTrue(any(".rules" in d for d in found), found)

    def test_a_hidden_bypass_list_is_covered_by_the_change_time(self):
        import check_settings

        with open(check_settings.EXPECTED) as f:
            expected = json.load(f)
        # What a read-only token sees: the same ruleset, its bypass list left out.
        seen = json.loads(json.dumps(expected))
        for s in seen["rulesets"]:
            s.pop("bypass_actors")
        self.assertEqual(check_settings.differences(check_settings.comparable(expected, seen), seen), [])
        # Editing the bypass list moves the change time, which the token does see.
        seen["rulesets"][0]["updated_at"] = "2027-01-01T00:00:00.000+00:00"
        found = check_settings.differences(check_settings.comparable(expected, seen), seen)
        self.assertTrue(any(".updated_at" in d for d in found), found)
        # A visible bypass list is still compared.
        widened = json.loads(json.dumps(expected))
        widened["rulesets"][0]["bypass_actors"].append(
            {"actor_id": 1, "actor_type": "Integration", "bypass_mode": "always"}
        )
        found = check_settings.differences(check_settings.comparable(expected, widened), widened)
        self.assertTrue(any("bypass_actors" in d for d in found), found)

    def test_a_change_time_is_read_in_utc_or_not_at_all(self):
        import check_settings

        self.assertEqual(
            check_settings.changed_at("2026-11-09T19:05:33.079-06:00"),
            check_settings.changed_at("2026-11-10T01:05:33.079Z"),
        )
        for bad in (None, "", "yesterday", "2026-11-10T01:05:33"):
            with self.assertRaises(check_settings.Unreadable, msg=bad):
                check_settings.changed_at(bad)

    def test_no_visible_admin_is_unreadable(self):
        import check_settings

        real = check_settings.get

        def get(path, token):
            if "/rulesets" in path or "/collaborators" in path:
                return []
            if path == "/repos/hyaloslabs/marketplace":
                return {"visibility": "private", "default_branch": "main"}
            raise check_settings.Unreadable("not reached")

        check_settings.get = get
        try:
            with self.assertRaises(check_settings.Unreadable) as raised:
                check_settings.live("hyaloslabs/marketplace", "t")
        finally:
            check_settings.get = real
        self.assertIn("admins", str(raised.exception))

    def fake_app(self, permissions=None, repositories=("hyaloslabs/marketplace",)):
        """The App's answers, as GitHub gives them; and the calls made, to check the token is revoked."""
        import check_settings

        with open(check_settings.EXPECTED) as f:
            grant = json.load(f)["app"]["permissions"]
        calls = []

        def get(path, token, method="GET", body=None):
            calls.append((method, path, token, body))
            if path == "/app":
                return {"owner": {"login": "hyaloslabs"}, "permissions": grant, "events": []}
            if path.startswith("/app/installations?"):
                return [
                    {
                        "id": 7,
                        "account": {"login": "hyaloslabs"},
                        "repository_selection": "selected",
                        "permissions": permissions or grant,
                        "events": [],
                    }
                ]
            if path == "/app/installations/7/access_tokens":
                return {"token": "listing"}
            if path.startswith("/installation/repositories"):
                return {"repositories": [{"full_name": r} for r in repositories]}
            if path == "/installation/token":
                return None
            raise check_settings.Unreadable(path)

        return check_settings, get, calls

    def app_differences(self, **kw):
        check_settings, get, calls = self.fake_app(**kw)
        real = check_settings.get, check_settings.app_jwt
        check_settings.get, check_settings.app_jwt = get, lambda client_id, key: "jwt"
        try:
            actual = check_settings.app("Iv23", "key")
        finally:
            check_settings.get, check_settings.app_jwt = real
        with open(check_settings.EXPECTED) as f:
            expected = json.load(f)["app"]
        return check_settings.differences(expected, actual), calls

    def test_the_app_as_granted_matches(self):
        found, calls = self.app_differences()
        self.assertEqual(found, [])
        # The listing token asked for metadata only, and was revoked.
        self.assertIn(("POST", "/app/installations/7/access_tokens", "jwt", {"permissions": {"metadata": "read"}}), calls)
        self.assertIn(("DELETE", "/installation/token", "listing", None), calls)

    def test_a_widened_app_is_named(self):
        import check_settings

        with open(check_settings.EXPECTED) as f:
            wider = dict(json.load(f)["app"]["permissions"], administration="write")
        found, _ = self.app_differences(permissions=wider)
        self.assertTrue(any("installations[0].permissions.administration" in d for d in found), found)
        found, _ = self.app_differences(repositories=("hyaloslabs/marketplace", "hyaloslabs/hyalos"))
        self.assertTrue(any("installations[0].repositories" in d for d in found), found)

    def test_without_the_app_key_nothing_passes(self):
        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", "check_settings.py"), "hyaloslabs/marketplace"],
            capture_output=True,
            text=True,
            env={
                **{k: v for k, v in os.environ.items() if not k.startswith("SETTINGS_")},
                "SETTINGS_READ_TOKEN": "t",
            },
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("SETTINGS_APP_KEY are not both set", result.stderr)

    def test_without_a_token_nothing_passes(self):
        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", "check_settings.py"), "hyaloslabs/marketplace"],
            capture_output=True,
            env={k: v for k, v in os.environ.items() if k != "SETTINGS_READ_TOKEN"},
        )
        self.assertEqual(result.returncode, 1)


class Versions(unittest.TestCase):
    def test_a_changed_skill_needs_a_new_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, head = os.path.join(tmp, "base"), os.path.join(tmp, "head")
            with open(base, "w") as f:
                f.write("aa  hello-0.1.0.skill\n")
            with open(head, "w") as f:
                f.write("bb  hello-0.1.0.skill\n")
            run = lambda *a: subprocess.run(  # noqa: E731
                [sys.executable, os.path.join(ROOT, "tools", "versions.py"), *a],
                capture_output=True,
            ).returncode
            self.assertEqual(run(base, head), 1)
            with open(head, "w") as f:
                f.write("bb  hello-0.2.0.skill\n")
            self.assertEqual(run(base, head), 0)


if __name__ == "__main__":
    unittest.main()
