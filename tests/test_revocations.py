"""The revocation list (S7.7, ADR-0098 in hyaloslabs/hyalos)."""

import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import build  # noqa: E402
import pack  # noqa: E402
import revocations  # noqa: E402

A = "a" * 64
B = "b" * 64


class Revocations(unittest.TestCase):
    def test_this_repositorys_list_is_valid(self):
        revocations.load()

    def test_a_list_is_wrapped_the_same_way_every_time(self):
        entries = revocations.check(
            {"version": 1, "revoked": [{"digest": B, "reason": "x"}, {"digest": A, "reason": "y"}]}
        )
        self.assertEqual([e["digest"] for e in entries], [A, B])
        body = json.loads(revocations.wrap(entries))
        self.assertEqual((body["kind"], body["version"]), ("hyalos.revocation_list", 1))
        self.assertEqual(revocations.wrap(entries), revocations.wrap(list(reversed(entries))[::-1]))

    def test_what_is_not_a_list_is_refused(self):
        for bad in (
            {"version": 2, "revoked": []},
            {"version": 1},
            {"version": 1, "revoked": [], "extra": 1},
            {"version": 1, "revoked": [{"digest": A.upper(), "reason": "x"}]},
            {"version": 1, "revoked": [{"digest": A[:63], "reason": "x"}]},
            {"version": 1, "revoked": [{"digest": A, "reason": "Free text, not a code"}]},
            {"version": 1, "revoked": [{"digest": A, "reason": "x", "note": "y"}]},
            {"version": 1, "revoked": [{"digest": A, "reason": "x"}, {"digest": A, "reason": "y"}]},
        ):
            with self.assertRaises(revocations.Refused, msg=bad):
                revocations.check(bad)

    def test_a_revocation_is_never_dropped(self):
        one = [{"digest": A, "reason": "x"}]
        two = one + [{"digest": B, "reason": "y"}]
        self.assertEqual(revocations.dropped(one, two), [])
        self.assertEqual(revocations.dropped(two, one), [B])

    def test_a_revoked_skill_does_not_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "repo")
            shutil.copytree(os.path.join(ROOT, "skills"), os.path.join(root, "skills"))
            shutil.copy(os.path.join(ROOT, "versions.json"), root)
            shutil.copy(os.path.join(ROOT, "revocations.json"), root)
            out = os.path.join(tmp, "out")
            os.makedirs(out)
            built = build.build(root, out)
            with open(os.path.join(root, "revocations.json"), "w") as f:
                json.dump({"version": 1, "revoked": [{"digest": built[0][3], "reason": "x"}]}, f)
            again = os.path.join(tmp, "again")
            os.makedirs(again)
            with self.assertRaises(pack.Refused):
                build.build(root, again)


if __name__ == "__main__":
    unittest.main()
