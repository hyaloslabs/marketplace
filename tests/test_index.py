"""The index is written before signing, and nothing is published without its bundles."""

import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import index  # noqa: E402

with open(os.path.join(ROOT, "versions.json")) as versions:
    NAME, VERSION = next(iter(json.load(versions).items()))
ARTIFACT = f"{NAME}-{VERSION}.skill"
DIGEST = "a" * 64


class SignedIndex(unittest.TestCase):
    def setUp(self):
        self.dist = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dist)
        with open(os.path.join(self.dist, "DIGESTS"), "w") as f:
            f.write(f"{DIGEST}  {ARTIFACT}\n")

    def touch(self, name):
        with open(os.path.join(self.dist, name), "w"):
            pass

    def test_the_index_is_written_before_any_bundle_exists(self):
        self.assertEqual(index.main(["index.py", self.dist]), 0)
        with open(os.path.join(self.dist, "index.json")) as f:
            entry = json.load(f)["plugins"][NAME][0]
        self.assertEqual((entry["version"], entry["digest"]), (VERSION, DIGEST))
        self.assertEqual(entry["bundle"], f"{ARTIFACT}.sigstore.json")

    def test_nothing_is_signed_until_the_index_and_each_archive_have_bundles(self):
        index.main(["index.py", self.dist])
        self.assertEqual(
            index.unsigned(self.dist),
            ["index.json.sigstore.json", f"{ARTIFACT}.sigstore.json"],
        )
        self.assertEqual(index.main(["index.py", "signed", self.dist]), 1)
        self.touch(f"{ARTIFACT}.sigstore.json")
        self.assertEqual(index.main(["index.py", "signed", self.dist]), 1, "the index is unsigned")
        self.touch("index.json.sigstore.json")
        self.assertEqual(index.main(["index.py", "signed", self.dist]), 0)

    def test_a_skill_changed_under_a_released_version_is_still_refused(self):
        previous = os.path.join(self.dist, "previous.json")
        with open(previous, "w") as f:
            json.dump({"plugins": {NAME: [{"version": VERSION, "digest": "b" * 64}]}}, f)
        self.assertEqual(index.main(["index.py", self.dist, "--previous", previous]), 1)
        self.assertFalse(os.path.exists(os.path.join(self.dist, "index.json")))


if __name__ == "__main__":
    unittest.main()
