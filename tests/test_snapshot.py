"""The trusted-root snapshot (S7.11, ADR-0097 in hyaloslabs/hyalos): what is wrapped, and when it is
published. Fetching it needs the network and python-tuf, so release.yml and ci.yml do that."""

import datetime
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import snapshot  # noqa: E402

ROOT_DOC = {
    "mediaType": snapshot.MEDIA_TYPE,
    "tlogs": [{"baseUrl": "https://rekor.example"}],
    "certificateAuthorities": [{"uri": "https://fulcio.example"}],
    "ctlogs": [{"baseUrl": "https://ctfe.example"}],
}
NOW = datetime.datetime(2026, 11, 16, tzinfo=datetime.timezone.utc)


class Snapshot(unittest.TestCase):
    def test_a_root_is_wrapped_the_same_way_every_time(self):
        text = snapshot.wrap(ROOT_DOC)
        self.assertEqual(text, snapshot.wrap(json.loads(json.dumps(ROOT_DOC))))
        body = json.loads(text)
        self.assertEqual((body["kind"], body["version"]), ("hyalos.trusted_root_snapshot", 1))
        self.assertEqual(snapshot.unwrap(text), ROOT_DOC)

    def test_what_is_not_a_trusted_root_is_refused(self):
        for bad in (
            {**ROOT_DOC, "mediaType": "application/json"},
            {**ROOT_DOC, "tlogs": []},
            {k: v for k, v in ROOT_DOC.items() if k != "certificateAuthorities"},
            {**ROOT_DOC, "ctlogs": "none"},
            [],
        ):
            with self.assertRaises(ValueError):
                snapshot.wrap(bad)
        with self.assertRaises(ValueError):
            snapshot.unwrap(json.dumps({"kind": "other", "version": 1, "trusted_root": ROOT_DOC}))
        with self.assertRaises(ValueError):
            snapshot.unwrap(json.dumps({"kind": snapshot.KIND, "version": 2, "trusted_root": ROOT_DOC}))

    def test_a_snapshot_is_due_when_new_changed_or_old(self):
        same = snapshot.wrap(ROOT_DOC)
        other = snapshot.wrap({**ROOT_DOC, "tlogs": [{"baseUrl": "https://rekor2.example"}]})
        days = lambda n: NOW - datetime.timedelta(days=n)  # noqa: E731
        self.assertTrue(snapshot.due(same, None, None, NOW))
        self.assertTrue(snapshot.due(same, same, None, NOW))
        self.assertTrue(snapshot.due(other, same, days(1), NOW))
        self.assertFalse(snapshot.due(same, same, days(1), NOW))
        self.assertFalse(snapshot.due(same, same, days(snapshot.REFRESH_DAYS - 1), NOW))
        self.assertTrue(snapshot.due(same, same, days(snapshot.REFRESH_DAYS), NOW))

    def test_the_pinned_tuf_root_is_sigstores(self):
        with open(snapshot.TUF_ROOT) as f:
            signed = json.load(f)["signed"]
        self.assertEqual(signed["_type"], "root")
        self.assertGreaterEqual(signed["version"], 16)
        self.assertTrue(signed["consistent_snapshot"])


if __name__ == "__main__":
    unittest.main()
