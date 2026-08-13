import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mpvm_jira.mpvm import latest_snapshot, save_snapshot


class SnapshotTests(unittest.TestCase):
    def test_save_and_find_latest_by_names(self):
        payload = {"schema_version": 1, "assets": []}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            older = save_snapshot(
                base,
                payload,
                datetime(2026, 8, 4, 23, 59, 59, tzinfo=timezone.utc),
            )
            newest = save_snapshot(
                base,
                payload,
                datetime(2026, 8, 5, 1, 2, 3, tzinfo=timezone.utc),
            )
            (base / "05.08.2026" / "ignore.json").write_text(
                "{}", encoding="utf-8"
            )
            self.assertNotEqual(older, newest)
            self.assertEqual(latest_snapshot(base), newest)
            self.assertEqual(
                json.loads(newest.read_text(encoding="utf-8")), payload
            )


if __name__ == "__main__":
    unittest.main()
