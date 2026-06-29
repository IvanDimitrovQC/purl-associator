from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.load_progress import ProgressTracker


class LoadProgressTests(unittest.TestCase):
    def test_progress_tracker_writes_updates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "progress.json"
            tracker = ProgressTracker(
                path=path,
                load_type="sbom-refresh",
                metadata={"s3_uri": "s3://demo-bucket/prefix"},
            )
            tracker.update(
                totals={"selected": 2},
                counts={"processed": 1},
                current={"package": "demo"},
            )
            tracker.complete()

            data = json.loads(path.read_text())

        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["load_type"], "sbom-refresh")
        self.assertEqual(data["status"], "complete")
        self.assertEqual(data["metadata"]["s3_uri"], "s3://demo-bucket/prefix")
        self.assertEqual(data["totals"]["selected"], 2)
        self.assertEqual(data["counts"]["processed"], 1)
        self.assertIsNone(data["current"])


if __name__ == "__main__":
    unittest.main()
