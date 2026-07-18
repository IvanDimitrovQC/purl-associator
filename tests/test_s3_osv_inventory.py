from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.s3_osv_inventory import (
    filter_osv_inventory_paths,
    osv_inventory_payload,
    write_inventory,
)


class S3OsvInventoryTests(unittest.TestCase):
    def test_filter_osv_inventory_paths_keeps_advisories(self) -> None:
        paths = filter_osv_inventory_paths(
            [
                "channel-index.json",
                "noarch/sboms/demo/sbom-abc.cdx.json",
                "noarch/advisories/demo/osv-abc-def.json",
                "noarch/advisories/demo/notes.json",
            ]
        )

        self.assertEqual(
            paths,
            ["noarch/advisories/demo/osv-abc-def.json"],
        )

    def test_write_inventory_payload(self) -> None:
        object_paths = ["noarch/advisories/demo/osv-abc-def.json"]
        payload = osv_inventory_payload(
            s3_uri="s3://demo-bucket/prefix",
            object_paths=object_paths,
        )

        with tempfile.TemporaryDirectory() as tmp:
            out = write_inventory(payload=payload, out=Path(tmp) / "inventory.json")
            written = json.loads(out.read_text())

        self.assertEqual(written["s3_uri"], "s3://demo-bucket/prefix")
        self.assertEqual(written["object_count"], 1)
        self.assertEqual(written["advisory_count"], 1)
        self.assertEqual(written["objects"], object_paths)


if __name__ == "__main__":
    unittest.main()
