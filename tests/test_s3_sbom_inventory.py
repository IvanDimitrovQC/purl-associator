from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.s3_sbom_inventory import (
    filter_sbom_inventory_paths,
    sbom_inventory_payload,
    write_inventory,
)


class S3SbomInventoryTests(unittest.TestCase):
    def test_filter_sbom_inventory_paths_keeps_only_sboms(self) -> None:
        paths = filter_sbom_inventory_paths(
            [
                "channel-index.json",
                "noarch/sboms/demo/sbom-abc.cdx.json",
                "noarch/sboms/demo/event-abc.json",
                "noarch/advisories/demo/osv-abc-def.json",
            ]
        )

        self.assertEqual(
            paths,
            [
                "noarch/sboms/demo/sbom-abc.cdx.json",
            ],
        )

    def test_write_inventory_payload(self) -> None:
        object_paths = [
            "noarch/sboms/demo/sbom-abc.cdx.json",
        ]
        payload = sbom_inventory_payload(
            s3_uri="s3://demo-bucket/prefix",
            object_paths=object_paths,
        )

        with tempfile.TemporaryDirectory() as tmp:
            out = write_inventory(payload=payload, out=Path(tmp) / "inventory.json")
            written = json.loads(out.read_text())

        self.assertEqual(written["s3_uri"], "s3://demo-bucket/prefix")
        self.assertEqual(written["schema_version"], 2)
        self.assertEqual(written["object_count"], 1)
        self.assertEqual(written["sbom_count"], 1)
        self.assertNotIn("event_count", written)
        self.assertEqual(written["objects"], object_paths)


if __name__ == "__main__":
    unittest.main()
