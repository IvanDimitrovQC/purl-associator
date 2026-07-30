from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.correlate_osv import SECURITY_CVE_SCHEMA, security_payload_semantic_hash
from scripts.generate_sbom import SECURITY_CVE_PAYLOAD_NAME, build_security_artifact_bytes
from scripts.s3_osv_inventory import (
    is_cve_artifact_path,
    is_match_artifact_path,
    filter_osv_inventory_paths,
    filter_osv_related_inventory_paths,
    osv_inventory_payload,
    read_s3_osv_metadata,
    write_inventory,
)


class S3OsvInventoryTests(unittest.TestCase):
    def test_classifies_split_security_artifact_paths(self) -> None:
        self.assertTrue(is_cve_artifact_path(f"cves/CVE-1/{'a' * 64}.conda"))
        self.assertTrue(
            is_match_artifact_path(
                f"noarch/demo-1.2.3-py_0.matches/CVE-1/{'b' * 64}.conda"
            )
        )
        self.assertFalse(
            is_match_artifact_path(
                f"noarch/demo-1.2.3-py_0.advisories/{'c' * 64}.conda"
            )
        )

    def test_filter_osv_inventory_paths_keeps_advisories(self) -> None:
        paths = filter_osv_inventory_paths(
            [
                "channel-index.json",
                "noarch/sboms/demo/sbom-abc.cdx.json",
                "noarch/advisories/demo/osv-abc-def.json",
                f"noarch/demo-1.2.3-py_0.advisories/{'a' * 64}.conda",
                f"noarch/demo-1.2.3-py_0.matches/CVE-1/{'b' * 64}.conda",
                f"cves/CVE-1/{'c' * 64}.conda",
                "noarch/advisories/demo/notes.json",
            ]
        )

        self.assertEqual(
            paths,
            [
                "noarch/advisories/demo/osv-abc-def.json",
                f"noarch/demo-1.2.3-py_0.advisories/{'a' * 64}.conda",
            ],
        )

    def test_filter_osv_related_inventory_paths_keeps_cves_matches_and_advisories(
        self,
    ) -> None:
        paths = filter_osv_related_inventory_paths(
            [
                "channel-index.json",
                f"cves/CVE-1/{'a' * 64}.conda",
                f"noarch/demo-1.2.3-py_0.matches/CVE-1/{'b' * 64}.conda",
                f"noarch/demo-1.2.3-py_0.advisories/{'c' * 64}.conda",
            ]
        )

        self.assertEqual(
            paths,
            [
                f"cves/CVE-1/{'a' * 64}.conda",
                f"noarch/demo-1.2.3-py_0.advisories/{'c' * 64}.conda",
                f"noarch/demo-1.2.3-py_0.matches/CVE-1/{'b' * 64}.conda",
            ],
        )

    def test_write_inventory_payload(self) -> None:
        object_paths = [
            "noarch/advisories/demo/osv-abc-def.json",
            f"cves/CVE-1/{'a' * 64}.conda",
        ]
        payload = osv_inventory_payload(
            s3_uri="s3://demo-bucket/prefix",
            object_paths=object_paths,
        )

        with tempfile.TemporaryDirectory() as tmp:
            out = write_inventory(payload=payload, out=Path(tmp) / "inventory.json")
            written = json.loads(out.read_text())

        self.assertEqual(written["s3_uri"], "s3://demo-bucket/prefix")
        self.assertEqual(written["schema_version"], 2)
        self.assertEqual(written["object_count"], 2)
        self.assertEqual(written["cve_count"], 1)
        self.assertEqual(written["match_count"], 0)
        self.assertEqual(written["advisory_count"], 1)
        self.assertEqual(written["objects"], object_paths)

    def test_read_s3_osv_metadata_reads_security_container(self) -> None:
        payload = {
            "schema_version": 1,
            "id": "GHSA-demo-0001",
            "url": "https://osv.dev/vulnerability/GHSA-demo-0001",
            "source": {"name": "osv.dev"},
            "modified": "2026-01-01T00:00:00Z",
            "osv": {"id": "GHSA-demo-0001", "modified": "2026-01-01T00:00:00Z"},
        }
        artifact = build_security_artifact_bytes(
            payload=payload,
            kind="CVE",
            data_schema=SECURITY_CVE_SCHEMA,
            payload_name=SECURITY_CVE_PAYLOAD_NAME,
            created_on=1767225600,
        )

        def runner(
            cmd: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            return subprocess.CompletedProcess(cmd, 0, artifact, b"")

        path, metadata = read_s3_osv_metadata(
            relative_path=f"cves/GHSA-demo-0001/{'a' * 64}.conda",
            s3_uri="s3://demo-bucket/prefix",
            runner=runner,
        )

        self.assertEqual(path, f"cves/GHSA-demo-0001/{'a' * 64}.conda")
        self.assertEqual(metadata["artifact_dir"], "cves/GHSA-demo-0001")
        self.assertEqual(metadata["kind"], "CVE")
        self.assertEqual(
            metadata["semantic_version"],
            security_payload_semantic_hash(
                payload,
                kind="CVE",
                data_schema=SECURITY_CVE_SCHEMA,
            ),
        )

    def test_inventory_payload_includes_logical_artifacts(self) -> None:
        path = f"cves/CVE-1/{'a' * 64}.conda"
        payload = osv_inventory_payload(
            s3_uri="s3://demo-bucket/prefix",
            object_paths=[path],
            osv_metadata={
                path: {
                    "path": path,
                    "artifact_dir": "cves/CVE-1",
                    "kind": "CVE",
                    "semantic_version": "semantic-a",
                }
            },
        )

        self.assertEqual(payload["schema_version"], 3)
        self.assertEqual(
            payload["logical_artifacts"],
            {"cves/CVE-1": {"semantic-a": path}},
        )


if __name__ == "__main__":
    unittest.main()
