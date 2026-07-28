from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.load_progress import ProgressTracker
from scripts.refresh_osv import (
    collect_queryable_purls,
    filter_s3_sbom_artifact_paths,
    load_s3_osv_inventory,
    refresh_osv,
    stage_s3_sboms,
)
from scripts.generate_sbom import build_security_sbom_artifact_bytes
from scripts.s3_publish import paths_present_in_inventory


class RefreshOsvTests(unittest.TestCase):
    def _sbom(self) -> dict:
        return {
            "bomFormat": "CycloneDX",
            "metadata": {
                "component": {
                    "name": "demo",
                    "version": "1.2.3",
                    "purl": "pkg:conda/conda-forge/demo@1.2.3?subdir=noarch",
                    "bom-ref": "pkg:conda/conda-forge/demo@1.2.3?subdir=noarch",
                }
            },
            "components": [
                {
                    "name": "demo-pkg",
                    "version": "1.2.3",
                    "purl": "pkg:pypi/demo-pkg@1.2.3",
                    "bom-ref": "pkg:pypi/demo-pkg@1.2.3",
                },
                {
                    "name": "demo-pkg-duplicate",
                    "version": "1.2.3",
                    "purl": "pkg:pypi/demo-pkg@1.2.3",
                    "bom-ref": "pkg:pypi/demo-pkg@1.2.3",
                },
            ],
        }

    def test_collect_queryable_purls_deduplicates_across_sboms(self) -> None:
        self.assertEqual(
            collect_queryable_purls([self._sbom(), self._sbom()]),
            ["pkg:pypi/demo-pkg@1.2.3"],
        )

    def test_refresh_osv_writes_only_new_advisory_versions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            sbom_path = (
                root
                / "noarch"
                / "sboms"
                / "demo-1.2.3-py_0.conda"
                / "sbom-abc123def456.cdx.json"
            )
            sbom_path.parent.mkdir(parents=True)
            sbom_path.write_text(json.dumps(self._sbom()) + "\n")
            osv_results = {
                "pkg:pypi/demo-pkg@1.2.3": [
                    {"id": "GHSA-demo-0001", "modified": "2026-01-01T00:00:00Z"}
                ]
            }
            published: list[Path] = []
            progress = ProgressTracker(
                path=Path(tmp) / "progress.json",
                load_type="osv-refresh",
            )

            with patch(
                "scripts.refresh_osv.query_osv_chunked", return_value=osv_results
            ):
                first = refresh_osv(
                    channel_root=root,
                    batch_size=10,
                    workers=2,
                    progress=progress,
                    on_output=published.append,
                )
                second = refresh_osv(channel_root=root, batch_size=10)
            progress_data = json.loads((Path(tmp) / "progress.json").read_text())

        self.assertEqual(first.scanned, 1)
        self.assertEqual(first.queried_purls, 1)
        self.assertEqual(first.written, 3)
        self.assertEqual(first.existing, 0)
        self.assertEqual(second.written, 0)
        self.assertEqual(second.existing, 3)
        self.assertEqual(
            sorted(path.parent.name for path in first.outputs),
            ["GHSA-demo-0001", "GHSA-demo-0001", "demo-1.2.3-py_0.advisories"],
        )
        self.assertEqual(first.outputs[-1].parent.name, "demo-1.2.3-py_0.advisories")
        self.assertRegex(first.outputs[-1].name, r"^[0-9a-f]{64}\.conda$")
        self.assertEqual(published, first.outputs)
        self.assertEqual(progress_data["counts"]["processed"], 1)

    def test_refresh_osv_reads_security_conda_sbom_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            artifact = build_security_sbom_artifact_bytes(sbom=self._sbom())
            artifact_sha256 = hashlib.sha256(artifact).hexdigest()
            sbom_path = (
                root
                / "noarch"
                / "demo-1.2.3-py_0.sboms"
                / f"{artifact_sha256}.conda"
            )
            sbom_path.parent.mkdir(parents=True)
            sbom_path.write_bytes(artifact)
            osv_results = {
                "pkg:pypi/demo-pkg@1.2.3": [
                    {"id": "GHSA-demo-0001", "modified": "2026-01-01T00:00:00Z"}
                ]
            }

            with patch(
                "scripts.refresh_osv.query_osv_chunked", return_value=osv_results
            ):
                result = refresh_osv(channel_root=root, batch_size=10)

        self.assertEqual(result.scanned, 1)
        self.assertEqual(result.queried_purls, 1)
        self.assertEqual(result.written, 3)
        self.assertIn(
            root / "cves" / "GHSA-demo-0001",
            {path.parent for path in result.outputs},
        )
        self.assertIn(
            root / "noarch" / "demo-1.2.3-py_0.matches" / "GHSA-demo-0001",
            {path.parent for path in result.outputs},
        )
        self.assertIn(
            root / "noarch" / "demo-1.2.3-py_0.advisories",
            {path.parent for path in result.outputs},
        )

    def test_s3_osv_inventory_matches_channel_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            advisory_path = (
                root
                / "noarch"
                / "advisories"
                / "demo-1.2.3-py_0.conda"
                / "osv-abc123def456-fedcba654321.json"
            )
            inventory_path = Path(tmp) / "inventory.json"
            inventory_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "objects": [
                            (
                                "noarch/advisories/demo-1.2.3-py_0.conda/"
                                "osv-abc123def456-fedcba654321.json"
                            )
                        ],
                    }
                )
                + "\n"
            )

            inventory = load_s3_osv_inventory(inventory_path)
            self.assertTrue(
                paths_present_in_inventory(
                    [advisory_path],
                    root=root,
                    inventory=inventory,
                )
            )

    def test_filter_s3_sbom_artifact_paths_excludes_events_and_indexes(self) -> None:
        artifact_path = f"noarch/demo-1.2.3-py_0.sboms/{'a' * 64}.conda"
        self.assertEqual(
            filter_s3_sbom_artifact_paths(
                [
                    "noarch/sboms/demo/sbom-abc.cdx.json",
                    artifact_path,
                    "noarch/sboms/demo/event-abc.json",
                    "noarch/demo-1.2.3-py_0.sboms/event-abc.json",
                    "noarch/advisory-channel.json",
                    "channel-index.json",
                ]
            ),
            [
                artifact_path,
                "noarch/sboms/demo/sbom-abc.cdx.json",
            ],
        )

    def test_stage_s3_sboms_downloads_filtered_objects(self) -> None:
        calls: list[list[str]] = []

        def runner(
            cmd: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            if "list-objects-v2" in cmd:
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    json.dumps(
                        {
                            "Contents": [
                                {
                                    "Key": (
                                        "prefix/noarch/sboms/demo/sbom-abc.cdx.json"
                                    )
                                },
                                {"Key": ("prefix/noarch/sboms/demo/event-abc.json")},
                            ]
                        }
                    ),
                    "",
                )
            if "cp" in cmd:
                target = Path(cmd[cmd.index("cp") + 2])
                target.write_text(json.dumps(self._sbom()) + "\n")
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 1, "", "unexpected command")

        with tempfile.TemporaryDirectory() as tmp:
            stage_root = Path(tmp) / "stage"
            staged = stage_s3_sboms(
                s3_uri="s3://demo-bucket/prefix",
                stage_root=stage_root,
                workers=1,
                runner=runner,
            )

            self.assertEqual(
                staged,
                [stage_root / "noarch" / "sboms" / "demo" / "sbom-abc.cdx.json"],
            )
            self.assertTrue(staged[0].exists())

        self.assertEqual(sum(1 for call in calls if "list-objects-v2" in call), 1)
        self.assertEqual(sum(1 for call in calls if "cp" in call), 1)


if __name__ == "__main__":
    unittest.main()
