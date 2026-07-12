from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.advisory_index import (
    AdvisoryIndexState,
    SHARDS_DIR,
    build_indexes,
    build_indexes_from_s3,
)


class AdvisoryIndexTests(unittest.TestCase):
    def _sbom(self) -> dict:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "name": "demo",
                    "version": "1.2.3",
                    "purl": "pkg:conda/conda-forge/demo@1.2.3?subdir=noarch",
                    "properties": [
                        {"name": "conda:build", "value": "py_0"},
                        {"name": "sbom-generator:version", "value": "v1-sbom123"},
                        {
                            "name": "sbom-generator:input-sha256",
                            "value": "a" * 64,
                        },
                        {
                            "name": "purl-associator:mapping-sha256",
                            "value": "b" * 64,
                        },
                    ],
                }
            },
            "components": [
                {
                    "name": "demo-pkg",
                    "version": "1.2.3",
                    "purl": "pkg:pypi/demo-pkg@1.2.3",
                }
            ],
        }

    def _advisory(self) -> dict:
        return {
            "schema_version": 1,
            "correlation_version": "v1-osv123",
            "source_sbom": "noarch/sboms/demo/sbom-v1-sbom123.cdx.json",
            "subject": {
                "name": "demo",
                "version": "1.2.3",
                "purl": "pkg:conda/conda-forge/demo@1.2.3?subdir=noarch",
            },
            "query_count": 1,
            "vulnerability_count": 1,
            "findings": [
                {
                    "component_purl": "pkg:pypi/demo-pkg@1.2.3",
                    "vulnerability_id": "GHSA-demo-0001",
                }
            ],
        }

    def test_build_indexes_summarizes_sbom_and_osv_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            sbom_path = root / "noarch" / "sboms" / "demo.conda" / (
                "sbom-v1-sbom123.cdx.json"
            )
            advisory_path = root / "noarch" / "advisories" / "demo.conda" / (
                "osv-v1-sbom123-osv123.json"
            )
            sbom_path.parent.mkdir(parents=True)
            advisory_path.parent.mkdir(parents=True)
            sbom_path.write_text(json.dumps(self._sbom()) + "\n")
            advisory_path.write_text(json.dumps(self._advisory()) + "\n")

            paths = build_indexes(channel_root=root, channel="conda-forge")
            subdir_index = json.loads(
                (root / "noarch" / "advisory-repodata.json").read_text()
            )
            channel_index = json.loads((root / "channel-index.json").read_text())
            shard_entry = subdir_index["shards"]["demo"]
            shard = json.loads(
                (root / "noarch" / SHARDS_DIR / f"{shard_entry['sha256']}.json")
                .read_text()
            )

        record = shard["packages"]["demo.conda"]
        self.assertEqual(len(paths), 3)
        self.assertEqual(subdir_index["schema_version"], 2)
        self.assertNotIn("packages", subdir_index)
        self.assertEqual(subdir_index["package_name_count"], 1)
        self.assertEqual(shard["schema_version"], 1)
        self.assertEqual(shard["name"], "demo")
        self.assertEqual(channel_index["subdirs"]["noarch"]["package_count"], 1)
        self.assertTrue(channel_index["subdirs"]["noarch"]["sharded"])
        self.assertEqual(record["name"], "demo")
        self.assertEqual(record["sbom"]["version"], "v1-sbom123")
        self.assertEqual(record["sbom"]["component_purls"], ["pkg:pypi/demo-pkg@1.2.3"])
        self.assertEqual(record["osv"]["status"], "vulnerabilities_found")
        self.assertEqual(record["osv"]["finding_ids"], ["GHSA-demo-0001"])

    def test_advisory_index_state_loads_sharded_indexes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            sbom_path = root / "noarch" / "sboms" / "demo.conda" / (
                "sbom-v1-sbom123.cdx.json"
            )
            sbom_path.parent.mkdir(parents=True)
            sbom_path.write_text(json.dumps(self._sbom()) + "\n")
            build_indexes(channel_root=root, channel="conda-forge")

            state = AdvisoryIndexState.load(channel_root=root, channel="conda-forge")

        self.assertIn("noarch", state.subdirs)
        self.assertIn("demo.conda", state.subdirs["noarch"]["packages"])

    def test_build_indexes_from_s3_rebuilds_sharded_indexes(self) -> None:
        sbom_path = "noarch/sboms/demo.conda/sbom-v1-sbom123.cdx.json"
        advisory_path = "noarch/advisories/demo.conda/osv-v1-sbom123-osv123.json"
        payloads = {
            f"s3://demo-bucket/prefix/{sbom_path}": self._sbom(),
            f"s3://demo-bucket/prefix/{advisory_path}": self._advisory(),
        }
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
                                {"Key": f"prefix/{sbom_path}"},
                                {
                                    "Key": (
                                        "prefix/noarch/sboms/demo.conda/"
                                        "event-v1-sbom123.json"
                                    )
                                },
                                {"Key": f"prefix/{advisory_path}"},
                                {"Key": "prefix/noarch/advisory-repodata.json"},
                            ]
                        }
                    ),
                    "",
                )
            if "cp" in cmd:
                source = cmd[cmd.index("cp") + 1]
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    json.dumps(payloads[source]),
                    "",
                )
            return subprocess.CompletedProcess(cmd, 1, "", "unexpected command")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            paths = build_indexes_from_s3(
                channel_root=root,
                channel="conda-forge",
                s3_uri="s3://demo-bucket/prefix",
                workers=1,
                runner=runner,
            )
            subdir_index = json.loads(
                (root / "noarch" / "advisory-repodata.json").read_text()
            )

        self.assertEqual(len(paths), 3)
        self.assertIn("demo", subdir_index["shards"])
        self.assertEqual(sum(1 for call in calls if "list-objects-v2" in call), 1)
        self.assertEqual(sum(1 for call in calls if "cp" in call), 2)


if __name__ == "__main__":
    unittest.main()
