from __future__ import annotations

import hashlib
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
from scripts.generate_sbom import (
    build_security_sbom_artifact_bytes,
    write_versioned_sbom,
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
                        {"name": "sbom-generator:version", "value": "sbom123"},
                        {
                            "name": "sbom-generator:input-sha256",
                            "value": "a" * 64,
                        },
                        {
                            "name": "purl-associator:mapping-sha256",
                            "value": "b" * 64,
                        },
                        {
                            "name": "conda:filename",
                            "value": "demo-1.2.3-py_0.conda",
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
            "correlation_version": "osv123",
            "source_sbom": "noarch/demo-1.2.3-py_0.sboms/placeholder.conda",
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
                    "component_name": "demo-pkg",
                    "component_version": "1.2.3",
                    "vulnerability_id": "GHSA-demo-0001",
                    "modified": "2026-01-01T00:00:00Z",
                }
            ],
            "components": [
                {
                    "name": "demo-pkg",
                    "version": "1.2.3",
                    "purl": "pkg:pypi/demo-pkg@1.2.3",
                    "vulnerabilities": [
                        {
                            "id": "GHSA-demo-0001",
                            "modified": "2026-01-01T00:00:00Z",
                            "database_specific": {"severity": "MODERATE"},
                        }
                    ],
                }
            ],
        }

    def _write_security_sbom(self, root: Path) -> Path:
        path, _created = write_versioned_sbom(
            sbom=self._sbom(),
            root=root,
            subdir="noarch",
            filename="demo-1.2.3-py_0.conda",
        )
        return path

    def test_build_indexes_summarizes_sbom_and_osv_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            sbom_path = self._write_security_sbom(root)
            advisory_path = root / "noarch" / "advisories" / (
                "demo-1.2.3-py_0.conda"
            ) / "osv-sbom123-osv123.json"
            advisory_path.parent.mkdir(parents=True)
            advisory_path.write_text(json.dumps(self._advisory()) + "\n")

            paths = build_indexes(channel_root=root, channel="conda-forge")
            subdir_index = json.loads(
                (root / "noarch" / "advisory-channel.json").read_text()
            )
            channel_index = json.loads((root / "channel-index.json").read_text())
            shard_entry = subdir_index["shards"]["demo"]
            shard = json.loads(
                (root / "noarch" / SHARDS_DIR / f"{shard_entry['sha256']}.json")
                .read_text()
            )
            relative_sbom_path = f"noarch/demo-1.2.3-py_0.sboms/{sbom_path.name}"
            sbom_sha256 = sbom_path.stem
            sbom_size = sbom_path.stat().st_size

        record = shard["packages.conda"]["demo-1.2.3-py_0.conda"]
        sbom_record = record["sboms"]["sbom.v1"]
        self.assertEqual(len(paths), 3)
        self.assertEqual(subdir_index["schema_version"], 1)
        self.assertEqual(subdir_index["info"]["subdir"], "noarch")
        self.assertEqual(
            subdir_index["advisory_base_urls"]["shards"],
            "advisory-channel-shards/",
        )
        self.assertNotIn("packages", subdir_index)
        self.assertEqual(subdir_index["package_name_count"], 1)
        self.assertEqual(shard["schema_version"], 1)
        self.assertEqual(shard["shard_format"], "advisory-channel-shards-v1")
        self.assertEqual(shard["package"], "demo")
        self.assertIn("packages.conda", shard)
        self.assertNotIn("packages", shard)
        self.assertEqual(
            channel_index["subdirs"]["noarch"]["index"],
            "noarch/advisory-channel.json",
        )
        self.assertEqual(channel_index["subdirs"]["noarch"]["package_count"], 1)
        self.assertTrue(channel_index["subdirs"]["noarch"]["sharded"])
        self.assertEqual(record["name"], "demo")
        self.assertEqual(sbom_record["current"], relative_sbom_path)
        self.assertEqual(sbom_record["sha256"], sbom_sha256)
        self.assertEqual(sbom_record["size"], sbom_size)
        self.assertEqual(sbom_record["version"], "sbom123")
        self.assertEqual(sbom_record["component_purls"], ["pkg:pypi/demo-pkg@1.2.3"])
        self.assertEqual(record["osv"]["status"], "vulnerabilities_found")
        self.assertEqual(record["osv"]["finding_ids"], ["GHSA-demo-0001"])
        self.assertEqual(record["osv"]["vulnerabilities"][0]["id"], "GHSA-demo-0001")
        self.assertEqual(record["osv"]["vulnerabilities"][0]["severity"], "MEDIUM")

    def test_advisory_index_state_loads_sharded_indexes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            self._write_security_sbom(root)
            build_indexes(channel_root=root, channel="conda-forge")

            state = AdvisoryIndexState.load(channel_root=root, channel="conda-forge")

        self.assertIn("noarch", state.subdirs)
        self.assertIn("demo-1.2.3-py_0.conda", state.subdirs["noarch"]["packages"])

    def test_build_indexes_from_s3_rebuilds_sharded_indexes(self) -> None:
        sbom_artifact = build_security_sbom_artifact_bytes(sbom=self._sbom())
        artifact_sha256 = hashlib.sha256(sbom_artifact).hexdigest()
        sbom_path = f"noarch/demo-1.2.3-py_0.sboms/{artifact_sha256}.conda"
        advisory_path = (
            "noarch/advisories/demo-1.2.3-py_0.conda/osv-sbom123-osv123.json"
        )
        payloads = {
            f"s3://demo-bucket/prefix/{sbom_path}": sbom_artifact,
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
                                        "prefix/noarch/demo-1.2.3-py_0.sboms/"
                                        "event-sbom123.json"
                                    )
                                },
                                {"Key": f"prefix/{advisory_path}"},
                                {"Key": "prefix/noarch/advisory-channel.json"},
                            ]
                        }
                    ),
                    "",
                )
            if "cp" in cmd:
                source = cmd[cmd.index("cp") + 1]
                payload = payloads[source]
                if isinstance(payload, bytes):
                    return subprocess.CompletedProcess(cmd, 0, payload, b"")
                return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")
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
                (root / "noarch" / "advisory-channel.json").read_text()
            )
            shard_entry = subdir_index["shards"]["demo"]
            shard = json.loads(
                (root / "noarch" / SHARDS_DIR / f"{shard_entry['sha256']}.json")
                .read_text()
            )

        self.assertEqual(len(paths), 3)
        self.assertIn("demo", subdir_index["shards"])
        record = shard["packages.conda"]["demo-1.2.3-py_0.conda"]
        self.assertEqual(record["sboms"]["sbom.v1"]["sha256"], artifact_sha256)
        self.assertEqual(record["sboms"]["sbom.v1"]["size"], len(sbom_artifact))
        self.assertEqual(sum(1 for call in calls if "list-objects-v2" in call), 1)
        self.assertEqual(sum(1 for call in calls if "cp" in call), 2)


if __name__ == "__main__":
    unittest.main()
