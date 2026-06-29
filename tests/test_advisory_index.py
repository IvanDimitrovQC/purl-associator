from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.advisory_index import build_indexes


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
            subdir_index = json.loads((root / "noarch" / "advisory-repodata.json").read_text())
            channel_index = json.loads((root / "channel-index.json").read_text())

        record = subdir_index["packages"]["demo.conda"]
        self.assertEqual(len(paths), 2)
        self.assertEqual(channel_index["subdirs"]["noarch"]["package_count"], 1)
        self.assertEqual(record["name"], "demo")
        self.assertEqual(record["sbom"]["version"], "v1-sbom123")
        self.assertEqual(record["sbom"]["component_purls"], ["pkg:pypi/demo-pkg@1.2.3"])
        self.assertEqual(record["osv"]["status"], "vulnerabilities_found")
        self.assertEqual(record["osv"]["finding_ids"], ["GHSA-demo-0001"])


if __name__ == "__main__":
    unittest.main()
