from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.correlate_osv import (
    correlate_sbom,
    default_output_path,
    extract_component_purls,
)


class CorrelateOsvTests(unittest.TestCase):
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
                    "name": "unversioned",
                    "purl": "pkg:pypi/unversioned",
                    "bom-ref": "pkg:pypi/unversioned",
                },
                {
                    "name": "duplicate",
                    "purl": "pkg:pypi/demo-pkg@1.2.3",
                    "bom-ref": "pkg:pypi/demo-pkg@1.2.3",
                },
            ],
        }

    def test_extract_component_purls_deduplicates_and_marks_queryable(self) -> None:
        components = extract_component_purls(self._sbom())

        self.assertEqual([c["purl"] for c in components], [
            "pkg:pypi/demo-pkg@1.2.3",
            "pkg:pypi/unversioned",
        ])
        self.assertEqual([c["queryable"] for c in components], [True, False])

    def test_correlate_sbom_flattens_osv_findings(self) -> None:
        osv_response = {
            "pkg:pypi/demo-pkg@1.2.3": [
                {"id": "GHSA-demo-0001", "modified": "2026-01-01T00:00:00Z"}
            ]
        }

        with patch("scripts.correlate_osv.query_osv_batch", return_value=osv_response):
            advisory = correlate_sbom(
                self._sbom(),
                source_sbom="local-advisory-channel/noarch/sboms/demo.cdx.json",
            )

        self.assertEqual(advisory["query_count"], 1)
        self.assertEqual(advisory["vulnerability_count"], 1)
        self.assertEqual(
            advisory["components"][0]["vulnerabilities"][0]["id"],
            "GHSA-demo-0001",
        )
        self.assertEqual(
            advisory["findings"][0]["component_purl"],
            "pkg:pypi/demo-pkg@1.2.3",
        )
        self.assertEqual(
            advisory["skipped_components"][0]["reason"],
            "component PURL is not versioned",
        )

    def test_default_output_path_uses_advisories_sibling(self) -> None:
        self.assertEqual(
            default_output_path(
                Path("local-advisory-channel/noarch/sboms/demo.conda.cdx.json")
            ),
            Path("local-advisory-channel/noarch/advisories/demo.conda.osv.json"),
        )


if __name__ == "__main__":
    unittest.main()
