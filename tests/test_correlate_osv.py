from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from scripts.correlate_osv import (
    advisory_content_hash,
    correlate_sbom,
    default_output_path,
    extract_component_purls,
    finalized_advisory,
    query_osv_chunked,
    versioned_output_path,
    write_advisory,
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
        self.assertEqual(advisory["schema_version"], 2)
        self.assertEqual(advisory["vulnerability_count"], 1)
        self.assertEqual(
            advisory["components"][0]["vulnerabilities"][0]["id"],
            "GHSA-demo-0001",
        )
        self.assertEqual(
            advisory["components"][0]["vulnerabilities"][0]["url"],
            "https://osv.dev/vulnerability/GHSA-demo-0001",
        )
        self.assertEqual(
            advisory["findings"][0]["component_purl"],
            "pkg:pypi/demo-pkg@1.2.3",
        )
        self.assertEqual(
            advisory["findings"][0]["url"],
            "https://osv.dev/vulnerability/GHSA-demo-0001",
        )
        self.assertEqual(
            advisory["skipped_components"][0]["reason"],
            "component PURL is not versioned",
        )

    def test_query_osv_chunked_hydrates_unique_vulnerability_details(self) -> None:
        query_responses = [
            {
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-demo-0001",
                                "modified": "2026-01-01T00:00:00Z",
                            }
                        ]
                    }
                ]
            },
            {
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-demo-0001",
                                "modified": "2026-01-01T00:00:00Z",
                            }
                        ]
                    }
                ]
            },
        ]
        details = {
            "GHSA-demo-0001": {
                "id": "GHSA-demo-0001",
                "modified": "2026-01-02T00:00:00Z",
                "database_specific": {"severity": "HIGH"},
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                ],
            }
        }

        with (
            patch("scripts.correlate_osv._post_json", side_effect=query_responses),
            patch(
                "scripts.correlate_osv.query_osv_vulnerabilities",
                return_value=details,
            ) as detail_mock,
        ):
            results = query_osv_chunked(
                ["pkg:pypi/a@1", "pkg:pypi/b@1"],
                batch_size=1,
                detail_workers=4,
            )

        detail_mock.assert_called_once()
        self.assertEqual(detail_mock.call_args.args[0], ["GHSA-demo-0001"])
        self.assertEqual(
            results["pkg:pypi/a@1"][0]["severity"][0]["type"],
            "CVSS_V3",
        )
        self.assertEqual(
            results["pkg:pypi/a@1"][0]["modified"],
            "2026-01-02T00:00:00Z",
        )

    def test_default_output_path_uses_advisories_sibling(self) -> None:
        self.assertEqual(
            default_output_path(
                Path("local-advisory-channel/noarch/sboms/demo.conda.cdx.json")
            ),
            Path("local-advisory-channel/noarch/advisories/demo.conda.osv.json"),
        )

    def test_default_output_path_uses_versioned_advisory_path(self) -> None:
        self.assertEqual(
            default_output_path(
                Path(
                    "local-advisory-channel/noarch/sboms/"
                    "demo-1.2.3-py_0.conda/sbom-abc123def456.cdx.json"
                )
            ),
            Path(
                "local-advisory-channel/noarch/advisories/"
                "demo-1.2.3-py_0.conda/osv-abc123def456.json"
            ),
        )

    def test_versioned_output_path_includes_advisory_content_hash(self) -> None:
        advisory = {
            "schema_version": 1,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "source_sbom": "demo",
            "components": [],
        }
        advisory_hash = advisory_content_hash(advisory)

        self.assertEqual(
            versioned_output_path(
                Path(
                    "local-advisory-channel/noarch/sboms/"
                    "demo-1.2.3-py_0.conda/sbom-abc123def456.cdx.json"
                ),
                advisory,
            ),
            Path(
                "local-advisory-channel/noarch/advisories/"
                f"demo-1.2.3-py_0.conda/osv-abc123def456-{advisory_hash}.json"
            ),
        )

    def test_write_advisory_is_idempotent_for_same_content(self) -> None:
        advisory = {
            "schema_version": 1,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "source_sbom": "demo",
            "components": [],
        }
        same_content = {**advisory, "generated_at": "2026-01-02T00:00:00+00:00"}

        self.assertEqual(advisory_content_hash(advisory), advisory_content_hash(same_content))

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "osv.json"
            first_path, first_created = write_advisory(advisory, out)
            second_path, second_created = write_advisory(same_content, out)
            written = finalized_advisory(advisory)

        self.assertEqual(first_path, second_path)
        self.assertTrue(first_created)
        self.assertFalse(second_created)
        self.assertRegex(written["correlation_version"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
