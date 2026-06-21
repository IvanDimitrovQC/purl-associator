from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.generate_sbom import (
    add_version_to_purl,
    build_cyclonedx_sbom,
    generate_sbom,
    load_mapping_entry,
)


class GenerateSbomTests(unittest.TestCase):
    def _write_demo_mapping(self, root: Path) -> tuple[Path, Path]:
        mapping_dir = root / "web" / "public"
        detail_dir = mapping_dir / "mapping_packages"
        detail_dir.mkdir(parents=True)

        index = {
            "schema_version": 2,
            "packages": {
                "demo": {
                    "name": "demo",
                    "detail_path": "mapping_packages/aa.json",
                }
            },
        }
        detail = {
            "schema_version": 1,
            "packages": {
                "demo": {
                    "name": "demo",
                    "version": "1.2.3",
                    "build": "py_0",
                    "subdir": "noarch",
                    "url": (
                        "https://conda.anaconda.org/conda-forge/noarch/"
                        "demo-1.2.3-py_0.conda"
                    ),
                    "purl": "pkg:pypi/demo-pkg",
                    "type": "pypi",
                    "pkg_name": "demo-pkg",
                    "confidence": 0.99,
                    "sources": ["recipe-source", "parselmouth-artifact"],
                    "auto_verified": True,
                    "status": "verified",
                    "source": "manual",
                }
            },
        }
        index_path = mapping_dir / "mappings-index.json"
        detail_path = detail_dir / "aa.json"
        index_path.write_text(json.dumps(index) + "\n")
        detail_path.write_text(json.dumps(detail) + "\n")
        return index_path, root / "missing-auto.json"

    def _write_demo_repodata(self, root: Path) -> Path:
        repodata = {
            "packages.conda": {
                "demo-1.2.3-py_0.conda": {
                    "name": "demo",
                    "version": "1.2.3",
                    "build": "py_0",
                    "build_number": 0,
                    "depends": ["python >=3.12"],
                    "license": "MIT",
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                }
            }
        }
        path = root / "repodata.json"
        path.write_text(json.dumps(repodata) + "\n")
        return path

    def test_load_mapping_from_split_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index_path, payload_path = self._write_demo_mapping(root)

            entry = load_mapping_entry(
                "demo", mapping_index=index_path, mapping_payload=payload_path
            )

        self.assertEqual(entry["purl"], "pkg:pypi/demo-pkg")
        self.assertEqual(entry["subdir"], "noarch")

    def test_generate_sbom_from_repodata_and_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index_path, payload_path = self._write_demo_mapping(root)
            repodata_path = self._write_demo_repodata(root)

            filename, subdir, sbom = generate_sbom(
                package="demo",
                version=None,
                build=None,
                subdir=None,
                filename=None,
                channel="conda-forge",
                repodata_ref=str(repodata_path),
                mapping_index=index_path,
                mapping_payload=payload_path,
                purl_type_filter="pypi",
            )

        subject = sbom["metadata"]["component"]
        upstream = sbom["components"][0]
        self.assertEqual(filename, "demo-1.2.3-py_0.conda")
        self.assertEqual(subdir, "noarch")
        self.assertEqual(
            subject["purl"],
            "pkg:conda/conda-forge/demo@1.2.3?subdir=noarch&build=py_0",
        )
        self.assertEqual(subject["hashes"][0]["alg"], "SHA-256")
        self.assertEqual(subject["licenses"][0]["license"]["name"], "MIT")
        self.assertEqual(upstream["purl"], "pkg:pypi/demo-pkg@1.2.3")
        self.assertEqual(
            sbom["dependencies"][0]["dependsOn"],
            ["pkg:pypi/demo-pkg@1.2.3"],
        )

    def test_add_version_to_purl_preserves_qualifiers_and_subpath(self) -> None:
        self.assertEqual(
            add_version_to_purl("pkg:pypi/demo?repository_url=x#src", "1.2.3"),
            "pkg:pypi/demo@1.2.3?repository_url=x#src",
        )
        self.assertEqual(
            add_version_to_purl("pkg:pypi/demo@1.0.0", "1.2.3"),
            "pkg:pypi/demo@1.0.0",
        )

    def test_build_cyclonedx_rejects_missing_mapping_purl(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "does not have a mapped PURL"):
            build_cyclonedx_sbom(
                mapping={"name": "demo"},
                record={"name": "demo", "version": "1.2.3"},
                filename="demo-1.2.3-py_0.conda",
                channel="conda-forge",
                subdir="noarch",
            )


if __name__ == "__main__":
    unittest.main()
