from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.generate_sbom import (
    SECURITY_METADATA_NAME,
    SECURITY_SBOM_PAYLOAD_NAME,
    add_version_to_purl,
    build_cyclonedx_sbom,
    generate_sbom,
    generate_sbom_from_mapping,
    get_sbom_version,
    load_mapping_entry,
    load_mapping_entry_file,
    sbom_output_path,
    write_versioned_sbom,
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
        self.assertRegex(get_sbom_version(sbom), r"^[0-9a-f]{64}$")

    def test_generate_sbom_from_mapping_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _index_path, _payload_path = self._write_demo_mapping(root)
            repodata_path = self._write_demo_repodata(root)
            entry_path = root / "entry.json"
            entry_path.write_text(
                json.dumps(
                    {
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
                    }
                )
                + "\n"
            )

            filename, subdir, sbom = generate_sbom_from_mapping(
                load_mapping_entry_file(entry_path),
                version=None,
                build=None,
                subdir=None,
                filename=None,
                channel="conda-forge",
                repodata_ref=str(repodata_path),
                purl_type_filter="pypi",
            )

        self.assertEqual(filename, "demo-1.2.3-py_0.conda")
        self.assertEqual(subdir, "noarch")
        self.assertEqual(sbom["components"][0]["purl"], "pkg:pypi/demo-pkg@1.2.3")

    def test_write_versioned_sbom_creates_security_conda_artifact(self) -> None:
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

            first_path, first_created = write_versioned_sbom(
                sbom=sbom, root=root / "channel", subdir=subdir, filename=filename
            )
            second_path, second_created = write_versioned_sbom(
                sbom=sbom, root=root / "channel", subdir=subdir, filename=filename
            )
            version = get_sbom_version(sbom)
            expected_sbom_path = sbom_output_path(
                root / "channel",
                subdir="noarch",
                filename="demo-1.2.3-py_0.conda",
                version=first_path.stem,
            )
            with zipfile.ZipFile(first_path) as artifact:
                names = sorted(artifact.namelist())
                security = json.loads(artifact.read(SECURITY_METADATA_NAME))
                payload_bytes = artifact.read(SECURITY_SBOM_PAYLOAD_NAME)
                payload = json.loads(payload_bytes)

            self.assertEqual(first_path, second_path)
            self.assertTrue(first_created)
            self.assertFalse(second_created)
            self.assertEqual(first_path, expected_sbom_path)
            self.assertRegex(first_path.stem, r"^[0-9a-f]{64}$")
            self.assertEqual(
                first_path.parent,
                root / "channel" / "noarch" / "demo-1.2.3-py_0.sboms",
            )
            self.assertEqual(first_path.suffix, ".conda")
            self.assertEqual(names, [SECURITY_METADATA_NAME, SECURITY_SBOM_PAYLOAD_NAME])
            self.assertEqual(security["metadata"]["kind"], "SBOM")
            self.assertEqual(security["metadata"]["data_schema"], "sbom.v1")
            self.assertIsNone(security["metadata"]["parent_sha256"])
            self.assertIsInstance(security["metadata"]["created_on"], int)
            payload_metadata = security["artifacts"][SECURITY_SBOM_PAYLOAD_NAME]
            self.assertEqual(payload_metadata["size"], len(payload_bytes))
            self.assertEqual(
                payload_metadata["sha256"],
                hashlib.sha256(payload_bytes).hexdigest(),
            )
            self.assertEqual(get_sbom_version(payload), version)

    def test_sbom_version_tracks_only_significant_content(self) -> None:
        record = {
            "name": "demo",
            "version": "1.2.3",
            "build": "py_0",
            "build_number": 0,
            "sha256": "a" * 64,
            "license": "MIT",
        }
        mapping = {
            "name": "demo",
            "version": "1.2.3",
            "build": "py_0",
            "subdir": "noarch",
            "purl": "pkg:pypi/demo-pkg",
            "pkg_name": "demo-pkg",
            "download_count": 1,
        }

        first = build_cyclonedx_sbom(
            mapping=mapping,
            record=record,
            filename="demo-1.2.3-py_0.conda",
            channel="conda-forge",
            subdir="noarch",
        )
        insignificant_change = {
            **mapping,
            "download_count": 2,
            "summary": "updated package description",
        }
        second = build_cyclonedx_sbom(
            mapping=insignificant_change,
            record=record,
            filename="demo-1.2.3-py_0.conda",
            channel="conda-forge",
            subdir="noarch",
        )
        purl_change = {**mapping, "purl": "pkg:pypi/renamed-demo-pkg"}
        third = build_cyclonedx_sbom(
            mapping=purl_change,
            record=record,
            filename="demo-1.2.3-py_0.conda",
            channel="conda-forge",
            subdir="noarch",
        )

        self.assertEqual(get_sbom_version(first), get_sbom_version(second))
        self.assertNotEqual(get_sbom_version(first), get_sbom_version(third))

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
