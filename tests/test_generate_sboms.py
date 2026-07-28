from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.load_progress import ProgressTracker
from scripts.generate_sboms import (
    generate_many,
    is_eligible_mapping,
    load_s3_logical_sbom_inventory,
    load_s3_sbom_inventory,
    load_repodata,
    load_mapping_entries,
    paths_present_in_inventory,
)
from scripts.generate_sbom import read_security_sbom_payload


class GenerateSbomsTests(unittest.TestCase):
    def _write_mapping_payload(self, root: Path) -> Path:
        payload = {
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
                },
                "unmapped": {
                    "name": "unmapped",
                    "version": "1.0.0",
                    "subdir": "noarch",
                    "purl": None,
                },
            },
        }
        path = root / "mappings.json"
        path.write_text(json.dumps(payload) + "\n")
        return path

    def _repodata(self) -> dict:
        return {
            "packages.conda": {
                "demo-1.2.3-py_0.conda": {
                    "name": "demo",
                    "version": "1.2.3",
                    "build": "py_0",
                    "build_number": 0,
                    "sha256": "a" * 64,
                },
                "other-2.0.0-py_0.conda": {
                    "name": "other",
                    "version": "2.0.0",
                    "build": "py_0",
                    "build_number": 0,
                    "sha256": "b" * 64,
                },
            }
        }

    def _historical_repodata(self) -> dict:
        return {
            "packages.conda": {
                "demo-1.0.0-py_0.conda": {
                    "name": "demo",
                    "version": "1.0.0",
                    "build": "py_0",
                    "build_number": 0,
                    "sha256": "1" * 64,
                },
                "demo-1.2.0-py_0.conda": {
                    "name": "demo",
                    "version": "1.2.0",
                    "build": "py_0",
                    "build_number": 0,
                    "sha256": "2" * 64,
                },
                "demo-1.2.0-py_1.conda": {
                    "name": "demo",
                    "version": "1.2.0",
                    "build": "py_1",
                    "build_number": 1,
                    "sha256": "3" * 64,
                },
                "demo-1.10.0-py_0.conda": {
                    "name": "demo",
                    "version": "1.10.0",
                    "build": "py_0",
                    "build_number": 0,
                    "sha256": "4" * 64,
                },
            }
        }

    def test_load_mapping_entries_from_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_mapping_payload(Path(tmp))

            entries = load_mapping_entries(path)

        self.assertEqual([name for name, _entry in entries], ["demo", "unmapped"])
        self.assertEqual(entries[0][1]["purl"], "pkg:pypi/demo-pkg")

    def test_is_eligible_mapping_filters_missing_or_wrong_purls(self) -> None:
        ok, reason = is_eligible_mapping(
            {"purl": "pkg:pypi/demo", "subdir": "noarch"},
            purl_type_filter="pypi",
        )
        self.assertTrue(ok)
        self.assertIsNone(reason)

        ok, reason = is_eligible_mapping(
            {"purl": "pkg:github/demo/demo", "subdir": "noarch"},
            purl_type_filter="pypi",
        )
        self.assertFalse(ok)
        self.assertIn("does not match", str(reason))

    def test_generate_many_random_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entries = load_mapping_entries(self._write_mapping_payload(root))
            published: list[Path] = []
            progress = ProgressTracker(
                path=root / "progress.json",
                load_type="sbom-refresh",
            )

            with patch(
                "scripts.generate_sboms._load_json_ref", return_value=self._repodata()
            ):
                result = generate_many(
                    entries,
                    channel="conda-forge",
                    out_dir=root / "local-advisory-channel",
                    purl_type_filter="pypi",
                    random_one=True,
                    seed="stable",
                    progress=progress,
                    on_artifacts=published.extend,
                )
                second_result = generate_many(
                    entries,
                    channel="conda-forge",
                    out_dir=root / "local-advisory-channel",
                    purl_type_filter="pypi",
                    random_one=True,
                    seed="stable",
                )

            out = result.generated[0]
            sbom = read_security_sbom_payload(out)
            progress_data = json.loads((root / "progress.json").read_text())

        self.assertEqual(len(result.generated), 1)
        self.assertEqual(result.existing, 0)
        self.assertEqual(second_result.generated, result.generated)
        self.assertEqual(second_result.existing, 1)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(result.errors, [])
        self.assertEqual(sbom["components"][0]["purl"], "pkg:pypi/demo-pkg@1.2.3")
        self.assertRegex(out.name, r"^[0-9a-f]{64}\.conda$")
        self.assertEqual(out.parent.name, "demo-1.2.3-py_0.sboms")
        self.assertEqual(len(published), 1)
        self.assertEqual(progress_data["counts"]["processed"], 1)

    def test_generate_many_can_run_with_workers(self) -> None:
        entries = [
            (
                "demo",
                {
                    "name": "demo",
                    "version": "1.2.3",
                    "build": "py_0",
                    "subdir": "noarch",
                    "purl": "pkg:pypi/demo-pkg",
                    "pkg_name": "demo-pkg",
                },
            ),
            (
                "other",
                {
                    "name": "other",
                    "version": "2.0.0",
                    "build": "py_0",
                    "subdir": "noarch",
                    "purl": "pkg:pypi/other-pkg",
                    "pkg_name": "other-pkg",
                },
            ),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "scripts.generate_sboms._load_json_ref", return_value=self._repodata()
            ):
                result = generate_many(
                    entries,
                    channel="conda-forge",
                    out_dir=Path(tmp) / "local-advisory-channel",
                    purl_type_filter="pypi",
                    workers=2,
                )

        self.assertEqual(len(result.generated), 2)
        self.assertEqual(result.existing, 0)
        self.assertEqual(result.errors, [])

    def test_generate_many_can_generate_latest_versions_per_package(self) -> None:
        entries = [
            (
                "demo",
                {
                    "name": "demo",
                    "version": "1.0.0",
                    "build": "py_0",
                    "subdir": "noarch",
                    "purl": "pkg:pypi/demo-pkg",
                    "pkg_name": "demo-pkg",
                },
            )
        ]

        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "scripts.generate_sboms._load_json_ref",
                return_value=self._historical_repodata(),
            ):
                result = generate_many(
                    entries,
                    channel="conda-forge",
                    out_dir=Path(tmp) / "local-advisory-channel",
                    purl_type_filter="pypi",
                    versions_per_package=2,
                )

            sboms = [read_security_sbom_payload(path) for path in result.generated]
            filenames = {path.parent.name for path in result.generated}
            purls = {sbom["components"][0]["purl"] for sbom in sboms}

        self.assertEqual(len(result.generated), 2)
        self.assertEqual(result.existing, 0)
        self.assertEqual(result.inventory_skipped, 0)
        self.assertEqual(result.errors, [])
        self.assertEqual(
            purls,
            {"pkg:pypi/demo-pkg@1.10.0", "pkg:pypi/demo-pkg@1.2.0"},
        )
        self.assertIn("demo-1.2.0-py_1.sboms", filenames)

    def test_generate_many_can_skip_inventory_present_historical_sboms(self) -> None:
        entries = [
            (
                "demo",
                {
                    "name": "demo",
                    "version": "1.0.0",
                    "build": "py_0",
                    "subdir": "noarch",
                    "purl": "pkg:pypi/demo-pkg",
                    "pkg_name": "demo-pkg",
                },
            )
        ]
        skipped_paths: list[Path] = []

        def skip_artifacts(paths: list[Path]) -> bool:
            skipped_paths.extend(paths)
            return True

        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "scripts.generate_sboms._load_json_ref",
                return_value=self._historical_repodata(),
            ):
                result = generate_many(
                    entries,
                    channel="conda-forge",
                    out_dir=Path(tmp) / "local-advisory-channel",
                    purl_type_filter="pypi",
                    versions_per_package=1,
                    skip_artifacts=skip_artifacts,
                )

        self.assertEqual(result.generated, [])
        self.assertEqual(result.existing, 0)
        self.assertEqual(result.inventory_skipped, 1)
        self.assertEqual(len(skipped_paths), 1)
        self.assertFalse(any(path.exists() for path in skipped_paths))

    def test_generate_many_can_skip_logical_inventory_present_sboms(self) -> None:
        entries = [
            (
                "demo",
                {
                    "name": "demo",
                    "version": "1.2.3",
                    "build": "py_0",
                    "subdir": "noarch",
                    "purl": "pkg:pypi/demo-pkg",
                    "pkg_name": "demo-pkg",
                },
            )
        ]
        skipped: list[tuple[Path, str]] = []

        def skip_logical_artifact(path: Path, sbom_version: str) -> Path | None:
            skipped.append((path, sbom_version))
            return path.with_name(f"{'b' * 64}.conda")

        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "scripts.generate_sboms._load_json_ref", return_value=self._repodata()
            ):
                result = generate_many(
                    entries,
                    channel="conda-forge",
                    out_dir=Path(tmp) / "local-advisory-channel",
                    purl_type_filter="pypi",
                    skip_logical_artifact=skip_logical_artifact,
                )

        self.assertEqual(result.generated, [])
        self.assertEqual(result.existing, 0)
        self.assertEqual(result.inventory_skipped, 1)
        self.assertEqual(len(skipped), 1)
        self.assertRegex(skipped[0][1], r"^[0-9a-f]{64}$")

    def test_load_repodata_uses_fresh_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "cache"
            repodata_path = cache_dir / "conda-forge" / "noarch" / "repodata.json"
            metadata_path = cache_dir / "conda-forge" / "noarch" / "metadata.json"
            repodata_path.parent.mkdir(parents=True)
            repodata_path.write_text(json.dumps(self._repodata()) + "\n")
            metadata_path.write_text(json.dumps({"fetched_at": 9_999_999_999}) + "\n")

            repodata = load_repodata(
                channel="conda-forge",
                subdir="noarch",
                cache_dir=cache_dir,
                cache_max_age_seconds=1200,
                refresh_cache=False,
            )

        self.assertEqual(
            repodata["packages.conda"]["demo-1.2.3-py_0.conda"]["name"],
            "demo",
        )

    def test_s3_sbom_inventory_matches_channel_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            sbom_path = (
                root
                / "noarch"
                / "demo-1.2.3-py_0.sboms"
                / f"{'a' * 64}.conda"
            )
            inventory_path = Path(tmp) / "inventory.json"
            inventory_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "objects": [
                            f"noarch/demo-1.2.3-py_0.sboms/{'a' * 64}.conda",
                        ],
                    }
                )
                + "\n"
            )

            inventory = load_s3_sbom_inventory(inventory_path)
            self.assertTrue(
                paths_present_in_inventory(
                    [sbom_path],
                    root=root,
                    inventory=inventory,
                )
            )

    def test_load_s3_logical_sbom_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inventory_path = Path(tmp) / "inventory.json"
            inventory_path.write_text(
                json.dumps(
                    {
                        "schema_version": 3,
                        "objects": [],
                        "logical_sboms": {
                            "noarch/demo-1.2.3-py_0.sboms": {
                                "abc": (
                                    "noarch/demo-1.2.3-py_0.sboms/"
                                    f"{'a' * 64}.conda"
                                )
                            }
                        },
                    }
                )
                + "\n"
            )

            inventory = load_s3_logical_sbom_inventory(inventory_path)

        self.assertEqual(
            inventory[("noarch/demo-1.2.3-py_0.sboms", "abc")],
            f"noarch/demo-1.2.3-py_0.sboms/{'a' * 64}.conda",
        )


if __name__ == "__main__":
    unittest.main()
