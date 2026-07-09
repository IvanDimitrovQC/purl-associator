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
    load_s3_sbom_inventory,
    load_repodata,
    load_mapping_entries,
    paths_present_in_inventory,
)


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
            sbom = json.loads(out.read_text())
            progress_data = json.loads((root / "progress.json").read_text())

        self.assertEqual(len(result.generated), 1)
        self.assertEqual(result.existing, 0)
        self.assertEqual(second_result.generated, result.generated)
        self.assertEqual(second_result.existing, 1)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(result.errors, [])
        self.assertEqual(sbom["components"][0]["purl"], "pkg:pypi/demo-pkg@1.2.3")
        self.assertEqual(out.name[:8], "sbom-v1-")
        self.assertEqual(len(published), 2)
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

            sboms = [json.loads(path.read_text()) for path in result.generated]
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
        self.assertIn("demo-1.2.0-py_1.conda", filenames)

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
        self.assertEqual(len(skipped_paths), 2)
        self.assertFalse(any(path.exists() for path in skipped_paths))

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
            sbom_path = root / "noarch" / "sboms" / "demo" / "sbom-v1-abc.cdx.json"
            event_path = root / "noarch" / "sboms" / "demo" / "event-v1-abc.json"
            inventory_path = Path(tmp) / "inventory.json"
            inventory_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "objects": [
                            "noarch/sboms/demo/sbom-v1-abc.cdx.json",
                            "noarch/sboms/demo/event-v1-abc.json",
                        ],
                    }
                )
                + "\n"
            )

            inventory = load_s3_sbom_inventory(inventory_path)
            self.assertTrue(
                paths_present_in_inventory(
                    [sbom_path, event_path],
                    root=root,
                    inventory=inventory,
                )
            )


if __name__ == "__main__":
    unittest.main()
