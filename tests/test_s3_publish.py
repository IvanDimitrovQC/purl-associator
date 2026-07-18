from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.s3_publish import (
    S3PublishError,
    cleanup_uploaded_files,
    download_file,
    download_files,
    list_s3_relative_paths,
    parse_s3_uri,
    s3_uri_for_relative_path,
    s3_uri_for_path,
    upload_file,
    upload_files,
)


class S3PublishTests(unittest.TestCase):
    def test_parse_s3_uri(self) -> None:
        location = parse_s3_uri("s3://demo-bucket/advisory/channel")

        self.assertEqual(location.bucket, "demo-bucket")
        self.assertEqual(location.prefix, "advisory/channel")

    def test_list_s3_relative_paths_paginates_and_strips_prefix(self) -> None:
        calls: list[list[str]] = []

        def runner(
            cmd: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            if "--continuation-token" in cmd:
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    '{"Contents":[{"Key":"prefix/noarch/second.json"}]}',
                    "",
                )
            return subprocess.CompletedProcess(
                cmd,
                0,
                (
                    '{"Contents":[{"Key":"prefix/noarch/first.json"}],'
                    '"NextContinuationToken":"next"}'
                ),
                "",
            )

        paths = list_s3_relative_paths(
            s3_uri="s3://demo-bucket/prefix",
            runner=runner,
        )

        self.assertEqual(paths, ["noarch/first.json", "noarch/second.json"])
        self.assertEqual(len(calls), 2)

    def test_s3_uri_for_path_preserves_channel_relative_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            path = root / "noarch" / "sboms" / "demo" / "sbom-abcd.cdx.json"

            destination = s3_uri_for_path(
                local_path=path,
                root=root,
                s3_uri="s3://demo-bucket/prefix",
            )

        self.assertEqual(
            destination,
            "s3://demo-bucket/prefix/noarch/sboms/demo/sbom-abcd.cdx.json",
        )

    def test_s3_uri_for_relative_path_preserves_channel_relative_path(self) -> None:
        self.assertEqual(
            s3_uri_for_relative_path(
                relative_path="noarch/sboms/demo/sbom-abcd.cdx.json",
                s3_uri="s3://demo-bucket/prefix",
            ),
            "s3://demo-bucket/prefix/noarch/sboms/demo/sbom-abcd.cdx.json",
        )

    def test_upload_file_dry_run_does_not_require_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            path = root / "noarch" / "missing.json"

            result = upload_file(
                local_path=path,
                root=root,
                s3_uri="s3://demo-bucket/prefix",
                dry_run=True,
            )

        self.assertTrue(result.uploaded)
        self.assertFalse(result.already_exists)

    def test_upload_file_skips_existing_object(self) -> None:
        calls: list[list[str]] = []

        def runner(
            cmd: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            path = root / "noarch" / "demo.json"
            path.parent.mkdir(parents=True)
            path.write_text("{}\n")

            result = upload_file(
                local_path=path,
                root=root,
                s3_uri="s3://demo-bucket/prefix",
                runner=runner,
            )

        self.assertFalse(result.uploaded)
        self.assertTrue(result.already_exists)
        self.assertEqual(len(calls), 1)
        self.assertIn("head-object", calls[0])

    def test_upload_file_copies_missing_object(self) -> None:
        calls: list[list[str]] = []

        def runner(
            cmd: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            if "head-object" in cmd:
                return subprocess.CompletedProcess(cmd, 255, "", "Not Found")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            path = root / "noarch" / "demo.json"
            path.parent.mkdir(parents=True)
            path.write_text("{}\n")

            result = upload_file(
                local_path=path,
                root=root,
                s3_uri="s3://demo-bucket/prefix",
                runner=runner,
            )

        self.assertTrue(result.uploaded)
        self.assertFalse(result.already_exists)
        self.assertEqual(len(calls), 2)
        self.assertIn("s3", calls[1])
        self.assertIn("cp", calls[1])

    def test_upload_files_runs_with_workers(self) -> None:
        calls: list[list[str]] = []

        def runner(
            cmd: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            if "head-object" in cmd:
                return subprocess.CompletedProcess(cmd, 255, "", "Not Found")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            first = root / "noarch" / "first.json"
            second = root / "noarch" / "second.json"
            first.parent.mkdir(parents=True)
            first.write_text("{}\n")
            second.write_text("{}\n")

            summary = upload_files(
                local_paths=[first, second],
                root=root,
                s3_uri="s3://demo-bucket/prefix",
                workers=2,
                runner=runner,
            )

        self.assertEqual(summary.uploaded, 2)
        self.assertEqual(summary.existing, 0)
        self.assertEqual(sum(1 for call in calls if "head-object" in call), 2)
        self.assertEqual(sum(1 for call in calls if "cp" in call), 2)

    def test_download_file_copies_relative_object(self) -> None:
        calls: list[list[str]] = []

        def runner(
            cmd: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "stage"
            result = download_file(
                relative_path="noarch/sboms/demo/sbom-abcd.cdx.json",
                root=root,
                s3_uri="s3://demo-bucket/prefix",
                runner=runner,
            )

        self.assertEqual(
            result.s3_uri,
            "s3://demo-bucket/prefix/noarch/sboms/demo/sbom-abcd.cdx.json",
        )
        self.assertEqual(
            result.local_path,
            root / "noarch" / "sboms" / "demo" / "sbom-abcd.cdx.json",
        )
        self.assertEqual(len(calls), 1)
        self.assertIn("cp", calls[0])

    def test_download_files_runs_with_workers(self) -> None:
        calls: list[list[str]] = []

        def runner(
            cmd: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "stage"
            summary = download_files(
                relative_paths=[
                    "noarch/sboms/first/sbom-first.cdx.json",
                    "noarch/sboms/second/sbom-second.cdx.json",
                ],
                root=root,
                s3_uri="s3://demo-bucket/prefix",
                workers=2,
                runner=runner,
            )

        self.assertEqual(summary.downloaded, 2)
        self.assertEqual(sum(1 for call in calls if "cp" in call), 2)

    def test_upload_file_overwrite_skips_head_object_check(self) -> None:
        calls: list[list[str]] = []

        def runner(
            cmd: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            path = root / "channel-index.json"
            path.parent.mkdir(parents=True)
            path.write_text("{}\n")

            result = upload_file(
                local_path=path,
                root=root,
                s3_uri="s3://demo-bucket/prefix",
                overwrite=True,
                runner=runner,
            )

        self.assertTrue(result.uploaded)
        self.assertFalse(result.already_exists)
        self.assertEqual(len(calls), 1)
        self.assertIn("cp", calls[0])

    def test_upload_file_head_object_bad_request_suggests_region(self) -> None:
        def runner(
            cmd: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                cmd,
                255,
                "",
                "An error occurred (400) when calling the HeadObject operation: "
                "Bad Request",
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            path = root / "noarch" / "demo.json"
            path.parent.mkdir(parents=True)
            path.write_text("{}\n")

            with self.assertLogs("scripts.s3_publish", level="ERROR"):
                with self.assertRaisesRegex(S3PublishError, "--s3-region"):
                    upload_file(
                        local_path=path,
                        root=root,
                        s3_uri="s3://demo-bucket/prefix",
                        runner=runner,
                    )

    def test_cleanup_uploaded_files_removes_confirmed_local_artifacts(self) -> None:
        calls: list[list[str]] = []

        def runner(
            cmd: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            if "head-object" in cmd:
                return subprocess.CompletedProcess(cmd, 255, "", "Not Found")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "local-advisory-channel"
            path = root / "noarch" / "sboms" / "demo" / "sbom.json"
            path.parent.mkdir(parents=True)
            path.write_text("{}\n")

            summary = upload_files(
                local_paths=[path],
                root=root,
                s3_uri="s3://demo-bucket/prefix",
                runner=runner,
            )
            cleanup = cleanup_uploaded_files(summary, root=root)

            self.assertFalse(path.exists())
            self.assertEqual(cleanup.count, 1)
            self.assertFalse(path.parent.exists())


if __name__ == "__main__":
    unittest.main()
