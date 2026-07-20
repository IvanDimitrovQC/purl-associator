# PURL Associator

This repository maintains canonical **conda-forge package identity mappings**.
Each mapping record is keyed by conda-forge package name and carries identifiers
that downstream security tooling can use:

- a primary Package URL (**PURL**) and optional alternative PURLs
- optional CPE 2.3 vendor/product prefixes for NVD matching
- package context such as latest observed version, recipe/source URLs, summary,
  and download counts

CVE assignment, OpenVEX review state, AI CVE drafts, and SBOM-derived findings
are intentionally out of scope. A downstream CVE project should consume the
identity mapping payload produced here, enumerate conda-forge versions there,
and join those versions with OSV/NVD affected-version data there.

## Data model

The core object is a conda-forge package identity record:

```json
{
  "name": "ncurses",
  "version": "6.5",
  "purl": "pkg:github/ThomasDickey/ncurses-snapshots",
  "type": "github",
  "namespace": "ThomasDickey",
  "pkg_name": "ncurses-snapshots",
  "alternative_purls": [],
  "cpes": [
    "cpe:2.3:a:gnu:ncurses",
    "cpe:2.3:a:invisible-island:ncurses"
  ],
  "status": "verified"
}
```

PURLs identify source/package ecosystem coordinates. CPEs identify NVD
vendor/product coordinates. CPE strings stored here are identity-level prefixes;
this repository does not store CVE affected ranges or per-CVE version decisions.

## Sources and outputs

| Path | Purpose |
|---|---|
| `mappings/auto.json` | automatically inferred PURL mappings |
| `mappings/manual.json` | legacy/manual reviewed overrides |
| `mappings/contributions/*.json` | PR-submitted mapping contributions, including CPE pipeline output |
| `mappings/cpe_candidates/*.json` | audit output from CPE discovery |
| `mappings/cpe_vet/*.json` | optional AI tiebreaker output for ambiguous CPE candidates |
| `web/public/mappings.json` | generated full mapping bundle |
| `web/public/mappings-index.json` | generated compact index for the web app |
| `web/public/mapping_packages/*.json` | generated sharded package detail payloads |

## PURL flow

```mermaid
flowchart TD
  A[conda-forge metadata] --> B[scripts.automap]
  B --> C[mappings/auto.json]
  C --> D[scripts.merge_mappings]
  E[mappings/manual.json] --> D
  F[mappings/contributions/*.json] --> D
  D --> G[web/public/mappings*.json]
  G --> H[PURL editing UI]
  H --> I[Worker POST /api/submit]
  I --> F
```

Useful commands:

```sh
pixi run purl:automap --only numpy,ripgrep,pandas
pixi run -e lite mappings:merge
pixi run -e lite mappings:validate
pixi run purl:test
```

## CPE flow

CPE discovery is part of identity mapping, not CVE assignment. The retained CPE
pipeline proposes NVD vendor/product prefixes and promotes accepted mappings as
normal contribution files. Those CPEs then flow through `scripts.merge_mappings`
into the public mapping payload.

```mermaid
flowchart TD
  A[mappings/auto.json + reviewed mappings] --> B[scripts.cpe_discover]
  B --> C[mappings/cpe_candidates/*.json]
  C --> D[scripts.cpe_vet optional]
  D --> E[mappings/cpe_vet/*.json]
  C --> F[scripts.cpe_promote]
  E --> F
  F --> G[mappings/contributions/*--cpe-pipeline--*.json]
  G --> H[scripts.merge_mappings]
```

Useful commands:

```sh
pixi run cpe:discover --top 50
pixi run cpe:vet --dry-run
pixi run cpe:promote --dry-run
pixi run -e lite mappings:merge
pixi run -e lite mappings:validate
```

## Frontend behavior

The GitHub Pages app is a PURL editing UI:

- users can review, edit, approve, or mark PURL mappings as unmapped
- staged PURL edits are saved locally until submitted
- submitted edits open PRs containing one new file under `mappings/contributions/`
- CPEs are displayed read-only as package identity metadata
- no CVE dashboard, OpenVEX review, AI CVE queue, or deep-inspection routes are
  served from this repository

The Worker exposes only:

- `POST /exchange` for GitHub OAuth code exchange
- `POST /api/submit` for PURL mapping contribution PRs

## Downstream CVE consumption

A downstream CVE project should consume `web/public/mappings.json` or the split
`mappings-index.json` + `mapping_packages/*.json` payload. It should then:

1. enumerate conda-forge package versions independently,
2. use PURLs for OSV/package-ecosystem matching,
3. use CPE prefixes for NVD matching,
4. apply OSV/NVD affected-version logic in that downstream project, and
5. store CVE assignment/review state outside this repository.

## Local SBOM demo

This fork also includes a small local CycloneDX generator that demonstrates the
first downstream step: enrich one concrete conda-forge artifact with its mapped
upstream PURL. The generated files are written under `local-advisory-channel/`
and are ignored by git.

```sh
pixi run -e lite sbom:generate pandas
```

By default the command reads the split mapping payload, uses the mapped
`version`/`build`/`subdir` as artifact coordinates, fetches conda-forge
`repodata.json` for that subdir, and writes:

```text
local-advisory-channel/<subdir>/sboms/<filename>/sbom-<hash>.cdx.json
```

The `<hash>` version is content-addressed from SBOM-significant inputs: the
conda artifact metadata, the mapping fields emitted into the SBOM, and the SBOM
generator input schema. Volatile values such as generation time do not affect
the version. Running the same generation twice for unchanged significant inputs
returns the same path and does not rewrite the SBOM.
When the mapped PURL or another SBOM-visible field changes, a new versioned SBOM
is appended next to the old one.

For offline or reproducible runs, pass a local repodata file:

```sh
pixi run -e lite sbom:generate pandas --repodata /path/to/repodata.json
```

You can also generate from a single package mapping entry JSON object:

```sh
pixi run -e lite sbom:generate --mapping-entry /path/to/package-entry.json
```

To generate SBOMs from a purl-associator payload, pass an auto/detail/index
mapping JSON to the batch wrapper:

```sh
pixi run -e lite sbom:generate-many mappings/auto.json
```

The batch command defaults to mapped PyPI packages. Use `--purl-type any` to
include other mapped PURL types, `--limit N` for a small prefix of eligible
entries, or `--random` to generate one random eligible package:

```sh
pixi run -e lite sbom:generate-many mappings/auto.json --random
```

For periodic local maintenance, use the cached refresh command:

```sh
pixi run -e lite sbom:refresh
```

That command reads `mappings/auto.json`, fetches conda-forge repodata once per
needed subdir, caches it under `.cache/repodata/`, generates SBOM candidates,
and appends only SBOM versions whose significant content hash is new. Re-running
the command with unchanged mapping and repodata content reports existing SBOM
versions instead of writing duplicates. Repodata fetches use conditional cache
headers when available and retry transient `429`/`5xx` responses with backoff.

To generate SBOMs for historical package versions, ask the refresh command to
fan out each mapped package over the latest N distinct conda versions found in
repodata:

```sh
pixi run -e lite sbom:refresh --versions-per-package 10
```

This still treats `mappings/auto.json` as the package identity source. The
unversioned mapped PURL is combined with each selected conda artifact version
when the SBOM is written, for example `pkg:pypi/numpy` becomes
`pkg:pypi/numpy@2.1.3`. By default historical selection scans the subdir stored
in the mapping and writes the latest build for each selected version. To scan
the full conda-forge platform matrix instead, use `--artifact-subdirs all`.
Use `--artifact-selection all-builds` only when every historical build is needed;
it creates many more artifacts.

The SBOM subject is the conda artifact (`metadata.component`). The mapped PyPI
PURL is emitted as a CycloneDX component with the artifact version added, so a
later OSV correlator can read component PURLs directly.

You can then query OSV for the component PURLs in that SBOM:

```sh
pixi run -e lite osv:correlate \
  local-advisory-channel/<subdir>/sboms/<filename>/sbom-<hash>.cdx.json
```

The correlator calls OSV's `/v1/querybatch` endpoint with versioned component
PURLs and writes:

```text
local-advisory-channel/<subdir>/advisories/<filename>/
  osv-<sbom-hash>-<osv-hash>.json
```

That sidecar contains the SBOM subject, the queried components, skipped
unversioned PURLs, and flattened vulnerability findings for a future advisory
channel index. OSV advisory artifact schema version 2 also stores a canonical
`https://osv.dev/vulnerability/<id>` URL for each vulnerability finding.

For periodic OSV maintenance, refresh all locally available SBOMs in one
deduplicated pass:

```sh
pixi run -e lite osv:refresh
```

By default the OSV refresh command scans `local-advisory-channel/*/sboms/`.
When local SBOM artifacts are cleaned after upload, pass
`--s3-sbom-source-uri s3://<bucket>/<prefix>` so the command lists SBOMs from
the S3 advisory channel, downloads them into a temporary channel-shaped staging
directory, deduplicates all versioned component PURLs, queries OSV in bounded
`/v1/querybatch` chunks, and writes a new advisory artifact only when the
normalized OSV result content is new. The advisory hash ignores volatile
generation time, so rerunning against the same OSV response does not write a
duplicate artifact. This OSV refresh should still run periodically even when no
new SBOM is generated, because OSV vulnerability data can change independently
from the package identity mapping. OSV requests also retry transient `429`/`5xx`
responses with backoff.

Useful maintenance variants:

```sh
pixi run -e lite sbom:refresh --limit 100
pixi run -e lite sbom:refresh --refresh-cache
pixi run -e lite osv:refresh --batch-size 250
pixi run -e lite osv:refresh --dry-run
```

For large local runs, use bounded workers to overlap local artifact generation
and S3 uploads:

```sh
pixi run -e lite sbom:refresh --workers 8 --s3-workers 4
pixi run -e lite osv:refresh --workers 8 --s3-workers 4
```

`--workers` controls package/SBOM or advisory generation workers. For SBOM
refresh it also overlaps per-package upload handling. For OSV refresh it
parallelizes local SBOM loading and advisory artifact generation after the
deduplicated OSV query completes. `--s3-workers` controls parallel S3 object
checks/uploads inside each upload batch. Keep both values modest for laptop
runs; S3 and OSV retries still apply independently.

To publish the local advisory channel to S3, pass an S3 destination. The scripts
use the AWS CLI, so AWS credentials must already be configured through the
environment, default profile, or `--s3-profile`.

```sh
pixi run -e lite sbom:refresh \
  --s3-uri s3://<bucket>/<prefix> \
  --progress-file .tmp/sbom-refresh-progress.json \
  --update-index \
  --cleanup-uploaded \
  --workers 8 \
  --s3-workers 4

pixi run -e lite osv:refresh \
  --s3-sbom-source-uri s3://<bucket>/<prefix> \
  --s3-uri s3://<bucket>/<prefix> \
  --progress-file .tmp/osv-refresh-progress.json \
  --update-index \
  --cleanup-uploaded \
  --workers 8 \
  --s3-workers 4
```

For interrupted local SBOM population runs, you can first snapshot the SBOM
objects already present in S3 and then skip S3 `HEAD`/`PUT` checks for those
artifacts on the next refresh:

```sh
pixi run -e lite sbom:s3-inventory \
  --s3-uri s3://<bucket>/<prefix> \
  --s3-profile <profile> \
  --s3-region <region> \
  --out .tmp/s3-sbom-inventory.json

pixi run -e lite sbom:refresh \
  --s3-uri s3://<bucket>/<prefix> \
  --s3-profile <profile> \
  --s3-region <region> \
  --s3-sbom-inventory .tmp/s3-sbom-inventory.json \
  --skip-existing-s3-sboms \
  --versions-per-package 10 \
  --progress-file .tmp/sbom-refresh-progress.json \
  --update-index \
  --cleanup-uploaded
```

This is a resume-time optimization: the refresh still builds each candidate
SBOM locally so it can compute the content-addressed path and update indexes.
When `--skip-existing-s3-sboms` is also set, historical SBOM refreshes can
compute the exact expected SBOM path from repodata and the mapping first; if the
path is listed in the inventory, local SBOM generation is skipped entirely for
that artifact. Otherwise, when the SBOM path is listed in the inventory, it skips
the per-object S3 existence check/upload and removes the local temp file when
`--cleanup-uploaded` is set.

To write a lightweight local summary of the SBOM state in S3, reuse the same
inventory:

```sh
pixi run -e lite sbom:summary \
  --s3-uri s3://<bucket>/<prefix> \
  --s3-profile <profile> \
  --s3-region <region> \
  --s3-sbom-inventory .tmp/s3-sbom-inventory.json \
  --out .tmp/sbom-summary.json
```

The summary counts SBOM files, subdirs, packages, and package versions without
downloading every SBOM JSON. It derives package/version/build from the conda
artifact filename. Pass `--include-artifacts` if you also want per-artifact rows
in the output.

OSV advisory artifacts support the same S3 publication pattern. Because OSV
artifacts are derived from a specific SBOM version and current OSV response
content, one SBOM version can accumulate multiple advisory artifact versions
over time:

```text
local-advisory-channel/<subdir>/advisories/<filename>/
  osv-<sbom-version>-<osv-hash>.json
```

To avoid repeated S3 object checks for OSV artifacts already uploaded, snapshot
the existing advisory objects and pass that inventory to `osv:refresh`:

```sh
pixi run -e lite osv:s3-inventory \
  --s3-uri s3://<bucket>/<prefix> \
  --s3-profile <profile> \
  --s3-region <region> \
  --out .tmp/s3-osv-inventory.json

pixi run -e lite osv:refresh \
  --s3-sbom-source-uri s3://<bucket>/<prefix> \
  --s3-sbom-source-inventory .tmp/s3-sbom-inventory.json \
  --s3-uri s3://<bucket>/<prefix> \
  --s3-profile <profile> \
  --s3-region <region> \
  --s3-osv-inventory .tmp/s3-osv-inventory.json \
  --progress-file .tmp/osv-refresh-progress.json \
  --update-index \
  --cleanup-uploaded
```

The SBOM source inventory avoids listing S3 before downloading source SBOMs. The
OSV inventory is still only used after the exact advisory output path is known;
if OSV data has changed, the new hash produces a new path and the artifact is
uploaded. S3-sourced SBOMs are staged under `.tmp/osv-sbom-stage/` by default
and removed after a successful run unless `--keep-s3-sbom-stage` is set.

To create a lightweight local package-to-vulnerabilities summary from the OSV
artifacts already in S3, run:

```sh
pixi run -e lite osv:vulnerability-summary \
  --s3-uri s3://<bucket>/<prefix> \
  --s3-profile <profile> \
  --s3-region <region> \
  --s3-osv-inventory .tmp/s3-osv-inventory.json \
  --out .tmp/osv-vulnerability-summary.json \
  --workers 8
```

The summary script streams advisory JSON from S3 directly into memory and writes
only the local output file. By default it reports the latest advisory artifact
per source SBOM, which avoids including superseded append-only OSV results. Pass
`--include-all-artifacts` to aggregate every OSV artifact version, or
`--only-vulnerable` to omit packages with empty vulnerability lists. Vulnerability
rows include OSV IDs, component PURLs, and canonical OSV URLs; URLs are derived
from the ID when reading older schema version 1 advisory artifacts. Summary
payloads with vulnerability URLs use schema version 2.

To build the static data file consumed by the local dashboard from mutable S3
indexes/shards only, skip the OSV summary scan:

```sh
pixi run -e lite advisory:dashboard-data \
  --s3-uri s3://<bucket>/<prefix> \
  --s3-profile <profile> \
  --s3-region <region> \
  --mapping-json mappings/auto.json \
  --skip-osv-summary \
  --out web/public/advisory-dashboard-data.json \
  --s3-output-uri s3://<bucket>/temp \
  --workers 8
```

This is the fast path for dashboard generation. It reads `channel-index.json`,
the subdir shard indexes, package-name shards, and the PURL mapping, but does
not stream every OSV artifact. Indexes produced by the current code include
compact vulnerability rows under each current OSV record; older indexes still
work, but vulnerability drilldowns fall back to OSV IDs from `finding_ids`.

To build the dashboard from a separately generated local OSV vulnerability
summary instead:

```sh
pixi run -e lite advisory:dashboard-data \
  --s3-uri s3://<bucket>/<prefix> \
  --s3-profile <profile> \
  --s3-region <region> \
  --mapping-json mappings/auto.json \
  --osv-summary .tmp/osv-vulnerability-summary.json \
  --out web/public/advisory-dashboard-data.json \
  --s3-output-uri s3://<bucket>/temp \
  --workers 8
```

The dashboard payload includes package-level flags such as `missing_purl`,
`has_sbom`, `missing_osv`, `vulnerabilities_found`,
`no_known_vulnerabilities`, and latest-indexed-version flags. It also keeps the
artifact rows needed to drill down by version, platform subdir, and build. When
OSV findings are present, their IDs link to the corresponding OSV page, and
newer index/summary inputs can include severity metadata. Dashboard payloads use
schema version 2. When `--s3-output-uri` is set, the generated dashboard JSON is
uploaded to that separate S3 prefix using the local output filename. This lets
the dashboard read advisory-channel data from one prefix, such as
`s3://<bucket>/test1`, while publishing the handoff JSON to another prefix, such
as `s3://<bucket>/temp/advisory-dashboard-data.json`.

S3 keys preserve the local channel-relative path. For example:

```text
local-advisory-channel/noarch/sboms/demo/sbom-abc.cdx.json
```

is published as:

```text
s3://<bucket>/<prefix>/noarch/sboms/demo/sbom-abc.cdx.json
```

Before uploading, the publisher checks whether the target object already exists
and skips it if present. The object names are content-addressed, so repeated
runs do not intentionally overwrite artifacts. For stricter production
append-only guarantees, enforce write-once behavior with bucket policy,
versioning, or Object Lock.

When `--cleanup-uploaded` is enabled, local files are deleted only after the S3
upload succeeds or the object is confirmed to already exist in S3. Failed
uploads leave their local staging files in place for inspection or retry.

The optional `--progress-file` writes a temporary JSON status file describing
the current load type, inputs, totals, current item, counters, and final status.
It is intended for monitoring long local runs and can be deleted after the load
finishes.

All advisory-channel CLI commands also write logs to stderr and to a local file
under `.tmp/logs/` by default, for example
`.tmp/logs/sbom-refresh-<timestamp>-<pid>.log`. Use `--log-file <path>` to pick
a stable path for a run, or `--log-level DEBUG` when investigating retries,
cache decisions, S3 object checks, index updates, or OSV batches.

The `--update-index` flag keeps mutable catalog files in the advisory channel:

```text
local-advisory-channel/channel-index.json
local-advisory-channel/<subdir>/advisory-repodata.json
local-advisory-channel/<subdir>/advisory-repodata-shards/<sha256>.json
```

`channel-index.json` points at each subdir index. Each
`advisory-repodata.json` is a small shard index keyed by package name. The shard
index maps each package name to a content-addressed JSON shard under
`advisory-repodata-shards/`. Each shard stores the current records for that
package's conda artifact filenames, including current SBOM path/version,
component PURLs, current OSV advisory path/version, finding IDs, vulnerability
count, and a compact status such as `no_known_vulnerabilities` or
`vulnerabilities_found`. Full SBOM and OSV details remain in their separate
artifacts.

Indexes are mutable snapshots. They are uploaded to S3 with overwrite semantics,
while content-addressed SBOM and OSV artifacts remain append-only. Shard files
are also content-addressed, so unchanged package-name shards keep the same path
across rebuilds. These sharded indexes are also the SBOM generation tracker, so
the channel does not write one event sidecar per SBOM. To rebuild indexes from
local artifacts at any point, run:

```sh
pixi run -e lite advisory:index
```

To rebuild the mutable sharded indexes from the current S3 storage state, stream
the existing SBOM and OSV artifacts from S3 and upload the resulting
`channel-index.json`, subdir shard indexes, and shard files:

```sh
pixi run -e lite advisory:index \
  --s3-source-uri s3://<bucket>/<prefix> \
  --s3-sbom-inventory .tmp/s3-sbom-inventory.json \
  --s3-osv-inventory .tmp/s3-osv-inventory.json \
  --channel-root .tmp/advisory-index \
  --s3-uri s3://<bucket>/<prefix> \
  --s3-profile <profile> \
  --s3-region <region> \
  --workers 8 \
  --s3-workers 8
```

On EC2 with an instance role, omit `--s3-profile`.

## Verification

Run these checks before opening a PR:

```sh
pixi run -e lite mappings:merge
pixi run -e lite mappings:validate
pixi run -e lite sbom:test
pixi run app:check
```

For frontend/Worker-only checks:

```sh
cd web && npm run build
cd worker && npm run typecheck
```
