#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Required AWS/channel defaults. Override any of these before invoking the script.
export BUCKET="${BUCKET:-advisory-channel-457644036667-eu-north-1-an}"
export REGION="${REGION:-eu-north-1}"
export TOP_N="${TOP_N:-1000}"
export PREFIX="${PREFIX:-test-top${TOP_N}}"
export TEMP_PREFIX="${TEMP_PREFIX:-temp}"
export CHANNEL="${CHANNEL:-s3://${BUCKET}/${PREFIX}}"
export TEMP="${TEMP:-s3://${BUCKET}/${TEMP_PREFIX}}"
export DASHBOARD_S3_OUTPUT_URI="${DASHBOARD_S3_OUTPUT_URI:-$TEMP}"

# Local inputs/outputs.
export MAPPING_JSON="${MAPPING_JSON:-mappings/auto.json}"
export TOP_MAPPINGS="${TOP_MAPPINGS:-.tmp/top-${TOP_N}-mappings.json}"
export SBOM_INVENTORY="${SBOM_INVENTORY:-.tmp/s3-sbom-inventory-top${TOP_N}.json}"
export OSV_INVENTORY="${OSV_INVENTORY:-.tmp/s3-osv-inventory-top${TOP_N}.json}"
export SBOM_PROGRESS="${SBOM_PROGRESS:-.tmp/sbom-refresh-top${TOP_N}-progress.json}"
export OSV_PROGRESS="${OSV_PROGRESS:-.tmp/osv-refresh-top${TOP_N}-progress.json}"
export INDEX_ROOT="${INDEX_ROOT:-.tmp/advisory-index-top${TOP_N}}"
export DASHBOARD_OUT="${DASHBOARD_OUT:-.tmp/advisory-dashboard-data.json}"
export REPODATA_CACHE="${REPODATA_CACHE:-.cache/repodata}"

# Selection and generation knobs.
export PURL_TYPE="${PURL_TYPE:-pypi}"
export VERSIONS_PER_PACKAGE="${VERSIONS_PER_PACKAGE:-40}"
export ARTIFACT_SUBDIRS="${ARTIFACT_SUBDIRS:-all}"
export ARTIFACT_SELECTION="${ARTIFACT_SELECTION:-latest-build-per-version-per-subdir}"
export OSV_BATCH_SIZE="${OSV_BATCH_SIZE:-800}"
export WORKERS="${WORKERS:-16}"
export S3_WORKERS="${S3_WORKERS:-8}"
export SBOM_INVENTORY_WORKERS="${SBOM_INVENTORY_WORKERS:-8}"
export CLEANUP_UPLOADED="${CLEANUP_UPLOADED:-1}"
export INCLUDE_MISSING_DOWNLOADS="${INCLUDE_MISSING_DOWNLOADS:-0}"
export ALLOW_MISSING_PURL="${ALLOW_MISSING_PURL:-0}"

S3_ARGS=(--s3-region "$REGION")
if [[ -n "${AWS_PROFILE:-}" ]]; then
  S3_ARGS+=(--s3-profile "$AWS_PROFILE")
fi

CLEANUP_ARGS=()
if [[ "$CLEANUP_UPLOADED" == "1" ]]; then
  CLEANUP_ARGS+=(--cleanup-uploaded)
fi

TOP_MAPPING_ARGS=()
if [[ "$INCLUDE_MISSING_DOWNLOADS" == "1" ]]; then
  TOP_MAPPING_ARGS+=(--include-missing-downloads)
fi
if [[ "$ALLOW_MISSING_PURL" == "1" ]]; then
  TOP_MAPPING_ARGS+=(--allow-missing-purl)
fi

run() {
  printf '\n>>>'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

printf 'Lean demo channel configuration:\n'
printf '  CHANNEL=%s\n' "$CHANNEL"
printf '  TEMP=%s\n' "$TEMP"
printf '  DASHBOARD_S3_OUTPUT_URI=%s\n' "$DASHBOARD_S3_OUTPUT_URI"
printf '  REGION=%s\n' "$REGION"
printf '  TOP_N=%s\n' "$TOP_N"
printf '  VERSIONS_PER_PACKAGE=%s\n' "$VERSIONS_PER_PACKAGE"
printf '  ARTIFACT_SUBDIRS=%s\n' "$ARTIFACT_SUBDIRS"
printf '  WORKERS=%s S3_WORKERS=%s\n' "$WORKERS" "$S3_WORKERS"
if [[ -n "${AWS_PROFILE:-}" ]]; then
  printf '  AWS_PROFILE=%s\n' "$AWS_PROFILE"
fi

command -v pixi >/dev/null || {
  echo "error: pixi is not available on PATH" >&2
  exit 2
}
command -v aws >/dev/null || {
  echo "error: aws is not available on PATH" >&2
  exit 2
}

run pixi run -e lite mappings:select-top \
  --mapping-json="$MAPPING_JSON" \
  --out="$TOP_MAPPINGS" \
  --limit="$TOP_N" \
  --purl-type="$PURL_TYPE" \
  --s3-uri="$TEMP" \
  "${S3_ARGS[@]}" \
  --s3-workers="$S3_WORKERS" \
  "${TOP_MAPPING_ARGS[@]}"

run pixi run -e lite sbom:s3-inventory \
  --s3-uri="$CHANNEL" \
  "${S3_ARGS[@]}" \
  --include-metadata \
  --workers="$SBOM_INVENTORY_WORKERS" \
  --out="$SBOM_INVENTORY"

run pixi run -e lite sbom:generate-many \
  "$TOP_MAPPINGS" \
  --cache-dir="$REPODATA_CACHE" \
  --versions-per-package="$VERSIONS_PER_PACKAGE" \
  --artifact-subdirs="$ARTIFACT_SUBDIRS" \
  --artifact-selection="$ARTIFACT_SELECTION" \
  --purl-type="$PURL_TYPE" \
  --s3-uri="$CHANNEL" \
  "${S3_ARGS[@]}" \
  --s3-sbom-inventory="$SBOM_INVENTORY" \
  --skip-existing-s3-sboms \
  --progress-file="$SBOM_PROGRESS" \
  "${CLEANUP_ARGS[@]}" \
  --workers="$WORKERS" \
  --s3-workers="$S3_WORKERS"

run pixi run -e lite sbom:s3-inventory \
  --s3-uri="$CHANNEL" \
  "${S3_ARGS[@]}" \
  --include-metadata \
  --workers="$SBOM_INVENTORY_WORKERS" \
  --out="$SBOM_INVENTORY"

run pixi run -e lite osv:s3-inventory \
  --s3-uri="$CHANNEL" \
  "${S3_ARGS[@]}" \
  --out="$OSV_INVENTORY"

run pixi run -e lite osv:refresh \
  --s3-sbom-source-uri="$CHANNEL" \
  --s3-sbom-source-inventory="$SBOM_INVENTORY" \
  --s3-uri="$CHANNEL" \
  "${S3_ARGS[@]}" \
  --s3-osv-inventory="$OSV_INVENTORY" \
  --progress-file="$OSV_PROGRESS" \
  --update-index \
  "${CLEANUP_ARGS[@]}" \
  --batch-size="$OSV_BATCH_SIZE" \
  --workers="$WORKERS" \
  --s3-workers="$S3_WORKERS"

run pixi run -e lite osv:s3-inventory \
  --s3-uri="$CHANNEL" \
  "${S3_ARGS[@]}" \
  --out="$OSV_INVENTORY"

run pixi run -e lite advisory:index \
  --s3-source-uri="$CHANNEL" \
  --s3-sbom-inventory="$SBOM_INVENTORY" \
  --s3-osv-inventory="$OSV_INVENTORY" \
  --s3-uri="$CHANNEL" \
  "${S3_ARGS[@]}" \
  --channel-root="$INDEX_ROOT" \
  --workers="$WORKERS" \
  --s3-workers="$S3_WORKERS"

run pixi run -e lite advisory:dashboard-data \
  --s3-uri="$CHANNEL" \
  "${S3_ARGS[@]}" \
  --mapping-json="$TOP_MAPPINGS" \
  --skip-osv-summary \
  --out="$DASHBOARD_OUT" \
  --s3-output-uri="$DASHBOARD_S3_OUTPUT_URI" \
  --workers="$WORKERS"

printf '\nLean demo channel population complete.\n'
printf '  CHANNEL=%s\n' "$CHANNEL"
printf '  TOP_MAPPINGS=%s\n' "$TOP_MAPPINGS"
printf '  DASHBOARD_OUT=%s\n' "$DASHBOARD_OUT"
printf '  DASHBOARD_S3_OUTPUT_URI=%s\n' "$DASHBOARD_S3_OUTPUT_URI"
