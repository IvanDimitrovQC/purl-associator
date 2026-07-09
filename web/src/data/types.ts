export type AutoMapping = {
  purl: string | null;
  type: string | null;
  namespace: string | null;
  pkg_name: string | null;
  confidence: number;
  sources: string[];
  alternative_purls?: PurlAlternative[] | null;
};

export type PurlAlternative = {
  purl: string;
  type: string;
  namespace: string | null;
  pkg_name: string;
  confidence: number;
  source: string;
};

export type ManualOverride = {
  purl: string | null;
  type: string | null;
  namespace: string | null;
  pkg_name: string | null;
  alternative_purls?: (PurlAlternative | string)[] | null;
  unmapped?: boolean;
  note?: string;
  approved_by?: string;
  approved_at?: string;
};

export type PackageEntry = {
  name: string;
  version: string;
  build?: string;
  subdir?: string;
  url?: string;
  purl: string | null;
  type: string | null;
  namespace: string | null;
  pkg_name: string | null;
  confidence: number;
  sources: string[];
  homepage: string | null;
  repo: string | null;
  recipe_url: string | null;
  summary: string | null;
  source_url: string | null;
  note: string | null;
  fetched_at: string | null;
  status: "auto-unverified" | "auto-verified" | "verified" | "unmapped" | "edited";
  source: "auto" | "manual";
  unmapped?: boolean;
  approved_by?: string;
  approved_at?: string;
  alternative_purls?: (PurlAlternative | string)[] | null;
  auto_verified?: boolean;
  verification_sources?: string[] | null;
  /** CPE 2.3 vendor/product prefixes for downstream NVD matching. */
  cpes?: string[] | null;
  /** the original auto guess, kept for diff display when an override exists */
  auto?: AutoMapping;
  /** total downloads on prefix.dev for this package (null if not ranked) */
  download_count?: number | null;
};

export type MappingPackageIndex = Pick<
  PackageEntry,
  | "name"
  | "version"
  | "purl"
  | "type"
  | "namespace"
  | "pkg_name"
  | "status"
  | "download_count"
  | "alternative_purls"
  | "unmapped"
  | "cpes"
  | "auto"
> & {
  detail_path: string;
};

export type MappingsPayload = {
  schema_version: number;
  generated_at: string | null;
  auto_generated_at: string | null;
  manual_updated_at: string | null;
  channel: string;
  package_count: number;
  packages: Record<string, PackageEntry>;
};

export type MappingsIndexPayload = Omit<MappingsPayload, "packages"> & {
  packages: Record<string, MappingPackageIndex>;
};

export type Edit = {
  type: string;
  namespace: string;
  pkgName: string;
  purl: string;
  alternative_purls: string[];
  /** Full replacement CPE list. undefined = untouched — the contribution
   *  omits the field so the cpe-pipeline layer keeps owning CPEs. */
  cpes?: string[];
  unmapped: boolean;
  note: string;
  approved?: boolean;
};

export type Repo = {
  owner: string;
  name: string;
  branch: string;
  url: string;
};

export type GitHubUser = {
  login: string;
  name: string | null;
  avatar_url: string;
  initial: string;
  color: string;
};

export type AdvisoryVulnerability = {
  id: string | null;
  url?: string | null;
  component_purl?: string | null;
  component_name?: string | null;
  component_version?: string | null;
  modified?: string | null;
  source_advisory?: string | null;
};

export type AdvisoryArtifactState = {
  exists: boolean;
  path: string | null;
  version?: string | null;
  input_sha256?: string | null;
  mapping_sha256?: string | null;
  status?: string | null;
  correlation_version?: string | null;
  query_count?: number;
  vulnerability_count?: number;
  finding_ids?: string[];
};

export type DashboardArtifact = {
  filename: string;
  name: string;
  version: string | null;
  subdir: string | null;
  build: string | null;
  conda_purl: string | null;
  component_purls: string[];
  sbom: AdvisoryArtifactState;
  osv: AdvisoryArtifactState;
  vulnerabilities: AdvisoryVulnerability[];
};

export type DashboardPackage = {
  name: string;
  mapped_purl: string | null;
  purl_type: string | null;
  purl_confidence: number | null;
  has_purl: boolean;
  artifact_count: number;
  version_count: number;
  subdir_count: number;
  latest_version: string | null;
  latest_version_basis: string | null;
  sbom: {
    any_exists: boolean;
    all_artifacts_have_sbom: boolean;
    missing_count: number;
  };
  osv: {
    any_artifact_checked: boolean;
    all_artifacts_checked: boolean;
    missing_count: number;
    any_vulnerabilities_found: boolean;
    total_vulnerability_findings: number;
    unique_vulnerability_count: number;
    no_vulnerabilities_found_for_any_artifact: boolean;
    vulnerabilities_found_in_any_artifact: boolean;
    latest_version: string | null;
    latest_version_basis: string | null;
    latest_version_artifact_count: number;
    latest_version_any_checked: boolean;
    latest_version_all_checked: boolean;
    latest_version_any_vulnerabilities_found: boolean;
    latest_version_total_vulnerability_findings: number;
  };
  flags: string[];
  vulnerabilities: AdvisoryVulnerability[];
  artifacts: DashboardArtifact[];
};

export type AdvisoryDashboardPayload = {
  schema_version: number;
  generated_at: string;
  sources: {
    s3_uri: string;
    mapping_json: string;
    osv_summary: string;
    channel_index_generated_at?: string | null;
    osv_summary_generated_at?: string | null;
  };
  counts: {
    packages: number;
    artifacts: number;
    packages_with_purl: number;
    packages_with_sbom: number;
    packages_with_osv: number;
    packages_with_vulnerabilities: number;
    vulnerability_findings: number;
  };
  packages: Record<string, DashboardPackage>;
};
