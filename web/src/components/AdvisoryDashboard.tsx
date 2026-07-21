import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type {
  AdvisoryVulnerability,
  DashboardArtifact,
  DashboardPackage,
} from "../data/types";
import { useAdvisoryDashboardData } from "../data/useAdvisoryDashboardData";
import { ConfidenceBar, Glyph, PurlChip, Theme } from "./Primitives";

type StatusTone = "good" | "bad" | "warn" | "muted";
type PackageStatusFilter =
  | "all"
  | "latest_vulnerable"
  | "previous_vulnerable"
  | "any_vulnerable"
  | "osv_missing"
  | "osv_partial"
  | "no_known_vulnerabilities"
  | "sbom_missing"
  | "missing_purl";

const PACKAGE_STATUS_FILTERS: Array<{
  value: PackageStatusFilter;
  label: string;
}> = [
  { value: "all", label: "All statuses" },
  { value: "latest_vulnerable", label: "Latest vuln" },
  { value: "previous_vulnerable", label: "Previous vuln" },
  { value: "any_vulnerable", label: "Any vuln" },
  { value: "osv_missing", label: "OSV missing" },
  { value: "osv_partial", label: "OSV partial" },
  { value: "no_known_vulnerabilities", label: "No vulns" },
  { value: "sbom_missing", label: "SBOM missing" },
  { value: "missing_purl", label: "Missing PURL" },
];

const DASHBOARD_GRID_COLUMNS = "310px 160px 150px 270px minmax(360px, 1fr)";
const DRILLDOWN_ROW_HEIGHT = 46;

type VersionFindingRow = {
  version: string;
  artifactCount: number;
  checkedCount: number;
  vulnerabilityCount: number;
};

type VulnerabilitySort = "severity" | "newest" | "oldest" | "id";

const VULNERABILITY_SORT_OPTIONS: Array<{
  value: VulnerabilitySort;
  label: string;
}> = [
  { value: "severity", label: "Severity" },
  { value: "newest", label: "Newest" },
  { value: "oldest", label: "Oldest" },
  { value: "id", label: "ID" },
];

function uniqueSorted(values: Array<string | null | undefined>): string[] {
  return Array.from(new Set(values.filter((value): value is string => Boolean(value))))
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
}

function versionKey(version: string | null): string {
  return version ?? "unknown";
}

function artifactVulnerabilityCount(artifact: DashboardArtifact): number {
  return artifact.osv.vulnerability_count ?? artifact.vulnerabilities.length;
}

function artifactVulnerabilityKeys(artifact: DashboardArtifact): string[] {
  const keys = artifact.vulnerabilities
    .map((vulnerability, index) => {
      if (vulnerability.id) return vulnerability.id;
      if (vulnerability.url) return vulnerability.url;
      if (vulnerability.component_purl) {
        return `${vulnerability.component_purl}#${index}`;
      }
      return null;
    })
    .filter((value): value is string => Boolean(value));
  if (keys.length > 0) return Array.from(new Set(keys));

  const findingIds = artifact.osv.finding_ids?.filter(Boolean) ?? [];
  if (findingIds.length > 0) return Array.from(new Set(findingIds));

  return Array.from(
    { length: artifactVulnerabilityCount(artifact) },
    (_, index) => `${artifact.filename}#${index}`,
  );
}

function latestVersion(pkg: DashboardPackage): string | null {
  return pkg.latest_version ?? pkg.osv.latest_version;
}

function latestVersionArtifacts(pkg: DashboardPackage): DashboardArtifact[] {
  const latest = latestVersion(pkg);
  if (!latest) return [];
  return pkg.artifacts.filter(
    (artifact) => versionKey(artifact.version) === versionKey(latest),
  );
}

function latestVersionVulnerabilityCount(pkg: DashboardPackage): number {
  if (typeof pkg.osv.latest_version_total_vulnerability_findings === "number") {
    return pkg.osv.latest_version_total_vulnerability_findings;
  }
  return latestVersionArtifacts(pkg).reduce(
    (total, artifact) => total + artifactVulnerabilityCount(artifact),
    0,
  );
}

function latestVersionFullyChecked(pkg: DashboardPackage): boolean {
  if (typeof pkg.osv.latest_version_all_checked === "boolean") {
    return pkg.osv.latest_version_all_checked;
  }
  const artifacts = latestVersionArtifacts(pkg);
  return artifacts.length > 0 && artifacts.every((artifact) => artifact.osv.exists);
}

function latestVersionHasVulnerabilities(pkg: DashboardPackage): boolean {
  return (
    pkg.flags.includes("latest_version_vulnerabilities_found") ||
    pkg.osv.latest_version_any_vulnerabilities_found ||
    latestVersionVulnerabilityCount(pkg) > 0
  );
}

function previousVersionVulnerabilityCount(pkg: DashboardPackage): number {
  const latest = latestVersion(pkg);
  if (!latest) {
    return 0;
  }
  const previousArtifacts = pkg.artifacts.filter(
    (artifact) => versionKey(artifact.version) !== versionKey(latest),
  );
  return previousArtifacts.reduce(
    (total, artifact) => total + artifactVulnerabilityCount(artifact),
    0,
  );
}

function previousVersionOnlyHasVulnerabilities(pkg: DashboardPackage): boolean {
  return (
    previousVersionVulnerabilityCount(pkg) > 0 &&
    !latestVersionHasVulnerabilities(pkg) &&
    latestVersionFullyChecked(pkg)
  );
}

function statusTone(pkg: DashboardPackage): StatusTone {
  if (latestVersionHasVulnerabilities(pkg)) return "bad";
  if (previousVersionOnlyHasVulnerabilities(pkg)) return "warn";
  if (pkg.flags.includes("missing_osv") || pkg.flags.includes("partial_osv"))
    return "warn";
  if (pkg.flags.includes("vulnerabilities_found")) return "warn";
  if (pkg.flags.includes("no_known_vulnerabilities")) return "good";
  return "muted";
}

function statusLabel(pkg: DashboardPackage): string {
  if (latestVersionHasVulnerabilities(pkg)) return "Latest vulnerable";
  if (previousVersionOnlyHasVulnerabilities(pkg)) return "Previous vulnerable";
  if (pkg.flags.includes("missing_osv")) return "OSV missing";
  if (pkg.flags.includes("partial_osv")) return "OSV partial";
  if (pkg.flags.includes("vulnerabilities_found")) return "Vuln found";
  if (pkg.flags.includes("no_known_vulnerabilities")) return "No known vulns";
  if (pkg.flags.includes("missing_sbom")) return "SBOM missing";
  return "Indexed";
}

function severityTone(severity: string | null | undefined): StatusTone {
  const normalized = severity?.toUpperCase();
  if (normalized === "CRITICAL" || normalized === "HIGH") return "bad";
  if (normalized === "MEDIUM") return "warn";
  if (normalized === "LOW" || normalized === "NONE") return "good";
  return "muted";
}

function severityLabel(severity: string | null | undefined): string {
  if (!severity) return "Unknown";
  return severity.toUpperCase();
}

function severityTitle(vuln: AdvisoryVulnerability): string {
  const pieces = [`Severity: ${severityLabel(vuln.severity)}`];
  if (typeof vuln.severity_score === "number") {
    pieces.push(`score ${vuln.severity_score.toFixed(1)}`);
  }
  if (vuln.severity_source) {
    pieces.push(`source ${vuln.severity_source}`);
  }
  if (vuln.severity_vector) {
    pieces.push(vuln.severity_vector);
  }
  return pieces.join(" · ");
}

function severityRank(severity: string | null | undefined): number {
  const normalized = severity?.toUpperCase();
  if (normalized === "CRITICAL") return 5;
  if (normalized === "HIGH") return 4;
  if (normalized === "MEDIUM") return 3;
  if (normalized === "LOW") return 2;
  if (normalized === "NONE") return 1;
  return 0;
}

function vulnerabilityTimestamp(vuln: AdvisoryVulnerability): number | null {
  if (!vuln.modified) return null;
  const timestamp = Date.parse(vuln.modified);
  return Number.isFinite(timestamp) ? timestamp : null;
}

function vulnerabilitySortLabel(sort: VulnerabilitySort): string {
  return (
    VULNERABILITY_SORT_OPTIONS.find((option) => option.value === sort)?.label ?? sort
  );
}

function vulnerabilityId(vuln: AdvisoryVulnerability): string {
  return vuln.id ?? vuln.url ?? vuln.component_purl ?? "";
}

function compareVulnerabilitiesById(
  a: AdvisoryVulnerability,
  b: AdvisoryVulnerability,
): number {
  return vulnerabilityId(a).localeCompare(vulnerabilityId(b), undefined, {
    numeric: true,
  });
}

function compareNullableTimestamp(
  a: number | null,
  b: number | null,
  direction: "asc" | "desc",
): number {
  if (a === null && b === null) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return direction === "asc" ? a - b : b - a;
}

function sortVulnerabilities(
  vulnerabilities: AdvisoryVulnerability[],
  sort: VulnerabilitySort,
): AdvisoryVulnerability[] {
  return vulnerabilities.slice().sort((a, b) => {
    if (sort === "severity") {
      const severityDelta = severityRank(b.severity) - severityRank(a.severity);
      if (severityDelta !== 0) return severityDelta;
      const scoreDelta = (b.severity_score ?? -1) - (a.severity_score ?? -1);
      if (scoreDelta !== 0) return scoreDelta;
      const timeDelta = compareNullableTimestamp(
        vulnerabilityTimestamp(a),
        vulnerabilityTimestamp(b),
        "desc",
      );
      if (timeDelta !== 0) return timeDelta;
      return compareVulnerabilitiesById(a, b);
    }
    if (sort === "newest") {
      const timeDelta = compareNullableTimestamp(
        vulnerabilityTimestamp(a),
        vulnerabilityTimestamp(b),
        "desc",
      );
      if (timeDelta !== 0) return timeDelta;
      const severityDelta = severityRank(b.severity) - severityRank(a.severity);
      if (severityDelta !== 0) return severityDelta;
      return compareVulnerabilitiesById(a, b);
    }
    if (sort === "oldest") {
      const timeDelta = compareNullableTimestamp(
        vulnerabilityTimestamp(a),
        vulnerabilityTimestamp(b),
        "asc",
      );
      if (timeDelta !== 0) return timeDelta;
      const severityDelta = severityRank(b.severity) - severityRank(a.severity);
      if (severityDelta !== 0) return severityDelta;
      return compareVulnerabilitiesById(a, b);
    }
    return compareVulnerabilitiesById(a, b);
  });
}

function matchesStatusFilter(
  pkg: DashboardPackage,
  filter: PackageStatusFilter,
): boolean {
  if (filter === "all") return true;
  if (filter === "latest_vulnerable") {
    return latestVersionHasVulnerabilities(pkg);
  }
  if (filter === "previous_vulnerable") {
    return previousVersionOnlyHasVulnerabilities(pkg);
  }
  if (filter === "any_vulnerable") {
    return pkg.flags.includes("vulnerabilities_found");
  }
  if (filter === "osv_missing") return pkg.flags.includes("missing_osv");
  if (filter === "osv_partial") return pkg.flags.includes("partial_osv");
  if (filter === "no_known_vulnerabilities") {
    return pkg.flags.includes("no_known_vulnerabilities");
  }
  if (filter === "sbom_missing") return pkg.flags.includes("missing_sbom");
  return pkg.flags.includes("missing_purl");
}

function toneColors(theme: Theme, tone: StatusTone): { bg: string; fg: string } {
  if (tone === "good") {
    return {
      bg: theme.dark ? "#1f2a18" : "#edf7e5",
      fg: theme.dark ? "#9adf6d" : theme.t.good,
    };
  }
  if (tone === "bad") {
    return {
      bg: theme.dark ? "#321c18" : "#ffe4dc",
      fg: theme.dark ? "#ff9a75" : theme.t.bad,
    };
  }
  if (tone === "warn") {
    return {
      bg: theme.dark ? "#312814" : "#fff2cc",
      fg: theme.dark ? "#ffd366" : theme.t.warn,
    };
  }
  return {
    bg: theme.dark ? "#1f2631" : "#f3efe6",
    fg: theme.t.fg2,
  };
}

function Badge({
  theme,
  tone,
  children,
}: {
  theme: Theme;
  tone: StatusTone;
  children: ReactNode;
}) {
  const c = toneColors(theme, tone);
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        minHeight: 22,
        padding: "2px 7px",
        borderRadius: 4,
        background: c.bg,
        color: c.fg,
        fontSize: 10.5,
        fontWeight: 700,
        textTransform: "uppercase",
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

function SummaryMetric({
  label,
  value,
  theme,
  tone = "muted",
}: {
  label: string;
  value: string | number;
  theme: Theme;
  tone?: StatusTone;
}) {
  const c = toneColors(theme, tone);
  return (
    <div style={{ minWidth: 0 }}>
      <div
        style={{
          color: theme.t.fg2,
          fontSize: 10.5,
          fontWeight: 700,
          textTransform: "uppercase",
        }}
      >
        {label}
      </div>
      <div
        style={{
          color: tone === "muted" ? theme.t.fg1 : c.fg,
          fontVariantNumeric: "tabular-nums",
          fontSize: 19,
          fontWeight: 700,
          marginTop: 2,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
    </div>
  );
}

function SummaryCell({
  children,
  theme,
  columns = 1,
}: {
  children: ReactNode;
  theme: Theme;
  columns?: number;
}) {
  return (
    <div
      style={{
        minWidth: 0,
        padding: "8px 10px",
        borderRight: `1px solid ${theme.t.border}`,
        display: "grid",
        gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))`,
        gap: 10,
        alignItems: "center",
      }}
    >
      {children}
    </div>
  );
}

function SelectorColumn({
  title,
  items,
  selected,
  onSelect,
  theme,
  width,
  renderSuffix,
  getItemTitle,
}: {
  title: string;
  items: string[];
  selected: string | null;
  onSelect: (item: string) => void;
  theme: Theme;
  width: number;
  renderSuffix?: (item: string) => ReactNode;
  getItemTitle?: (item: string) => string;
}) {
  return (
    <section
      style={{
        width,
        minWidth: width,
        borderRight: `1px solid ${theme.t.border}`,
        background: theme.t.surface,
        minHeight: 0,
        display: "flex",
        flexDirection: "column",
      }}
    >
      <div
        style={{
          padding: "10px 12px",
          borderBottom: `1px solid ${theme.t.border}`,
          color: theme.t.fg2,
          fontSize: 11,
          fontWeight: 700,
          textTransform: "uppercase",
        }}
      >
        {title}
      </div>
      <div style={{ overflow: "auto", minHeight: 0 }}>
        {items.length === 0 ? (
          <div style={{ padding: 14, color: theme.t.fg3, fontSize: 12 }}>—</div>
        ) : (
          items.map((item) => {
            const active = item === selected;
            const suffix = renderSuffix?.(item);
            return (
              <button
                key={item}
                onClick={() => onSelect(item)}
                style={{
                  width: "100%",
                  height: DRILLDOWN_ROW_HEIGHT,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 8,
                  padding: "0 12px",
                  background: active ? theme.t.rowSelected : "transparent",
                  border: 0,
                  borderBottom: `1px solid ${theme.t.border}`,
                  color: active ? theme.t.fg1 : theme.t.fg2,
                  cursor: "pointer",
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: 12,
                  textAlign: "left",
                }}
                title={getItemTitle?.(item) ?? item}
              >
                <span
                  style={{
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {item}
                </span>
                <span
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 6,
                    flexShrink: 0,
                  }}
                >
                  {suffix}
                  {active && <Glyph name="chev" size={12} />}
                </span>
              </button>
            );
          })
        )}
      </div>
    </section>
  );
}

function ArtifactList({
  artifacts,
  selected,
  onSelect,
  theme,
}: {
  artifacts: DashboardArtifact[];
  selected: string | null;
  onSelect: (filename: string) => void;
  theme: Theme;
}) {
  return (
    <section
      style={{
        width: 270,
        minWidth: 270,
        borderRight: `1px solid ${theme.t.border}`,
        background: theme.t.surface,
        minHeight: 0,
        display: "flex",
        flexDirection: "column",
      }}
    >
      <div
        style={{
          padding: "10px 12px",
          borderBottom: `1px solid ${theme.t.border}`,
          color: theme.t.fg2,
          fontSize: 11,
          fontWeight: 700,
          textTransform: "uppercase",
        }}
      >
        Builds
      </div>
      <div style={{ overflow: "auto", minHeight: 0 }}>
        {artifacts.length === 0 ? (
          <div style={{ padding: 14, color: theme.t.fg3, fontSize: 12 }}>—</div>
        ) : (
          artifacts.map((artifact) => {
            const active = artifact.filename === selected;
            const vulnCount = artifact.osv.vulnerability_count ?? 0;
            return (
              <button
                key={artifact.filename}
                onClick={() => onSelect(artifact.filename)}
                style={{
                  width: "100%",
                  height: DRILLDOWN_ROW_HEIGHT,
                  display: "grid",
                  gridTemplateColumns: "minmax(0, 1fr) auto",
                  gap: 8,
                  alignItems: "center",
                  padding: "7px 10px",
                  background: active ? theme.t.rowSelected : "transparent",
                  border: 0,
                  borderBottom: `1px solid ${theme.t.border}`,
                  color: active ? theme.t.fg1 : theme.t.fg2,
                  cursor: "pointer",
                  textAlign: "left",
                }}
              >
                <div style={{ minWidth: 0 }}>
                  <div
                    style={{
                      fontFamily: "JetBrains Mono, monospace",
                      fontSize: 12,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={artifact.filename}
                  >
                    {artifact.build ?? artifact.filename}
                  </div>
                  <div
                    style={{
                      marginTop: 3,
                      fontSize: 10.5,
                      color: theme.t.fg3,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {artifact.filename}
                  </div>
                </div>
                <Badge
                  theme={theme}
                  tone={
                    vulnCount > 0
                      ? "bad"
                      : artifact.osv.exists
                        ? "good"
                        : "warn"
                  }
                >
                  {vulnCount > 0 ? vulnCount : artifact.osv.exists ? "OSV" : "—"}
                </Badge>
              </button>
            );
          })
        )}
      </div>
    </section>
  );
}

function DetailRow({
  label,
  children,
  theme,
}: {
  label: string;
  children: ReactNode;
  theme: Theme;
}) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "120px minmax(0, 1fr)",
        gap: 12,
        padding: "8px 0",
        borderBottom: `1px solid ${theme.t.border}`,
      }}
    >
      <div
        style={{
          color: theme.t.fg2,
          fontSize: 11,
          fontWeight: 700,
          textTransform: "uppercase",
        }}
      >
        {label}
      </div>
      <div style={{ minWidth: 0, color: theme.t.fg1, fontSize: 12 }}>
        {children}
      </div>
    </div>
  );
}

function MonospaceValue({
  value,
  theme,
}: {
  value: string | null | undefined;
  theme: Theme;
}) {
  return (
    <span
      style={{
        display: "block",
        color: value ? theme.t.fg1 : theme.t.fg3,
        fontFamily: "JetBrains Mono, monospace",
        overflowWrap: "anywhere",
        lineHeight: 1.45,
      }}
    >
      {value || "—"}
    </span>
  );
}

function VulnerabilityList({
  vulnerabilities,
  theme,
}: {
  vulnerabilities: AdvisoryVulnerability[];
  theme: Theme;
}) {
  const [sort, setSort] = useState<VulnerabilitySort>("severity");
  const sortedVulnerabilities = useMemo(
    () => sortVulnerabilities(vulnerabilities, sort),
    [vulnerabilities, sort],
  );

  if (vulnerabilities.length === 0) {
    return (
      <div style={{ color: theme.t.fg3, fontSize: 12 }}>
        No OSV findings recorded for the selected artifact.
      </div>
    );
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 10,
        }}
      >
        <span
          style={{
            color: theme.t.fg3,
            fontSize: 10.5,
            fontVariantNumeric: "tabular-nums",
          }}
        >
          {vulnerabilities.length.toLocaleString()} CVEs
        </span>
        <label
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            color: theme.t.fg2,
            fontSize: 11,
          }}
          title={`Sorted by ${vulnerabilitySortLabel(sort).toLowerCase()}`}
        >
          Sort
          <select
            value={sort}
            onChange={(event) =>
              setSort(event.target.value as VulnerabilitySort)
            }
            aria-label="Sort vulnerabilities"
            style={{
              height: 28,
              minWidth: 108,
              background: theme.t.surface2,
              border: `1px solid ${theme.t.border}`,
              borderRadius: 6,
              color: theme.t.fg1,
              outline: "none",
              fontFamily: "Inter, sans-serif",
              fontSize: 11,
              padding: "0 7px",
            }}
          >
            {VULNERABILITY_SORT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      </div>
      {sortedVulnerabilities.map((vuln, index) => (
        <div
          key={`${vuln.id}-${vuln.component_purl}-${index}`}
          style={{
            border: `1px solid ${theme.t.border}`,
            borderRadius: 6,
            padding: 9,
            background: theme.t.surface2,
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 10,
              marginBottom: 5,
            }}
          >
            <div
              style={{
                minWidth: 0,
                display: "flex",
                alignItems: "center",
                gap: 7,
              }}
            >
              {vuln.url ? (
                <a
                  href={vuln.url}
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    minWidth: 0,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    fontFamily: "JetBrains Mono, monospace",
                    fontWeight: 700,
                    color: theme.t.bad,
                    fontSize: 12,
                    textDecoration: "none",
                  }}
                >
                  {vuln.id ?? "unknown"}
                </a>
              ) : (
                <span
                  style={{
                    minWidth: 0,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    fontFamily: "JetBrains Mono, monospace",
                    fontWeight: 700,
                    color: theme.t.bad,
                    fontSize: 12,
                  }}
                >
                  {vuln.id ?? "unknown"}
                </span>
              )}
              <span title={severityTitle(vuln)}>
                <Badge theme={theme} tone={severityTone(vuln.severity)}>
                  {severityLabel(vuln.severity)}
                </Badge>
              </span>
            </div>
            <span style={{ color: theme.t.fg3, fontSize: 11 }}>
              {vuln.modified ?? ""}
            </span>
          </div>
          <MonospaceValue value={vuln.component_purl} theme={theme} />
        </div>
      ))}
    </div>
  );
}

function versionFindingRows(pkg: DashboardPackage): VersionFindingRow[] {
  return uniqueSorted(pkg.artifacts.map((artifact) => artifact.version))
    .reverse()
    .map((version) => {
      const artifacts = pkg.artifacts.filter(
        (artifact) => versionKey(artifact.version) === version,
      );
      const vulnerabilityKeys = new Set<string>();
      for (const artifact of artifacts) {
        for (const key of artifactVulnerabilityKeys(artifact)) {
          vulnerabilityKeys.add(key);
        }
      }
      return {
        version,
        artifactCount: artifacts.length,
        checkedCount: artifacts.filter((artifact) => artifact.osv.exists).length,
        vulnerabilityCount: vulnerabilityKeys.size,
      };
    });
}

function shortVersionLabel(version: string): string {
  return version.length > 12 ? `${version.slice(0, 11)}...` : version;
}

function VersionFindingsChart({
  pkg,
  selectedVersion,
  onSelectVersion,
  theme,
}: {
  pkg: DashboardPackage;
  selectedVersion: string | null;
  onSelectVersion: (version: string) => void;
  theme: Theme;
}) {
  const rows = versionFindingRows(pkg).slice().reverse();
  if (rows.length === 0) return null;
  const maxVulnerabilities = Math.max(
    1,
    ...rows.map((row) => row.vulnerabilityCount),
  );
  const chartWidth = Math.max(420, rows.length * 58 + 64);
  const chartHeight = 176;
  const margin = { top: 18, right: 18, bottom: 42, left: 34 };
  const plotWidth = chartWidth - margin.left - margin.right;
  const plotHeight = chartHeight - margin.top - margin.bottom;
  const yTicks = Array.from(
    new Set([0, Math.ceil(maxVulnerabilities / 2), maxVulnerabilities]),
  );
  const xForIndex = (index: number) =>
    margin.left +
    (rows.length === 1 ? plotWidth / 2 : (index / (rows.length - 1)) * plotWidth);
  const yForCount = (count: number) =>
    margin.top + plotHeight - (count / maxVulnerabilities) * plotHeight;
  const checkedSegments: string[][] = [];
  let currentSegment: string[] = [];
  rows.forEach((row, index) => {
    if (row.checkedCount === 0) {
      if (currentSegment.length > 0) checkedSegments.push(currentSegment);
      currentSegment = [];
      return;
    }
    currentSegment.push(`${xForIndex(index)},${yForCount(row.vulnerabilityCount)}`);
  });
  if (currentSegment.length > 0) checkedSegments.push(currentSegment);
  return (
    <section
      style={{
        padding: "10px 0 12px",
        borderTop: `1px solid ${theme.t.border}`,
        borderBottom: `1px solid ${theme.t.border}`,
        marginBottom: 2,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "baseline",
          justifyContent: "space-between",
          gap: 12,
          marginBottom: 8,
        }}
      >
        <div
          style={{
            color: theme.t.fg2,
            fontSize: 11,
            fontWeight: 700,
            textTransform: "uppercase",
          }}
        >
          Vulnerabilities by version
        </div>
        <div
          style={{
            color: theme.t.fg3,
            fontSize: 10.5,
            fontVariantNumeric: "tabular-nums",
          }}
        >
          {rows.length.toLocaleString()} versions
        </div>
      </div>
      <div
        style={{
          overflowX: "auto",
          overflowY: "hidden",
          paddingBottom: 2,
        }}
      >
        <svg
          viewBox={`0 0 ${chartWidth} ${chartHeight}`}
          width={chartWidth}
          height={chartHeight}
          role="img"
          aria-label={`${pkg.name} OSV findings by version`}
          style={{ display: "block" }}
        >
          <line
            x1={margin.left}
            y1={margin.top}
            x2={margin.left}
            y2={margin.top + plotHeight}
            stroke={theme.t.border}
          />
          {yTicks.map((tick) => {
            const y = yForCount(tick);
            return (
              <g key={tick}>
                <line
                  x1={margin.left}
                  y1={y}
                  x2={margin.left + plotWidth}
                  y2={y}
                  stroke={theme.t.border}
                  strokeDasharray={tick === 0 ? undefined : "3 4"}
                />
                <text
                  x={margin.left - 8}
                  y={y + 3}
                  textAnchor="end"
                  fill={theme.t.fg3}
                  fontSize={10}
                  fontFamily="JetBrains Mono, monospace"
                >
                  {tick}
                </text>
              </g>
            );
          })}
          {checkedSegments.map((segment, index) => (
            <polyline
              key={index}
              points={segment.join(" ")}
              fill="none"
              stroke={theme.t.bad}
              strokeWidth={2}
              strokeLinejoin="round"
              strokeLinecap="round"
              opacity={0.8}
            />
          ))}
          {rows.map((row, index) => {
            const x = xForIndex(index);
            const checked = row.checkedCount > 0;
            const y = checked ? yForCount(row.vulnerabilityCount) : yForCount(0);
            const active = versionKey(selectedVersion) === row.version;
            const vulnerable = row.vulnerabilityCount > 0;
            const pointColor = !checked
              ? theme.t.warn
              : vulnerable
                ? theme.t.bad
                : theme.t.good;
            const showVersionLabel =
              rows.length <= 8 ||
              active ||
              index === 0 ||
              index === rows.length - 1 ||
              index % Math.ceil(rows.length / 6) === 0;
            return (
              <g
                key={row.version}
                onClick={() => onSelectVersion(row.version)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelectVersion(row.version);
                  }
                }}
                role="button"
                tabIndex={0}
                style={{ cursor: "pointer", outline: "none" }}
              >
                <title>
                  {`${row.version}: ${
                    checked ? row.vulnerabilityCount : "missing OSV"
                  } unique vulnerability ID(s) across ${
                    row.artifactCount
                  } artifact(s)`}
                </title>
                <line
                  x1={x}
                  y1={margin.top + plotHeight}
                  x2={x}
                  y2={margin.top + plotHeight + 5}
                  stroke={theme.t.border}
                />
                {active && (
                  <line
                    x1={x}
                    y1={margin.top}
                    x2={x}
                    y2={margin.top + plotHeight}
                    stroke={theme.t.accent}
                    strokeDasharray="3 3"
                    opacity={0.8}
                  />
                )}
                <circle
                  cx={x}
                  cy={y}
                  r={active ? 6 : 4.5}
                  fill={pointColor}
                  stroke={active ? theme.t.accent : theme.t.page}
                  strokeWidth={active ? 2.5 : 1.5}
                />
                {vulnerable && (
                  <text
                    x={x}
                    y={Math.max(margin.top + 8, y - 10)}
                    textAnchor="middle"
                    fill={theme.t.bad}
                    fontSize={10}
                    fontWeight={700}
                    fontFamily="JetBrains Mono, monospace"
                  >
                    {row.vulnerabilityCount}
                  </text>
                )}
                {showVersionLabel && (
                  <text
                    x={x}
                    y={chartHeight - 14}
                    textAnchor="middle"
                    fill={active ? theme.t.fg1 : theme.t.fg3}
                    fontSize={10}
                    fontFamily="JetBrains Mono, monospace"
                  >
                    {shortVersionLabel(row.version)}
                  </text>
                )}
              </g>
            );
          })}
          <text
            x={chartWidth - margin.right}
            y={chartHeight - 2}
            textAnchor="end"
            fill={theme.t.fg3}
            fontSize={10}
            fontFamily="JetBrains Mono, monospace"
          >
            latest
          </text>
        </svg>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(3, max-content)",
            gap: 12,
            marginTop: 6,
            color: theme.t.fg3,
            fontSize: 10.5,
            fontVariantNumeric: "tabular-nums",
          }}
        >
          <span>
            Latest: {rows[rows.length - 1]?.version ?? "—"}
          </span>
          <span>
            Max vulns: {maxVulnerabilities}
          </span>
          <span>
            Checked: {rows.filter((row) => row.checkedCount > 0).length}/
            {rows.length}
          </span>
        </div>
      </div>
    </section>
  );
}

function ArtifactDetail({
  pkg,
  artifact,
  selectedVersion,
  onSelectVersion,
  theme,
}: {
  pkg: DashboardPackage;
  artifact: DashboardArtifact | null;
  selectedVersion: string | null;
  onSelectVersion: (version: string) => void;
  theme: Theme;
}) {
  if (!artifact) {
    return (
      <section
        style={{
          minWidth: 0,
          flex: 1,
          padding: 18,
          overflow: "auto",
          background: theme.t.page,
        }}
      >
        <h2
          style={{
            margin: "0 0 10px",
            color: theme.t.fg1,
            fontSize: 18,
          }}
        >
          {pkg.name}
        </h2>
        <VersionFindingsChart
          pkg={pkg}
          selectedVersion={selectedVersion}
          onSelectVersion={onSelectVersion}
          theme={theme}
        />
        <DetailRow label="PURL" theme={theme}>
          <PurlChip purl={pkg.mapped_purl} theme={theme} />
        </DetailRow>
        <DetailRow label="Coverage" theme={theme}>
          <span style={{ color: theme.t.fg2 }}>
            {pkg.artifact_count.toLocaleString()} indexed artifacts
          </span>
        </DetailRow>
      </section>
    );
  }

  const vulnCount = artifact.osv.vulnerability_count ?? 0;
  return (
    <section
      style={{
        minWidth: 0,
        flex: 1,
        padding: 18,
        overflow: "auto",
        background: theme.t.page,
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          gap: 14,
          marginBottom: 14,
        }}
      >
        <div style={{ minWidth: 0 }}>
          <h2
            style={{
              margin: 0,
              color: theme.t.fg1,
              fontSize: 18,
              lineHeight: 1.25,
              overflowWrap: "anywhere",
            }}
          >
            {pkg.name}
          </h2>
          <div
            style={{
              marginTop: 4,
              color: theme.t.fg2,
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 12,
              overflowWrap: "anywhere",
            }}
          >
            {artifact.filename}
          </div>
        </div>
        <Badge theme={theme} tone={vulnCount > 0 ? "bad" : "good"}>
          {vulnCount > 0 ? `${vulnCount} findings` : "No known findings"}
        </Badge>
      </div>

      <VersionFindingsChart
        pkg={pkg}
        selectedVersion={selectedVersion}
        onSelectVersion={onSelectVersion}
        theme={theme}
      />
      <DetailRow label="Mapped PURL" theme={theme}>
        <PurlChip purl={pkg.mapped_purl} theme={theme} />
      </DetailRow>
      <DetailRow label="Confidence" theme={theme}>
        {typeof pkg.purl_confidence === "number" ? (
          <ConfidenceBar score={pkg.purl_confidence} theme={theme} width={120} />
        ) : (
          <span style={{ color: theme.t.fg3 }}>—</span>
        )}
      </DetailRow>
      <DetailRow label="Component" theme={theme}>
        <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
          {artifact.component_purls.length === 0 ? (
            <span style={{ color: theme.t.fg3 }}>—</span>
          ) : (
            artifact.component_purls.map((purl) => (
              <PurlChip key={purl} purl={purl} theme={theme} />
            ))
          )}
        </div>
      </DetailRow>
      <DetailRow label="Conda PURL" theme={theme}>
        <MonospaceValue value={artifact.conda_purl} theme={theme} />
      </DetailRow>
      <DetailRow label="SBOM" theme={theme}>
        <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
          <Badge theme={theme} tone={artifact.sbom.exists ? "good" : "warn"}>
            {artifact.sbom.exists ? "exists" : "missing"}
          </Badge>
          <MonospaceValue value={artifact.sbom.path} theme={theme} />
        </div>
      </DetailRow>
      <DetailRow label="OSV" theme={theme}>
        <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
          <Badge
            theme={theme}
            tone={vulnCount > 0 ? "bad" : artifact.osv.exists ? "good" : "warn"}
          >
            {artifact.osv.status ?? (artifact.osv.exists ? "checked" : "missing")}
          </Badge>
          <MonospaceValue value={artifact.osv.path} theme={theme} />
        </div>
      </DetailRow>
      <DetailRow label="Vulnerabilities" theme={theme}>
        <VulnerabilityList vulnerabilities={artifact.vulnerabilities} theme={theme} />
      </DetailRow>
    </section>
  );
}

export function AdvisoryDashboard({ theme }: { theme: Theme }) {
  const { payload, packages, loadError } = useAdvisoryDashboardData();
  const t = theme.t;
  const [q, setQ] = useState("");
  const [statusFilter, setStatusFilter] = useState<PackageStatusFilter>("all");
  const [selectedPackageName, setSelectedPackageName] = useState<string | null>(null);
  const [selectedVersion, setSelectedVersion] = useState<string | null>(null);
  const [selectedSubdir, setSelectedSubdir] = useState<string | null>(null);
  const [selectedFilename, setSelectedFilename] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const out = packages.filter((pkg) => {
      if (!matchesStatusFilter(pkg, statusFilter)) return false;
      return needle ? pkg.name.toLowerCase().includes(needle) : true;
    });
    out.sort((a, b) => {
      const latestDelta =
        Number(latestVersionHasVulnerabilities(b)) -
        Number(latestVersionHasVulnerabilities(a));
      if (latestDelta !== 0) return latestDelta;
      const previousDelta =
        Number(previousVersionOnlyHasVulnerabilities(b)) -
        Number(previousVersionOnlyHasVulnerabilities(a));
      if (previousDelta !== 0) return previousDelta;
      const av = a.osv.total_vulnerability_findings;
      const bv = b.osv.total_vulnerability_findings;
      if (av !== bv) return bv - av;
      return a.name.localeCompare(b.name);
    });
    return out;
  }, [packages, q, statusFilter]);

  const derivedCounts = useMemo(
    () => ({
      packagesWithLatestVersionVulnerabilities: packages.filter(
        latestVersionHasVulnerabilities,
      ).length,
      packagesWithPreviousVersionVulnerabilities: packages.filter(
        previousVersionOnlyHasVulnerabilities,
      ).length,
    }),
    [packages],
  );

  useEffect(() => {
    const selectedStillVisible = filtered.some(
      (pkg) => pkg.name === selectedPackageName,
    );
    const nextPackageName = selectedStillVisible
      ? selectedPackageName
      : (filtered[0]?.name ?? null);
    if (nextPackageName !== selectedPackageName) {
      setSelectedPackageName(nextPackageName);
    }
  }, [filtered, selectedPackageName]);

  const selectedPackage = useMemo(
    () => packages.find((pkg) => pkg.name === selectedPackageName) ?? null,
    [packages, selectedPackageName],
  );

  const versionRows = useMemo(
    () => (selectedPackage ? versionFindingRows(selectedPackage) : []),
    [selectedPackage],
  );

  const versionRowsByVersion = useMemo(
    () => new Map(versionRows.map((row) => [row.version, row])),
    [versionRows],
  );

  const versions = useMemo(
    () => versionRows.map((row) => row.version),
    [versionRows],
  );

  useEffect(() => {
    if (!selectedPackage) return;
    const nextVersion = selectedPackage.latest_version ?? versions[0] ?? null;
    setSelectedVersion(nextVersion);
    setSelectedSubdir(null);
    setSelectedFilename(null);
  }, [selectedPackage, versions]);

  const versionArtifacts = useMemo(() => {
    if (!selectedPackage || !selectedVersion) return [];
    return selectedPackage.artifacts.filter(
      (artifact) => versionKey(artifact.version) === selectedVersion,
    );
  }, [selectedPackage, selectedVersion]);

  const subdirs = useMemo(
    () => uniqueSorted(versionArtifacts.map((artifact) => artifact.subdir)),
    [versionArtifacts],
  );

  useEffect(() => {
    if (!selectedVersion) return;
    setSelectedSubdir(subdirs[0] ?? null);
    setSelectedFilename(null);
  }, [selectedVersion, subdirs]);

  const buildArtifacts = useMemo(() => {
    if (!selectedSubdir) return versionArtifacts;
    return versionArtifacts.filter((artifact) => artifact.subdir === selectedSubdir);
  }, [selectedSubdir, versionArtifacts]);

  useEffect(() => {
    setSelectedFilename(buildArtifacts[0]?.filename ?? null);
  }, [buildArtifacts]);

  const selectedArtifact = useMemo(
    () =>
      buildArtifacts.find((artifact) => artifact.filename === selectedFilename) ??
      null,
    [buildArtifacts, selectedFilename],
  );

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 48,
    overscan: 8,
  });

  if (loadError) {
    return (
      <div style={{ padding: 24, color: t.bad, fontSize: 13 }}>
        Failed to load dashboard data: {loadError}
      </div>
    );
  }

  if (!payload) {
    return (
      <div
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: t.fg2,
          fontSize: 13,
        }}
      >
        Loading advisory dashboard data…
      </div>
    );
  }

  return (
    <div
      style={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        background: t.page,
        minHeight: 0,
      }}
    >
      <div
        style={{
          display: "grid",
          gridTemplateColumns: DASHBOARD_GRID_COLUMNS,
          borderBottom: `1px solid ${t.border}`,
          background: t.surface,
          minHeight: 62,
          flexShrink: 0,
        }}
      >
        <SummaryCell theme={theme} columns={2}>
          <SummaryMetric
            label="Packages"
            value={payload.counts.packages}
            theme={theme}
          />
          <SummaryMetric
            label="Artifacts"
            value={payload.counts.artifacts}
            theme={theme}
          />
        </SummaryCell>
        <SummaryCell theme={theme}>
          <SummaryMetric
            label="OSV Checked"
            value={payload.counts.packages_with_osv}
            theme={theme}
            tone="good"
          />
        </SummaryCell>
        <SummaryCell theme={theme}>
          <SummaryMetric
            label="Latest Vuln"
            value={derivedCounts.packagesWithLatestVersionVulnerabilities}
            theme={theme}
            tone="bad"
          />
        </SummaryCell>
        <SummaryCell theme={theme} columns={2}>
          <SummaryMetric
            label="Previous Vuln"
            value={derivedCounts.packagesWithPreviousVersionVulnerabilities}
            theme={theme}
            tone="warn"
          />
          <SummaryMetric
            label="Findings"
            value={payload.counts.vulnerability_findings}
            theme={theme}
            tone="bad"
          />
        </SummaryCell>
        <div
          style={{
            padding: "10px 14px",
            color: t.fg2,
            fontSize: 11,
            display: "flex",
            flexDirection: "column",
            justifyContent: "center",
            alignItems: "flex-end",
            gap: 3,
          }}
        >
          <span>{payload.generated_at}</span>
          <span
            style={{
              fontFamily: "JetBrains Mono, monospace",
              maxWidth: 420,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={payload.sources.s3_uri}
          >
            {payload.sources.s3_uri}
          </span>
        </div>
      </div>

      <div
        style={{
          flex: 1,
          minHeight: 0,
          display: "grid",
          gridTemplateColumns: DASHBOARD_GRID_COLUMNS,
          overflow: "hidden",
        }}
      >
        <section
          style={{
            borderRight: `1px solid ${t.border}`,
            background: t.surface,
            minHeight: 0,
            display: "flex",
            flexDirection: "column",
          }}
        >
          <div
            style={{
              padding: 12,
              borderBottom: `1px solid ${t.border}`,
              display: "flex",
              flexDirection: "column",
              gap: 9,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Glyph name="search" size={14} />
              <span style={{ color: t.fg1, fontSize: 13, fontWeight: 700 }}>
                Packages
              </span>
              <span
                style={{
                  color: t.fg2,
                  fontSize: 11,
                  fontVariantNumeric: "tabular-nums",
                }}
              >
                {filtered.length.toLocaleString()} / {packages.length.toLocaleString()}
              </span>
            </div>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "minmax(0, 1fr) 132px",
                gap: 7,
              }}
            >
              <div style={{ position: "relative", minWidth: 0 }}>
                <input
                  value={q}
                  onChange={(event) => setQ(event.target.value)}
                  placeholder="Search package"
                  style={{
                    width: "100%",
                    height: 34,
                    background: t.surface2,
                    border: `1px solid ${t.border}`,
                    borderRadius: 7,
                    padding: "0 30px 0 10px",
                    color: t.fg1,
                    outline: "none",
                    fontFamily: "Inter, sans-serif",
                    fontSize: 13,
                  }}
                />
                {q && (
                  <button
                    onClick={() => setQ("")}
                    style={{
                      position: "absolute",
                      right: 4,
                      top: 4,
                      width: 26,
                      height: 26,
                      border: 0,
                      background: "transparent",
                      color: t.fg3,
                      cursor: "pointer",
                    }}
                    aria-label="Clear package search"
                  >
                    <Glyph name="close" size={12} />
                  </button>
                )}
              </div>
              <select
                value={statusFilter}
                onChange={(event) =>
                  setStatusFilter(event.target.value as PackageStatusFilter)
                }
                aria-label="Filter packages by status"
                style={{
                  width: "100%",
                  height: 34,
                  minWidth: 0,
                  background: t.surface2,
                  border: `1px solid ${t.border}`,
                  borderRadius: 7,
                  color: t.fg1,
                  outline: "none",
                  fontFamily: "Inter, sans-serif",
                  fontSize: 12,
                  padding: "0 8px",
                }}
              >
                {PACKAGE_STATUS_FILTERS.map((filter) => (
                  <option key={filter.value} value={filter.value}>
                    {filter.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div ref={scrollRef} style={{ flex: 1, overflow: "auto", minHeight: 0 }}>
            <div
              style={{
                height: virtualizer.getTotalSize(),
                position: "relative",
                width: "100%",
              }}
            >
              {virtualizer.getVirtualItems().map((vi) => {
                const pkg = filtered[vi.index];
                const active = pkg.name === selectedPackageName;
                const tone = statusTone(pkg);
                return (
                  <button
                    key={pkg.name}
                    onClick={() => setSelectedPackageName(pkg.name)}
                    style={{
                      position: "absolute",
                      top: 0,
                      left: 0,
                      width: "100%",
                      height: vi.size,
                      transform: `translateY(${vi.start}px)`,
                      display: "grid",
                      gridTemplateColumns: "minmax(0, 1fr) auto",
                      alignItems: "center",
                      gap: 8,
                      padding: "6px 10px",
                      border: 0,
                      borderBottom: `1px solid ${t.border}`,
                      background: active ? t.rowSelected : "transparent",
                      color: t.fg1,
                      cursor: "pointer",
                      textAlign: "left",
                    }}
                  >
                    <div style={{ minWidth: 0 }}>
                      <div
                        style={{
                          fontFamily: "JetBrains Mono, monospace",
                          fontSize: 12.5,
                          fontWeight: 700,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                        title={pkg.name}
                      >
                        {pkg.name}
                      </div>
                      <div
                        style={{
                          color: t.fg3,
                          fontSize: 10.5,
                          marginTop: 2,
                          fontVariantNumeric: "tabular-nums",
                        }}
                      >
                        {pkg.artifact_count} artifacts · {pkg.latest_version ?? "—"}
                      </div>
                    </div>
                    <Badge theme={theme} tone={tone}>
                      {statusLabel(pkg)}
                    </Badge>
                  </button>
                );
              })}
            </div>
          </div>
        </section>

        {selectedPackage ? (
          <>
            <SelectorColumn
              title="Versions"
              items={versions}
              selected={selectedVersion}
              onSelect={setSelectedVersion}
              theme={theme}
              width={160}
              renderSuffix={(version) => {
                const row = versionRowsByVersion.get(version);
                if (!row) return null;
                return (
                  <Badge
                    theme={theme}
                    tone={
                      row.vulnerabilityCount > 0
                        ? "bad"
                        : row.checkedCount > 0
                          ? "good"
                          : "warn"
                    }
                  >
                    {row.vulnerabilityCount}
                  </Badge>
                );
              }}
              getItemTitle={(version) => {
                const row = versionRowsByVersion.get(version);
                if (!row) return version;
                const checkedSuffix =
                  row.checkedCount === row.artifactCount
                    ? ""
                    : `; OSV checked for ${row.checkedCount}/${row.artifactCount}`;
                return `${version}: ${row.vulnerabilityCount} unique vulnerability ID(s) across ${row.artifactCount} artifact(s)${checkedSuffix}`;
              }}
            />
            <SelectorColumn
              title="Platforms"
              items={subdirs}
              selected={selectedSubdir}
              onSelect={setSelectedSubdir}
              theme={theme}
              width={150}
            />
            <ArtifactList
              artifacts={buildArtifacts}
              selected={selectedFilename}
              onSelect={setSelectedFilename}
              theme={theme}
            />
            <ArtifactDetail
              pkg={selectedPackage}
              artifact={selectedArtifact}
              selectedVersion={selectedVersion}
              onSelectVersion={setSelectedVersion}
              theme={theme}
            />
          </>
        ) : (
          <div
            style={{
              gridColumn: "2 / -1",
              color: t.fg3,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 13,
            }}
          >
            No package selected.
          </div>
        )}
      </div>
    </div>
  );
}
