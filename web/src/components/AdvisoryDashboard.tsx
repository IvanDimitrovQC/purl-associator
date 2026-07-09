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

function uniqueSorted(values: Array<string | null | undefined>): string[] {
  return Array.from(new Set(values.filter((value): value is string => Boolean(value))))
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
}

function versionKey(version: string | null): string {
  return version ?? "unknown";
}

function statusTone(pkg: DashboardPackage): StatusTone {
  if (pkg.flags.includes("vulnerabilities_found")) return "bad";
  if (pkg.flags.includes("missing_osv") || pkg.flags.includes("partial_osv"))
    return "warn";
  if (pkg.flags.includes("no_known_vulnerabilities")) return "good";
  return "muted";
}

function statusLabel(pkg: DashboardPackage): string {
  if (pkg.flags.includes("vulnerabilities_found")) return "Vulnerable";
  if (pkg.flags.includes("missing_osv")) return "OSV missing";
  if (pkg.flags.includes("partial_osv")) return "OSV partial";
  if (pkg.flags.includes("no_known_vulnerabilities")) return "No known vulns";
  if (pkg.flags.includes("missing_sbom")) return "SBOM missing";
  return "Indexed";
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

function Metric({
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
    <div
      style={{
        minWidth: 120,
        padding: "8px 10px",
        borderRight: `1px solid ${theme.t.border}`,
      }}
    >
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
          fontSize: 20,
          fontWeight: 700,
          marginTop: 2,
        }}
      >
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
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
}: {
  title: string;
  items: string[];
  selected: string | null;
  onSelect: (item: string) => void;
  theme: Theme;
  width: number;
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
            return (
              <button
                key={item}
                onClick={() => onSelect(item)}
                style={{
                  width: "100%",
                  height: 34,
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
                title={item}
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
                {active && <Glyph name="chev" size={12} />}
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
                  minHeight: 46,
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
  if (vulnerabilities.length === 0) {
    return (
      <div style={{ color: theme.t.fg3, fontSize: 12 }}>
        No OSV findings recorded for the selected artifact.
      </div>
    );
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {vulnerabilities.map((vuln, index) => (
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
            {vuln.url ? (
              <a
                href={vuln.url}
                target="_blank"
                rel="noreferrer"
                style={{
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
                  fontFamily: "JetBrains Mono, monospace",
                  fontWeight: 700,
                  color: theme.t.bad,
                  fontSize: 12,
                }}
              >
                {vuln.id ?? "unknown"}
              </span>
            )}
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

function ArtifactDetail({
  pkg,
  artifact,
  theme,
}: {
  pkg: DashboardPackage;
  artifact: DashboardArtifact | null;
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
  const [selectedPackageName, setSelectedPackageName] = useState<string | null>(null);
  const [selectedVersion, setSelectedVersion] = useState<string | null>(null);
  const [selectedSubdir, setSelectedSubdir] = useState<string | null>(null);
  const [selectedFilename, setSelectedFilename] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const out = packages.filter((pkg) =>
      needle ? pkg.name.toLowerCase().includes(needle) : true,
    );
    out.sort((a, b) => {
      const av = a.osv.total_vulnerability_findings;
      const bv = b.osv.total_vulnerability_findings;
      if (av !== bv) return bv - av;
      return a.name.localeCompare(b.name);
    });
    return out;
  }, [packages, q]);

  useEffect(() => {
    if (!selectedPackageName && filtered.length > 0) {
      setSelectedPackageName(filtered[0].name);
    }
  }, [filtered, selectedPackageName]);

  const selectedPackage = useMemo(
    () => packages.find((pkg) => pkg.name === selectedPackageName) ?? null,
    [packages, selectedPackageName],
  );

  const versions = useMemo(
    () =>
      uniqueSorted(
        selectedPackage?.artifacts.map((artifact) => artifact.version) ?? [],
      ).reverse(),
    [selectedPackage],
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
          display: "flex",
          alignItems: "stretch",
          borderBottom: `1px solid ${t.border}`,
          background: t.surface,
          minHeight: 62,
          flexShrink: 0,
        }}
      >
        <Metric label="Packages" value={payload.counts.packages} theme={theme} />
        <Metric label="Artifacts" value={payload.counts.artifacts} theme={theme} />
        <Metric
          label="OSV Checked"
          value={payload.counts.packages_with_osv}
          theme={theme}
          tone="good"
        />
        <Metric
          label="Vulnerable"
          value={payload.counts.packages_with_vulnerabilities}
          theme={theme}
          tone="bad"
        />
        <Metric
          label="Findings"
          value={payload.counts.vulnerability_findings}
          theme={theme}
          tone="bad"
        />
        <div
          style={{
            marginLeft: "auto",
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
          gridTemplateColumns: "310px 160px 150px 270px minmax(360px, 1fr)",
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
            <div style={{ position: "relative" }}>
              <input
                value={q}
                onChange={(event) => setQ(event.target.value)}
                placeholder="Search package name"
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
                >
                  <Glyph name="close" size={12} />
                </button>
              )}
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
            <ArtifactDetail pkg={selectedPackage} artifact={selectedArtifact} theme={theme} />
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
