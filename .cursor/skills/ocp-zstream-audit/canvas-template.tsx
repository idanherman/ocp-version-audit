// Canvas Template for OCP Z-Stream Audit
// ────────────────────────────────────────────────────────────────────
// The agent should COPY this template and fill in the data arrays below
// from the audit_data/*.json files. Do NOT use fetch() — embed all data inline.
//
// File: canvases/ocp-zstream-audit-{version}.canvas.tsx
// Example: canvases/ocp-zstream-audit-4.16.50.canvas.tsx

import {
  useState,
  useMemo,
  Stack,
  Row,
  Grid,
  H1,
  H2,
  H3,
  Text,
  Table,
  Card,
  CardHeader,
  CardBody,
  Stat,
  Pill,
  Callout,
  Divider,
  Link,
  Code,
  CollapsibleSection,
  BarChart,
  useHostTheme,
} from "cursor/canvas";

// ┌──────────────────────────────────────────────────────────────────────┐
// │ FILL IN: Replace these with actual data from audit_data/*.json      │
// └──────────────────────────────────────────────────────────────────────┘

const AUDIT_META = {
  targetVersion: "4.16.50",           // Customer's target version
  customerName: "Example Customer",    // For the title
  customerConfig: "SDN, HostNetwork, vSphere UPI, air-gapped",
  upgradePath: "4.12.40 → 4.13.59 → 4.14.56 → 4.15.58 → 4.16.50",
  generatedDate: new Date().toLocaleDateString(),
};

// From audit_data/changelog_target.json — bugs with per-z-stream fix mapping
// EVERY bug must have: id, component, description (RISK-focused), fixed_in_z, relevance
const BUGS: {
  id: string;
  component: string;
  description: string;
  fixed_in_z: number;
  is_cve: boolean;
  relevance: "relevant" | "conditional" | "irrelevant";
  category: string;
}[] = [
  // FILL IN from audit data — example:
  // { id: "OCPBUGS-62171", component: "machine-config-operator",
  //   description: "NM restart makes br-ex unusable → NODE NETWORK LOSS (bond+custom br-ex)",
  //   fixed_in_z: 65, is_cve: false, relevance: "conditional", category: "mco" },
];

// From audit_data/errata.json — CVEs with severity, CVSS, fix z-stream
const CVES: {
  id: string;
  cvss: number;
  severity: string;
  component: string;
  description: string;
  fixed_in_z: number;
  relevance: "relevant" | "conditional" | "irrelevant";
  note: string;
}[] = [
  // FILL IN from errata MCP data
];

// From audit_data/cincinnati.json — conditional edges per hop
const HOPS: {
  from: string;
  to: string;
  type: string;
  risks: { name: string; message: string; url: string; applies_when: string }[];
}[] = [
  // FILL IN from cincinnati check
];

// Cross-version: CVEs from newer OCP affecting this version with no fix
const CROSS_VERSION_UNFIXED: {
  id: string;
  cvss: number;
  component: string;
  description: string;
  fixStatus: string;
}[] = [
  // FILL IN from cross-version CVE search
];

// Never-backported bugs
const NEVER_BACKPORTED: {
  id: string;
  description: string;
  fixedIn: string;
  risk: string;
}[] = [
  // FILL IN — see reference.md for known list
];

// Z-stream errata timeline (from errata MCP search)
const ZSTREAM_ERRATA: {
  z: number;
  secCount: number;
  bugCount: number;
  cveCount: number;
  maxSev: string;
}[] = [
  // FILL IN from errata data
];

// KCS / Case-discovered risks (consultant-provided)
const KCS_RISKS: {
  kcs: string;
  title: string;
  condition: string;
  risk: string;
  source: string;
}[] = [
  // FILL IN from consultant input
];

// ┌──────────────────────────────────────────────────────────────────────┐
// │ Component — do NOT modify below unless extending the template       │
// └──────────────────────────────────────────────────────────────────────┘

type Section = "overview" | "cves" | "bugs" | "hops" | "crossver" | "kcs" | "sources";

export default function ZStreamAudit() {
  const [section, setSection] = useState<Section>("overview");
  const [relevanceFilter, setRelevanceFilter] = useState<"relevant" | "all">("relevant");

  const filteredBugs = relevanceFilter === "relevant"
    ? BUGS.filter((b) => b.relevance !== "irrelevant")
    : BUGS;

  const filteredCVEs = relevanceFilter === "relevant"
    ? CVES.filter((c) => c.relevance !== "irrelevant")
    : CVES;

  const totalCVEs = CVES.length;
  const totalBugs = BUGS.filter((b) => !b.is_cve).length;

  // Group bugs by category
  const bugsByCategory = useMemo(() => {
    const map = new Map<string, typeof BUGS>();
    for (const b of filteredBugs.filter((b) => !b.is_cve)) {
      const list = map.get(b.category) || [];
      list.push(b);
      map.set(b.category, list);
    }
    return [...map.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [filteredBugs]);

  const cumulativeCVEs = useMemo(() => {
    let cum = 0;
    return ZSTREAM_ERRATA.map((z) => {
      cum += z.cveCount;
      return cum;
    });
  }, []);

  const sections: { key: Section; label: string }[] = [
    { key: "overview", label: "Overview" },
    { key: "cves", label: `CVEs (${totalCVEs})` },
    { key: "bugs", label: `Bugs (${totalBugs})` },
    { key: "hops", label: "Upgrade Hops" },
    { key: "crossver", label: "Cross-Version" },
    { key: "kcs", label: "KCS / Cases" },
    { key: "sources", label: "Data Sources" },
  ];

  return (
    <Stack gap={20}>
      <Stack gap={4}>
        <H1>OCP {AUDIT_META.targetVersion} — Z-Stream Risk Audit</H1>
        <Text tone="secondary">{AUDIT_META.customerName} — {AUDIT_META.customerConfig}</Text>
        <Text tone="secondary" size="small">
          Path: {AUDIT_META.upgradePath} — Generated: {AUDIT_META.generatedDate}
        </Text>
      </Stack>

      <Grid columns={5} gap={10}>
        <Stat value={String(totalCVEs)} label="Unpatched CVEs" tone="danger" />
        <Stat value={String(ZSTREAM_ERRATA.reduce((s, z) => s + z.secCount + z.bugCount, 0))} label="Missing Errata" tone="warning" />
        <Stat value={String(totalBugs)} label="Functional Bugs" tone="warning" />
        <Stat value={String(CROSS_VERSION_UNFIXED.length)} label="Unfixed Cross-Ver" tone="danger" />
        <Stat value={String(NEVER_BACKPORTED.length)} label="Never Backported" tone="info" />
      </Grid>

      <Row gap={6} wrap>
        {sections.map((s) => (
          <span key={s.key}>
            <Pill active={section === s.key} onClick={() => setSection(s.key)}>
              {s.label}
            </Pill>
          </span>
        ))}
      </Row>

      <Row gap={8}>
        <Pill active={relevanceFilter === "relevant"} onClick={() => setRelevanceFilter("relevant")}>
          Customer-Relevant
        </Pill>
        <Pill active={relevanceFilter === "all"} onClick={() => setRelevanceFilter("all")}>
          All Findings
        </Pill>
      </Row>

      <Divider />

      {section === "overview" && (
        <Stack gap={16}>
          {ZSTREAM_ERRATA.length > 0 && (
            <>
              <H2>CVE Accumulation</H2>
              <BarChart
                categories={ZSTREAM_ERRATA.map((z) => `.${z.z}`)}
                series={[{ name: "Cumulative CVEs", data: cumulativeCVEs }]}
                height={240}
              />
            </>
          )}
          {ZSTREAM_ERRATA.length > 0 && (
            <>
              <H2>Errata by Z-Stream</H2>
              <Table
                headers={["Z-Stream", "Security", "Bug Fix", "CVEs", "Max Severity"]}
                columnAlign={["left", "right", "right", "right", "center"]}
                rows={ZSTREAM_ERRATA.map((z) => [
                  <Code>{AUDIT_META.targetVersion.split(".").slice(0, 2).join(".")}.{z.z}</Code>,
                  String(z.secCount), String(z.bugCount), String(z.cveCount),
                  <Pill active={z.maxSev === "Critical"} size="sm">{z.maxSev}</Pill>,
                ])}
                rowTone={ZSTREAM_ERRATA.map((z) =>
                  z.maxSev === "Critical" ? "danger" : z.maxSev === "Important" ? "warning" : "neutral"
                )}
                striped stickyHeader
              />
            </>
          )}
        </Stack>
      )}

      {section === "cves" && (
        <Stack gap={16}>
          <H2>Security Vulnerabilities</H2>
          <Table
            headers={["CVE", "CVSS", "Sev", "Component", "Description", "Fixed In", "Note"]}
            columnAlign={["left", "right", "center", "left", "left", "left", "left"]}
            rows={filteredCVEs.map((c) => [
              <Link href={`https://access.redhat.com/security/cve/${c.id}`}>{c.id}</Link>,
              <Text weight="bold">{c.cvss.toFixed(1)}</Text>,
              c.severity,
              <Code>{c.component}</Code>,
              c.description,
              <Code>.{c.fixed_in_z}</Code>,
              <Text size="small" tone="secondary">{c.note}</Text>,
            ])}
            rowTone={filteredCVEs.map((c) =>
              c.severity === "Critical" ? "danger" : c.cvss >= 8 ? "warning" : "info"
            )}
            striped stickyHeader
          />
        </Stack>
      )}

      {section === "bugs" && (
        <Stack gap={16}>
          <H2>Functional Bugs</H2>
          <Text tone="secondary">
            {filteredBugs.filter((b) => !b.is_cve).length} bugs. Each shows the exact z-stream that fixes it.
          </Text>
          {bugsByCategory.map(([category, bugs]) => (
            <div key={category}>
              <CollapsibleSection title={`${category} — ${bugs.length} bugs`} count={bugs.length} defaultOpen={bugs.length >= 5}>
                <Table
                  headers={["Bug", "Fixed In", "Description"]}
                  columnAlign={["left", "left", "left"]}
                  rows={bugs.map((b) => [
                    <Link href={`https://issues.redhat.com/browse/${b.id}`}>{b.id}</Link>,
                    <Code>.{b.fixed_in_z}</Code>,
                    <Text size="small">{b.description}</Text>,
                  ])}
                  rowTone={bugs.map((b) =>
                    b.relevance === "relevant" ? "warning" : b.relevance === "conditional" ? "info" : "neutral"
                  )}
                  striped
                />
              </CollapsibleSection>
            </div>
          ))}
        </Stack>
      )}

      {section === "hops" && (
        <Stack gap={16}>
          <H2>Upgrade Hop Conditional Edges (Cincinnati)</H2>
          {HOPS.map((hop) => (
            <div key={`${hop.from}-${hop.to}`}>
              <Card collapsible defaultOpen={hop.risks.length > 0}>
                <CardHeader trailing={<Pill size="sm" active={hop.risks.length > 0}>{hop.risks.length} risks</Pill>}>
                  {hop.from} → {hop.to} ({hop.type})
                </CardHeader>
                <CardBody>
                  {hop.risks.length === 0 ? (
                    <Text tone="secondary">No conditional update risks found.</Text>
                  ) : (
                    <Table
                      headers={["Risk", "Description", "Applies When"]}
                      rows={hop.risks.map((r) => [
                        <Link href={r.url}>{r.name}</Link>,
                        <Text size="small">{r.message.slice(0, 150)}</Text>,
                        r.applies_when,
                      ])}
                      rowTone={hop.risks.map((r) =>
                        r.applies_when === "Always" ? "danger" : "warning"
                      )}
                    />
                  )}
                </CardBody>
              </Card>
            </div>
          ))}
        </Stack>
      )}

      {section === "crossver" && (
        <Stack gap={16}>
          <H2>Cross-Version: Unfixed in {AUDIT_META.targetVersion}</H2>
          {CROSS_VERSION_UNFIXED.length > 0 && (
            <Table
              headers={["CVE", "CVSS", "Component", "Description", "Fix Status"]}
              rows={CROSS_VERSION_UNFIXED.map((c) => [
                <Link href={`https://access.redhat.com/security/cve/${c.id}`}>{c.id}</Link>,
                <Text weight="bold">{c.cvss.toFixed(1)}</Text>,
                <Code>{c.component}</Code>,
                c.description,
                <Pill active size="sm">{c.fixStatus}</Pill>,
              ])}
              rowTone={CROSS_VERSION_UNFIXED.map((c) =>
                c.fixStatus.includes("NO FIX") ? "danger" : "warning"
              )}
            />
          )}
          <H3>Bugs Never Backported</H3>
          {NEVER_BACKPORTED.length > 0 && (
            <Table
              headers={["Bug", "Description", "Fixed In", "Risk"]}
              rows={NEVER_BACKPORTED.map((b) => [
                <Link href={`https://issues.redhat.com/browse/${b.id}`}>{b.id}</Link>,
                b.description, <Code>{b.fixedIn}</Code>,
                <Text size="small">{b.risk}</Text>,
              ])}
              rowTone={NEVER_BACKPORTED.map(() => "warning" as const)}
            />
          )}
        </Stack>
      )}

      {section === "kcs" && (
        <Stack gap={16}>
          <H2>KCS / Case-Discovered Risks</H2>
          <Callout tone="info" title="Source transparency">
            These come from the consultant's own case history and KCS knowledge, not from automated tools.
          </Callout>
          {KCS_RISKS.length > 0 && (
            <Table
              headers={["KCS", "Issue", "Condition", "Risk", "Source"]}
              rows={KCS_RISKS.map((r) => [
                <Code>{r.kcs}</Code>,
                <Text weight="semibold">{r.title}</Text>,
                <Text size="small">{r.condition}</Text>,
                <Text size="small">{r.risk}</Text>,
                <Text size="small" tone="tertiary">{r.source}</Text>,
              ])}
              rowTone={KCS_RISKS.map(() => "warning" as const)}
            />
          )}
        </Stack>
      )}

      {section === "sources" && (
        <Stack gap={16}>
          <H2>Data Sources and Coverage Gaps</H2>
          <Table
            headers={["Source", "Covers", "Misses"]}
            rows={[
              ["Red Hat Errata (MCP)", "Full: container images + RHCOS RPMs", "KCS-only operational issues"],
              ["Release Controller", "Container image OCPBUGS with per-z-stream fix version", "RHCOS RPM layer"],
              ["Cincinnati Graph", "Conditional upgrade edges, blocked paths", "Bugs that don't block upgrades"],
              ["Cross-Version CVE Search", "CVEs in newer versions also affecting target", "Non-CVE functional bugs"],
              ["KCS / Cases", "Operational risks, state corruption", "Only what consultant brings"],
            ]}
            striped
          />
          <Callout tone="info" title="Not covered by this audit">
            Red Hat internal JIRA (Affects Version cross-referencing), full RHCOS RPM diff,
            operator compatibility matrices (ODF/ACM/CNV versions), TAM-level proactive notifications.
          </Callout>
        </Stack>
      )}
    </Stack>
  );
}
