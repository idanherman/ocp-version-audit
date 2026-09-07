---
name: ocp-zstream-audit
description: >-
  Perform a comprehensive risk audit of OpenShift z-stream versions in an upgrade path.
  Queries Cincinnati graph, release controller changelogs, Red Hat Errata MCP, and
  cross-version CVE data to find known bugs, unpatched CVEs, and operational risks.
  Use when a consultant asks about known bugs in specific z-streams, upgrade risk
  analysis, or proactive bug hunting before an OpenShift upgrade.
disable-model-invocation: true
---

# OCP Z-Stream Upgrade Risk Audit

Systematically find known bugs, unpatched CVEs, and operational risks in specific
OpenShift z-stream versions that a customer will use during an upgrade.

## Prerequisites

- Python 3.10+ with `requests` installed (check workspace `.venv/`)
- Red Hat Security MCP server configured in `.mcp.json` (namespace: `user-red-hat-security`)
- Internet access to `api.openshift.com` and `openshift-release.apps.ci.l2s4.p1.openshiftapps.com`

## Step 1: Collect Inputs

Ask the consultant for:

1. **Upgrade path** — exact z-stream versions for masters and workers:
   ```
   Masters: 4.12.40 → 4.13.59 → 4.14.56 → 4.15.58 → 4.16.50
   Workers: 4.12.40 → 4.14.56 → 4.16.50
   ```
2. **Target version** — which version the customer will stay on (e.g., 4.16.50)
3. **Architecture** — amd64, arm64, ppc64le, s390x (default: amd64)
4. **Customer environment profile**:
   - Platform: BareMetal / vSphere / AWS / Azure / GCP / None
   - CNI: OpenShiftSDN / OVNKubernetes
   - Ingress: HostNetwork / LoadBalancerService / NodePortService
   - Storage: ODF/Ceph / NFS / iSCSI / vSphere CSI / EBS / other
   - Special: multus/whereabouts, EgressIP, external gateways, IPsec
   - Disconnected: yes/no (affects ICSP/IDMS, registry mirror size)
   - Operators: ACM, ODF, CNV, Trident, Loki, etc.
   - etcd encryption: enabled/disabled
5. **Known cases/KCS** — any previous cases the consultant wants included

## Step 2: Run Cincinnati Graph Check

Run the script for each upgrade channel (stable, eus, fast — prefer eus for EUS versions):

```bash
.venv/bin/python3 scripts/ocp_zstream_audit.py cincinnati \
  --masters 4.12.40 4.13.59 4.14.56 4.15.58 4.16.50 \
  --workers 4.12.40 4.14.56 4.16.50 \
  --output audit_data/cincinnati.json
```

Also check EUS channels for version availability:
- 4.13.x should be in `eus-4.14` (not just stable-4.13)
- 4.15.x should be in `eus-4.16` (not just stable-4.15)

Report: conditional edges, version availability, and upgrade-blocking risks per hop.

## Step 3: Run Release Controller Changelog Check

For the **target version** (where the customer stays), fetch per-z-stream changelogs
to map each bug to its exact fix version:

```bash
.venv/bin/python3 scripts/ocp_zstream_audit.py changelog \
  --version 4.16.50 \
  --output audit_data/changelog_4.16.json
```

Repeat for each transient version in the path:
```bash
.venv/bin/python3 scripts/ocp_zstream_audit.py changelog \
  --version 4.13.59 --version 4.14.56 --version 4.15.58 \
  --output audit_data/changelog_transient.json
```

This fetches the changelog for every z-stream increment (e.g., 4.16.50→51, 51→52, ...)
and maps each OCPBUGS to its first-appearance z-stream.

## Step 4: Run Red Hat Errata Check (MCP)

If the Red Hat Security MCP is authenticated (namespace: `user-red-hat-security`), query it directly.
If not, authenticate first via `mcp_auth`, then:

1. **Search advisories** for the target version after the customer's z-stream:
   - Filter: `portal_product_filter:Red\ Hat\ OpenShift\ Container\ Platform|*|4.16|*`
   - Date filter: from the customer's z-stream release date to now
   - Pull ALL pages (rows=50, paginate with start=0,50,100,...)

2. **For each RHSA** (security advisory), extract CVE list, severity, z-stream

3. **For high-priority CVEs** (Critical, Important with CVSS >= 7.0), use `get_cve_by_id`
   to get full details: description, affected packages, mitigation, CVSS score

4. Repeat for transient versions (4.13, 4.14, 4.15)

Save all results to `audit_data/errata.json`.

## Step 5: Run Cross-Version CVE Search

Search for CVEs found in NEWER OCP versions (4.17, 4.18, ..., latest) that also affect
the customer's target version but have NO fix there:

1. For each newer version, use `search_advisories` to find recent security advisories
2. For each CVE found, use `list_cve_affected_products` to check if the target version
   is listed as "Affected" (not "Fixed")
3. Focus on Important/Critical CVEs with CVSS >= 7.0

Save to `audit_data/cross_version.json`.

## Step 6: Categorize and Filter

Categorize ALL findings by component area:
- networking, mco, apiserver, ingress, storage, monitoring, runtime, kernel,
  certificates, upgrade, disconnected, operators, vsphere, aws, azure, gcp, other

Then apply the customer profile to mark each finding as:
- **relevant** — matches customer's platform/CNI/config
- **conditional** — applies only if customer uses a specific feature (EgressIP, multus, etc.)
- **irrelevant** — wrong platform, wrong CNI, hypershift-only, etc.

**NEVER discard irrelevant findings.** Collapse them in the output but keep all data.

## Step 7: Identify Never-Backported Bugs

Search for known bugs fixed in newer minor versions that were never backported to the
target version. Check:
- OCPBUGS-56594 (kube-apiserver concurrent map crash — 4.17+)
- OCPBUGS-84534 (openshift-apiserver RBAC cache race — 4.20+)
- OCPBUGS-60628 (cert rotation controller metadata fight — 4.19+)
- OCPBUGS-62619 (MachineConfig etcd size validation — 4.17+)

Note: This list is not exhaustive. The cross-version CVE search (Step 5) partially
covers this, but functional bugs without CVEs require JIRA access to find systematically.

## Step 8: Render Canvas

Create a canvas at `canvases/ocp-zstream-audit-{target_version}.canvas.tsx` with:

1. **Overview tab**: Stats (CVE count, errata count, bug count), z-stream timeline chart,
   Cincinnati conditional edges
2. **CVEs tab**: All CVEs with CVSS, component, fix z-stream, customer relevance filter.
   Include pills to toggle: Relevant / All / By Category
3. **Bugs tab**: All functional bugs grouped by category with risk-focused descriptions.
   Each bug MUST show: bug ID (linked), component, description of customer-facing RISK
   (not just the fix title), and the exact z-stream that fixes it. Show ALL bugs, not examples.
4. **Transient Versions tab**: Errata for versions passed through during upgrade
5. **Cross-Version tab**: CVEs from newer versions that affect the target, never-backported bugs
6. **KCS / Case Knowledge tab**: Consultant-provided cases/KCS. Be transparent about sources.
7. **Data Sources tab**: What each source covers and what it misses. Include honest gaps.

## Step 9: Flag Gaps

Explicitly state in the canvas what the analysis does NOT cover:
- Red Hat internal JIRA queries (Affects Version fields for cross-version bugs)
- KCS article discovery (no search API — consultant must bring their own)
- RHCOS RPM-level diff (partially covered by errata, but not exhaustive)
- Operator compatibility matrices (ODF, ACM, CNV version requirements)
- TAM-level proactive bug notifications

## Output Structure

All data saved to `audit_data/` directory:
```
audit_data/
├── cincinnati.json         # Conditional edges per hop
├── changelog_4.16.json     # Per-z-stream bug mapping for target version
├── changelog_transient.json # Bugs in transient versions
├── errata.json             # Full errata + CVE data from MCP
├── cross_version.json      # CVEs from newer versions affecting target
└── summary.json            # Combined summary for canvas consumption
```

Canvas output: `canvases/ocp-zstream-audit-{target_version}.canvas.tsx`
