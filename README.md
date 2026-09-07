# ocp-version-audit

Find known bugs, unpatched CVEs, and operational risks in specific OpenShift z-stream versions.

Works for upgrade planning ("what will we hit during 4.12 → 4.16?") and steady-state auditing ("what's wrong with the 4.16.50 we're running?").

## What it does

Queries 5 data sources and produces a visual risk report:

| Source | Auth Required | What It Finds |
|--------|--------------|---------------|
| **Cincinnati Graph API** | No | Conditional upgrade edges, blocked paths |
| **Release Controller** | No | Per-z-stream bug mapping (which exact version fixes each bug) |
| **Red Hat Errata MCP** | Red Hat SSO | Full CVE + advisory data including RHCOS kernel/runc/sudo |
| **Cross-Version CVE Search** | Red Hat SSO | CVEs from 4.17+ that also affect your version |
| **KCS / Case Knowledge** | Manual | Operational risks you bring from experience |

## Quick Start

### 1. Clone this repo as your workspace

```bash
git clone https://github.com/idanherman/ocp-version-audit.git
cd ocp-version-audit
pip install requests
```

### 2. Open in Cursor

The `.cursor/skills/ocp-zstream-audit/` directory is auto-discovered.

### 3. Run the audit

Tell Cursor:
> "Audit OCP 4.16.50 for my customer on vSphere with SDN and HostNetwork routers"

Or use the CLI directly:
```bash
# Cincinnati conditional edges
python scripts/ocp_zstream_audit.py cincinnati \
  --masters 4.12.40 4.13.59 4.14.56 4.15.58 4.16.50 \
  --workers 4.12.40 4.14.56 4.16.50 \
  --output audit_data/cincinnati.json

# Per-z-stream bug mapping
python scripts/ocp_zstream_audit.py changelog \
  --version 4.16.50 \
  --output audit_data/changelog.json
```

### 4. Red Hat Errata (optional, requires Red Hat SSO)

The `.mcp.json` configures the Red Hat Security MCP server. On first use, Cursor will prompt for Red Hat SSO login. This unlocks:
- Full errata advisory search (RHSA/RHBA per z-stream)
- CVE details with CVSS scores and affected products
- Cross-version CVE search (find bugs in 4.17+ that also affect your version)

Without it, the Cincinnati and release controller checks still work.

## Output

The skill produces:
- **JSON data** in `audit_data/` for programmatic use
- **Interactive canvas** in Cursor with tabbed sections (CVEs, bugs, upgrade hops, cross-version, KCS)
- Every bug shows its **exact fix z-stream** (not just "fixed in 4.16.51-4.16.68 somewhere")

## What it doesn't cover

- Red Hat internal JIRA queries (Affects Version cross-referencing)
- KCS article discovery (no search API — bring your own case knowledge)
- Operator compatibility matrices (ODF, ACM, CNV version requirements)
- TAM-level proactive bug notifications

## Works with

- **Cursor** — full support with skill auto-discovery + canvas rendering
- **Any AI coding agent** — the SKILL.md workflow is plain markdown, scripts are standalone Python
- **CLI only** — `scripts/ocp_zstream_audit.py` works without any AI agent

## License

MIT
