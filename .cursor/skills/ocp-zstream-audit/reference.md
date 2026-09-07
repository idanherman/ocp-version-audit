# OCP Z-Stream Audit — Reference

## Script Usage

### Cincinnati Check
```bash
# Full customer path (masters + workers)
python scripts/ocp_zstream_audit.py cincinnati \
  --masters 4.12.40 4.13.59 4.14.56 4.15.58 4.16.50 \
  --workers 4.12.40 4.14.56 4.16.50 \
  --output audit_data/cincinnati.json

# Simple single path
python scripts/ocp_zstream_audit.py cincinnati \
  --path 4.14.20 4.16.50 \
  --output audit_data/cincinnati.json
```

### Changelog Check (Per-Z-Stream Bug Mapping)
```bash
# Target version (where customer stays)
python scripts/ocp_zstream_audit.py changelog \
  --version 4.16.50 \
  --output audit_data/changelog_target.json

# Multiple transient versions
python scripts/ocp_zstream_audit.py changelog \
  --version 4.13.59 --version 4.14.56 --version 4.15.58 \
  --output audit_data/changelog_transient.json
```

### Red Hat Errata (via MCP — agent does this, not the script)

The agent uses the Red Hat Security MCP tools directly:
- `search_advisories` — find all errata for a product/version/date range
- `get_errata_by_id` — full advisory details
- `get_cve_by_id` — full CVE details with CVSS, affected products, mitigation
- `list_cve_affected_products` — check which versions a CVE affects
- `search_cves` — broad CVE discovery by keyword

## EUS Channel Awareness

For EUS-to-EUS upgrades, versions appear in different channels:
- **4.12.x** in `eus-4.12` (also `eus-4.14` as source)
- **4.13.x** in `eus-4.14` (not just `stable-4.13`)
- **4.14.x** in `eus-4.14` and `eus-4.16`
- **4.15.x** in `eus-4.16` (not just `stable-4.15`)
- **4.16.x** in `eus-4.16`

The script checks all relevant channels automatically.

## Output JSON Structure

### cincinnati.json
```json
{
  "hops": [
    {
      "from": "4.12.40",
      "to": "4.13.59",
      "type": "y-stream",
      "risks": [
        {
          "name": "NetPolicyTimeoutsHostNetworkedPodTraffic",
          "message": "Clusters where Ingress Controller uses HostNetwork...",
          "url": "https://issues.redhat.com/browse/SDN-4481",
          "applies_when": "Conditional"
        }
      ]
    }
  ],
  "version_availability": {
    "4.13.59": {"found_in": ["eus-4.14", "fast-4.13"], "available": true}
  }
}
```

### changelog_target.json
```json
{
  "4.16.50": {
    "version": "4.16.50",
    "latest": "4.16.69",
    "total_bugs": 183,
    "bugs": [
      {
        "id": "OCPBUGS-62171",
        "component": "machine-config-operator",
        "description": "Fix - NetworkManager restart or crash renders br-ex unusable",
        "is_cve": false,
        "fixed_in_z": 65,
        "fixed_in_version": "4.16.65"
      }
    ],
    "per_zstream_counts": {"51": 9, "52": 11, ...}
  }
}
```

## Known Bugs Never Backported to 4.16

These are known from manual investigation. The cross-version CVE search may find more.

| Bug | Description | Fixed In | Risk |
|-----|-------------|----------|------|
| OCPBUGS-56594 | kube-apiserver concurrent map crash in audit logging | 4.17+ | API server panic |
| OCPBUGS-84534 | openshift-apiserver RBAC authorization cache race | 4.20+ | API server crash |
| OCPBUGS-60628 | Cert rotation controllers rewrite each other's metadata | 4.19+ | API write storm during upgrade |
| OCPBUGS-62619 | Rendered MachineConfig exceeds etcd 1.5MB limit | 4.17+ | API OOM in disconnected env |

## Customer Configuration Profile

When filtering bugs, categorize by platform relevance:

| Config | Relevant Categories |
|--------|-------------------|
| BareMetal + SDN | networking (SDN-specific), mco, ingress (HostNetwork), baremetal |
| vSphere + OVN | networking (OVN-specific), mco, vsphere, ingress |
| AWS + OVN | networking (OVN-specific), aws, ingress (LB) |
| Disconnected | disconnected, mco (ICSP/IDMS size), registry |
| With Multus | networking (whereabouts, IPAM, secondary networks) |
| With EgressIP | networking (EgressIP-specific) |
| With ODF/Ceph | storage (Ceph-specific) |
