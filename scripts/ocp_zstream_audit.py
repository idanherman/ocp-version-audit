#!/usr/bin/env python3
"""
OCP Z-Stream Upgrade Risk Audit — Unified CLI

Subcommands:
  cincinnati   Query Cincinnati graph for conditional upgrade edges
  changelog    Fetch release controller changelogs with per-z-stream bug mapping
  summary      Combine all audit_data/*.json into a single summary for canvas

Prerequisites:
  pip install requests

Red Hat Errata queries are done via the MCP server in Cursor, not this script.
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import requests

CINCINNATI_API = "https://api.openshift.com/api/upgrades_info/v1/graph"
RELEASE_CONTROLLER = "https://openshift-release.apps.ci.l2s4.p1.openshiftapps.com"


# ── Utilities ────────────────────────────────────────────────────────────────

def parse_version(v: str) -> tuple[int, int, int]:
    parts = v.split(".")
    return int(parts[0]), int(parts[1]), int(parts[2])


def minor_str(v: str) -> str:
    """'4.16.50' → '4.16'"""
    return ".".join(v.split(".")[:2])


def z_patch(v: str) -> int:
    """'4.16.50' → 50"""
    return int(v.split(".")[2])


# ── Cincinnati subcommand ────────────────────────────────────────────────────

def query_graph(channel: str, arch: str = "amd64") -> dict:
    try:
        resp = requests.get(
            CINCINNATI_API,
            params={"channel": channel, "arch": arch},
            headers={"Accept": "application/json"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"  [WARN] Failed to query {channel}: {e}", file=sys.stderr)
        return {"nodes": [], "edges": [], "conditionalEdges": []}


def versions_in_graph(graph: dict, minor: str) -> list[str]:
    return sorted(
        [n["version"] for n in graph.get("nodes", []) if n["version"].startswith(minor + ".")],
        key=lambda v: [int(x) for x in v.split(".")],
    )


def find_conditional_risks(graph: dict, from_v: str, to_v: str) -> list[dict]:
    """Find unique risks for a specific hop or involving either version."""
    seen = set()
    results = []
    for ce in graph.get("conditionalEdges", []):
        edges = ce.get("edges", [])
        involves = any(
            e.get("from") == from_v or e.get("to") == to_v
            for e in edges
        )
        if not involves:
            continue
        for risk in ce.get("risks", []):
            name = risk.get("name", "")
            if name in seen:
                continue
            seen.add(name)
            rules = risk.get("matchingRules", [])
            applies_when = "Always" if any(r.get("type") == "Always" for r in rules) else "Conditional"
            results.append({
                "name": name,
                "message": risk.get("message", ""),
                "url": risk.get("url", ""),
                "applies_when": applies_when,
            })
    return results


def cmd_cincinnati(args):
    """Cincinnati subcommand: check conditional edges for the upgrade path."""
    versions = args.masters or args.path
    if not versions:
        print("Error: provide --masters or --path", file=sys.stderr)
        sys.exit(1)

    arch = args.arch
    results = {"hops": [], "version_availability": {}}

    # Determine which channels to check (prefer eus for even minors)
    channels_needed = {}
    for v in versions:
        m = minor_str(v)
        _, mn, _ = parse_version(v)
        # EUS = even minors; also check eus-{next even} for odd minors
        if mn % 2 == 0:
            channels_needed[m] = [f"eus-{m}", f"stable-{m}", f"fast-{m}"]
        else:
            next_even = f"4.{mn + 1}"
            channels_needed[m] = [f"eus-{next_even}", f"stable-{m}", f"fast-{m}"]

    graphs = {}
    print("[Cincinnati] Querying graphs...")
    for m, ch_list in channels_needed.items():
        for ch in ch_list:
            if ch not in graphs:
                print(f"  {ch}...", end=" ", flush=True)
                graphs[ch] = query_graph(ch, arch)
                n = len(graphs[ch].get("nodes", []))
                c = len(graphs[ch].get("conditionalEdges", []))
                print(f"{n} versions, {c} conditional groups")

    # Check version availability
    for v in versions:
        m = minor_str(v)
        found_in = []
        for ch in channels_needed.get(m, []):
            if v in [n["version"] for n in graphs.get(ch, {}).get("nodes", [])]:
                found_in.append(ch)
        results["version_availability"][v] = {
            "found_in": found_in,
            "available": len(found_in) > 0,
        }
        status = ", ".join(found_in) if found_in else "NOT FOUND"
        print(f"  {v}: {status}")

    # Check each hop
    print("\n[Cincinnati] Checking hops...")
    for i in range(len(versions) - 1):
        fv, tv = versions[i], versions[i + 1]
        _, fm, _ = parse_version(fv)
        _, tm, _ = parse_version(tv)
        hop_type = "z-stream" if fm == tm else "y-stream"

        # Pick best graph for this hop
        best_graph = {}
        for ch in channels_needed.get(minor_str(tv), []):
            g = graphs.get(ch, {})
            if any(n["version"] == tv for n in g.get("nodes", [])):
                best_graph = g
                break

        risks = find_conditional_risks(best_graph, fv, tv)
        hop = {"from": fv, "to": tv, "type": hop_type, "risks": risks}
        results["hops"].append(hop)
        print(f"  {fv} → {tv} ({hop_type}): {len(risks)} risks")
        for r in risks:
            print(f"    {r['name']}: {r['message'][:80]}...")

    # Workers path if provided
    if args.workers:
        print("\n[Cincinnati] Workers path...")
        for i in range(len(args.workers) - 1):
            fv, tv = args.workers[i], args.workers[i + 1]
            _, fm, _ = parse_version(fv)
            _, tm, _ = parse_version(tv)
            best_graph = {}
            for ch in channels_needed.get(minor_str(tv), []):
                g = graphs.get(ch, {})
                if any(n["version"] == tv for n in g.get("nodes", [])):
                    best_graph = g
                    break
            risks = find_conditional_risks(best_graph, fv, tv)
            hop = {"from": fv, "to": tv, "type": "y-stream" if fm != tm else "z-stream", "risks": risks, "path": "workers"}
            results["hops"].append(hop)
            print(f"  {fv} → {tv}: {len(risks)} risks")

    _write_output(results, args.output, "cincinnati")


# ── Changelog subcommand ─────────────────────────────────────────────────────

def fetch_changelog_html(from_v: str, to_v: str) -> str:
    for stream in ["4-stable", "4-fast"]:
        url = f"{RELEASE_CONTROLLER}/releasestream/{stream}/release/{to_v}?from={from_v}"
        try:
            resp = requests.get(url, timeout=60)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            continue
    return ""


def get_latest_in_channel(minor: str, arch: str = "amd64") -> str:
    """Find the latest version across eus/stable/fast channels."""
    _, mn, _ = parse_version(minor + ".0")
    if mn % 2 == 0:
        channels = [f"eus-{minor}", f"stable-{minor}", f"fast-{minor}"]
    else:
        next_even = f"4.{mn + 1}"
        channels = [f"eus-{next_even}", f"stable-{minor}", f"fast-{minor}"]

    best = ""
    for ch in channels:
        g = query_graph(ch, arch)
        vs = versions_in_graph(g, minor)
        if vs:
            candidate = vs[-1]
            if not best or z_patch(candidate) > z_patch(best):
                best = candidate
    return best


def get_all_zstreams_in_range(minor: str, from_z: int, to_z: int, arch: str = "amd64") -> list[str]:
    """Get all available z-stream versions between from_z and to_z (exclusive/inclusive)."""
    for ch_type in ["eus", "stable", "fast"]:
        _, mn, _ = parse_version(minor + ".0")
        if ch_type == "eus" and mn % 2 == 0:
            ch = f"eus-{minor}"
        elif ch_type == "eus":
            ch = f"eus-4.{mn + 1}"
        else:
            ch = f"{ch_type}-{minor}"
        g = query_graph(ch, arch)
        vs = versions_in_graph(g, minor)
        filtered = [v for v in vs if from_z < z_patch(v) <= to_z]
        if filtered:
            return filtered
    return []


def parse_bugs_from_html(html: str) -> list[dict]:
    """Parse OCPBUGS and component from release controller HTML/markdown."""
    current_component = ""
    bugs = []
    seen = set()

    for line in html.split("\n"):
        # Component headers: ### component-name or <h3>component</h3>
        comp_match = re.match(r'^###\s+(.+)', line)
        if not comp_match:
            comp_match = re.search(r'<h[23][^>]*>([^<]+)</h[23]>', line)
        if comp_match:
            current_component = comp_match.group(1).strip()
            continue

        bug_ids = re.findall(r'(OCPBUGS-\d+)', line)
        if not bug_ids:
            continue

        # Accept lines starting with - (markdown) or <li> (HTML) or containing OCPBUGS
        is_list_item = line.strip().startswith("-") or "<li>" in line

        if not is_list_item:
            continue

        desc = line.strip().lstrip("- ")
        desc = re.sub(r'#\d+$', '', desc).strip()
        desc = re.sub(r'^(OCPBUGS-\d+[,:]\s*)+', '', desc)
        # Clean HTML tags
        desc = re.sub(r'<[^>]+>', '', desc).strip()
        # Remove trailing PR/commit refs
        desc = re.sub(r'\s*#\d+\s*$', '', desc).strip()
        cve_ids = re.findall(r'(CVE-\d{4}-\d+)', desc)

        for bid in bug_ids:
            if bid in seen:
                continue
            seen.add(bid)
            bugs.append({
                "id": bid,
                "component": current_component,
                "description": desc[:250],
                "is_cve": bool(cve_ids),
                "cve_ids": cve_ids,
            })
    return bugs


def cmd_changelog(args):
    """Changelog subcommand: fetch per-z-stream changelogs and map bugs to fix versions."""
    versions = args.version
    arch = args.arch
    results = {}

    for version in versions:
        m = minor_str(version)
        from_z = z_patch(version)

        # Find the latest version to compare against
        latest = get_latest_in_channel(m, arch)
        if not latest or latest == version:
            print(f"[Changelog] {version}: already latest or not found")
            results[version] = {"version": version, "latest": latest, "bugs": [], "per_zstream": {}}
            continue

        to_z = z_patch(latest)
        print(f"[Changelog] {version} → {latest} ({to_z - from_z} z-streams)")

        # Get all intermediate z-streams
        zstreams = get_all_zstreams_in_range(m, from_z, to_z, arch)
        if not zstreams:
            # Fallback: just do from→latest
            zstreams = [latest]
        print(f"  Available z-streams: {len(zstreams)}")

        # Fetch per-z-stream changelogs in parallel
        per_zstream = {}
        all_bugs = {}

        def fetch_one(prev_v: str, next_v: str) -> tuple[str, list[dict]]:
            html = fetch_changelog_html(prev_v, next_v)
            return next_v, parse_bugs_from_html(html) if html else []

        pairs = []
        prev = version
        for zs in zstreams:
            pairs.append((prev, zs))
            prev = zs

        print(f"  Fetching {len(pairs)} changelogs...", end=" ", flush=True)
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(fetch_one, p, n): (p, n) for p, n in pairs}
            for fut in as_completed(futures):
                zs_version, bugs = fut.result()
                z = z_patch(zs_version)
                per_zstream[z] = bugs
                for b in bugs:
                    if b["id"] not in all_bugs:
                        b["fixed_in_z"] = z
                        b["fixed_in_version"] = zs_version
                        all_bugs[b["id"]] = b
        print(f"done ({len(all_bugs)} unique bugs)")

        # Also fetch the full from→latest changelog for any bugs we might have missed
        print(f"  Cross-checking full {version}→{latest} changelog...", end=" ", flush=True)
        full_html = fetch_changelog_html(version, latest)
        full_bugs = parse_bugs_from_html(full_html) if full_html else []
        missed = 0
        for b in full_bugs:
            if b["id"] not in all_bugs:
                b["fixed_in_z"] = to_z
                b["fixed_in_version"] = latest
                b["note"] = "exact z-stream unknown (found in full diff only)"
                all_bugs[b["id"]] = b
                missed += 1
        print(f"{missed} additional bugs from full diff")

        results[version] = {
            "version": version,
            "latest": latest,
            "zstream_range": f"{from_z}→{to_z}",
            "zstreams_checked": len(zstreams),
            "total_bugs": len(all_bugs),
            "bugs": list(all_bugs.values()),
            "per_zstream_counts": {str(z): len(bugs) for z, bugs in sorted(per_zstream.items())},
            "changelog_urls": {
                "full": f"{RELEASE_CONTROLLER}/releasestream/4-stable/release/{latest}?from={version}",
            },
        }

        # Print per-z-stream summary
        for z in sorted(per_zstream.keys()):
            print(f"    4.{m.split('.')[1]}.{z}: {len(per_zstream[z])} bugs")

    _write_output(results, args.output, "changelog")


# ── Summary subcommand ───────────────────────────────────────────────────────

def cmd_summary(args):
    """Combine all audit_data files into a single summary."""
    audit_dir = Path(args.audit_dir)
    summary = {"sources": {}}

    for json_file in sorted(audit_dir.glob("*.json")):
        if json_file.name == "summary.json":
            continue
        try:
            data = json.load(open(json_file))
            summary["sources"][json_file.stem] = {
                "file": str(json_file),
                "keys": list(data.keys()) if isinstance(data, dict) else f"list[{len(data)}]",
            }
        except Exception as e:
            summary["sources"][json_file.stem] = {"error": str(e)}

    _write_output(summary, args.output, "summary")


# ── Common ───────────────────────────────────────────────────────────────────

def _write_output(data: dict, output: Optional[str], label: str):
    if output:
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"\n[{label}] Saved to {out}")
    else:
        print(json.dumps(data, indent=2, default=str))


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="OCP Z-Stream Upgrade Risk Audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s cincinnati --masters 4.12.40 4.13.59 4.14.56 4.15.58 4.16.50
  %(prog)s changelog --version 4.16.50 --output audit_data/changelog_4.16.json
  %(prog)s summary --audit-dir audit_data/
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # Cincinnati
    p_cin = sub.add_parser("cincinnati", help="Check Cincinnati graph for conditional upgrade edges")
    p_cin.add_argument("--masters", nargs="+", help="Master upgrade path")
    p_cin.add_argument("--workers", nargs="+", help="Worker upgrade path")
    p_cin.add_argument("--path", nargs="+", help="Single upgrade path (alias for --masters)")
    p_cin.add_argument("--arch", default="amd64")
    p_cin.add_argument("--output", type=str)
    p_cin.set_defaults(func=cmd_cincinnati)

    # Changelog
    p_cl = sub.add_parser("changelog", help="Fetch release controller changelogs with per-z-stream bug mapping")
    p_cl.add_argument("--version", nargs="+", required=True, help="Version(s) to audit")
    p_cl.add_argument("--arch", default="amd64")
    p_cl.add_argument("--output", type=str)
    p_cl.set_defaults(func=cmd_changelog)

    # Summary
    p_sum = sub.add_parser("summary", help="Combine audit_data files into summary")
    p_sum.add_argument("--audit-dir", default="audit_data", help="Directory with audit JSON files")
    p_sum.add_argument("--output", type=str)
    p_sum.set_defaults(func=cmd_summary)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
