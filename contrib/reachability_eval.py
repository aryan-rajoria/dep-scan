#!/usr/bin/env python3
"""Reachability analyzer evaluation harness (roadmap R1).

Runs depscan's FrameworkReachability and SemanticReachability against a repo's
already-generated ``reports/`` directory (atom slices + SBOMs) and emits a
deterministic report: reached-set sizes and the sorted sets themselves,
wall-clock, peak RSS, flows read / unique flows, and — when a VDR is present —
a vuln x reachability cross-reference.

This is the acceptance ORACLE for the reachability workstream (R3/R4): snapshot
a baseline, then after any refactor re-run in --check mode. The reached SETS
must not change except where a fix is explicitly correcting a documented bug,
and wall-clock / peak RSS must not regress.

Usage:
    # Evaluate the default repos (cdxgen + juice-shop) and print a report
    python contrib/reachability_eval.py

    # Evaluate specific repos
    python contrib/reachability_eval.py /path/to/repo1 /path/to/repo2

    # Write / update the baseline snapshot next to this script
    python contrib/reachability_eval.py --snapshot

    # Fail (exit 1) if reached sets changed vs the baseline
    python contrib/reachability_eval.py --check

Notes:
  * No network, no atom/slice regeneration. Reads existing reports/ only.
  * Timings and RSS are informational (machine dependent); the reached SETS are
    the correctness contract and are what --check diffs.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import resource
import sys
import time
from typing import Dict, List, Optional

# Allow running from a source checkout without installing the workspace.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ANALYSIS_SRC = os.path.join(_HERE, "..", "packages", "analysis-lib", "src")
if os.path.isdir(_ANALYSIS_SRC):
    sys.path.insert(0, os.path.abspath(_ANALYSIS_SRC))

from analysis_lib import ReachabilityAnalysisKV  # noqa: E402
from analysis_lib.reachability import (  # noqa: E402
    _iter_json_list,
    get_reachability_impl,
)

# Default evaluation repos. cdxgen + juice-shop both ship atom 2.5.x slices in
# their reports/ dir. Rust/tui is excluded (atom has no Rust support).
DEFAULT_REPOS = [
    "/Users/prabhu/work/cdxgen/cdxgen",
    "/Users/prabhu/sandbox/juice-shop",
]

BASELINE_FILE = os.path.join(_HERE, "reachability_eval.baseline.json")

ANALYZERS = ("FrameworkReachability", "SemanticReachability")


def _peak_rss_mb() -> float:
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS reports bytes, Linux reports kilobytes.
    return rss / (1024 * 1024) if sys.platform == "darwin" else rss / 1024


def _slice_stats(reports_dir: str) -> Dict[str, int]:
    """Count reachables flow-objects and unique flow-objects across all files.

    Independent of the analyzer, so a refactor that changes how slices are read
    can be compared against ground truth. Streams each file element-by-element
    (mirrors the R3c analyzer path) so the harness itself does not inflate the
    process peak RSS with a full parsed tree and obscure the analyzer's RSS
    improvement.
    """
    files = sorted(glob.glob(os.path.join(reports_dir, "*reachables.slices*.json")))
    total = 0
    unique = set()
    for f in files:
        for flow in _iter_json_list(f):
            if not isinstance(flow, dict):
                continue
            total += 1
            unique.add(hashlib.md5(json.dumps(flow, sort_keys=True).encode()).hexdigest())
    return {
        "reachables_files": len(files),
        "flows_total": total,
        "flows_unique": len(unique),
    }


def _find_vdr(reports_dir: str) -> Optional[str]:
    for pattern in ("*.vdr.json", "*.vdr", "bom.vdr.json"):
        hits = sorted(glob.glob(os.path.join(reports_dir, pattern)))
        if hits:
            return hits[0]
    return None


def _vuln_purls(vdr_file: str) -> List[str]:
    try:
        with open(vdr_file, encoding="utf-8") as fp:
            vdr = json.load(fp)
    except Exception:
        return []
    purls = set()
    for v in vdr.get("vulnerabilities", []) or []:
        for aff in v.get("affects", []) or []:
            ref = aff.get("ref")
            if ref and ref.startswith("pkg:"):
                purls.add(ref)
    return sorted(purls)


def _sorted_set(d: Optional[Dict]) -> List[str]:
    return sorted(d.keys()) if d else []


def evaluate_repo(repo: str) -> Dict:
    reports_dir = os.path.join(repo, "reports")
    result: Dict = {"repo": repo, "reports_dir": reports_dir}
    if not os.path.isdir(reports_dir):
        result["error"] = "no reports/ dir"
        return result
    result["slices"] = _slice_stats(reports_dir)
    vdr_file = _find_vdr(reports_dir)
    vuln_purls = _vuln_purls(vdr_file) if vdr_file else []
    result["vdr_file"] = os.path.basename(vdr_file) if vdr_file else None

    per_analyzer: Dict = {}
    for analyzer in ANALYZERS:
        options = ReachabilityAnalysisKV(
            project_types=["js"],
            src_dir=repo,
            bom_dir=reports_dir,
        )
        t0 = time.time()
        res = get_reachability_impl(analyzer, options).process()
        elapsed = time.time() - t0
        reached = _sorted_set(res.reached_purls)
        services = _sorted_set(res.reached_services)
        endpoints = _sorted_set(res.endpoint_reached_purls)
        direct = _sorted_set(res.direct_purls)
        entry = {
            "success": bool(res.success),
            "wall_clock_s": round(elapsed, 3),
            "peak_rss_mb_after": round(_peak_rss_mb()),
            "counts": {
                "direct_purls": len(direct),
                "reached_purls": len(reached),
                "reached_services": len(services),
                "endpoint_reached_purls": len(endpoints),
            },
            # The sorted sets are the correctness contract (what --check diffs).
            "sets": {
                "reached_purls": reached,
                "reached_services": services,
                "endpoint_reached_purls": endpoints,
            },
        }
        if vuln_purls:
            # R4.0: snapshot the actual vulnerable-purl SETS in each bucket so
            # --check can detect *which* vulns move between reached /
            # endpoint_reached / not_reached on a refactor, not just the count.
            # Contract: reached/endpoint_reached sets must not shrink (recall),
            # not_reached must not grow unless a fix explicitly corrects a bug.
            reached_set = set(reached)
            endpoint_set = set(endpoints)
            reached_vulns = sorted(p for p in vuln_purls if p in reached_set)
            endpoint_vulns = sorted(p for p in vuln_purls if p in endpoint_set)
            not_reached_vulns = sorted(p for p in vuln_purls if p not in reached_set)
            entry["vuln_cross_ref"] = {
                "vulnerable_purls": len(vuln_purls),
                "reached": len(reached_vulns),
                "endpoint_reached": len(endpoint_vulns),
                "not_reached": len(not_reached_vulns),
                # Sorted purl sets — the R4 accuracy contract.
                "reached_set": reached_vulns,
                "endpoint_reached_set": endpoint_vulns,
                "not_reached_set": not_reached_vulns,
            }
        per_analyzer[analyzer] = entry
    result["analyzers"] = per_analyzer
    return result


def _print_report(report: List[Dict]) -> None:
    for r in report:
        print(f"\n{'=' * 72}\n{r['repo']}")
        if r.get("error"):
            print(f"  ERROR: {r['error']}")
            continue
        s = r["slices"]
        print(
            f"  slices: {s['reachables_files']} files, "
            f"{s['flows_total']} flows ({s['flows_unique']} unique, "
            f"{s['flows_total'] - s['flows_unique']} dup)"
        )
        print(f"  vdr: {r.get('vdr_file')}")
        for analyzer, e in r["analyzers"].items():
            c = e["counts"]
            print(
                f"  {analyzer:22} {e['wall_clock_s']:6.2f}s  RSS~{e['peak_rss_mb_after']:5}MB  "
                f"direct={c['direct_purls']:4} reached={c['reached_purls']:4} "
                f"services={c['reached_services']:4} endpoint={c['endpoint_reached_purls']:4}"
            )
            if "vuln_cross_ref" in e:
                x = e["vuln_cross_ref"]
                # precision = of reached purls, how many are vuln (signal-to-noise);
                # recall = of vuln purls, how many are reached (coverage).
                reached_n = c["reached_purls"]
                precision = (x["reached"] / reached_n) if reached_n else 0.0
                recall = (x["reached"] / x["vulnerable_purls"]) if x["vulnerable_purls"] else 0.0
                print(
                    f"    {'':20}   vulns={x['vulnerable_purls']} reached={x['reached']} "
                    f"endpoint={x['endpoint_reached']} not_reached={x['not_reached']} "
                    f"precision={precision:.2f} recall={recall:.2f}"
                )


def _sets_only(report: List[Dict]) -> Dict:
    """Extract the correctness contract (repo -> analyzer -> sets + cross-ref).

    From R4.0 the contract has two layers: the reached/services/endpoint SETS
    (the hard contract — must not change unless a fix corrects a documented bug)
    and the vuln_cross_ref SETS (reached/endpoint_reached/not_reached vuln purls
    — recall must not drop, precision should hold or improve). Both are
    snapshotted so --check can attribute any delta to the right layer.
    """
    out = {}
    for r in report:
        if r.get("error"):
            continue
        per_analyzer: Dict = {}
        for a, e in r["analyzers"].items():
            per_analyzer[a] = {"sets": e["sets"]}
            xref = e.get("vuln_cross_ref")
            if xref:
                per_analyzer[a]["vuln_cross_ref"] = {
                    "reached_set": xref["reached_set"],
                    "endpoint_reached_set": xref["endpoint_reached_set"],
                    "not_reached_set": xref["not_reached_set"],
                }
        out[r["repo"]] = per_analyzer
    return out


def _diff_set(repo: str, analyzer: str, key: str, baseline_list, current_list) -> None:
    """Print a unified-style diff for one set contract (no-op if equal)."""
    bs, cs = set(baseline_list or []), set(current_list or [])
    if bs == cs:
        return
    added, removed = sorted(cs - bs), sorted(bs - cs)
    print(
        f"  {repo} / {analyzer} / {key}: +{len(added)} -{len(removed)}",
        file=sys.stderr,
    )
    for p in added[:10]:
        print(f"      + {p}", file=sys.stderr)
    for p in removed[:10]:
        print(f"      - {p}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repos", nargs="*", default=None, help="repo paths (default: cdxgen+juice-shop)")
    ap.add_argument("--snapshot", action="store_true", help="write/update the baseline snapshot")
    ap.add_argument("--check", action="store_true", help="diff reached sets vs baseline; exit 1 on change")
    ap.add_argument("--json", action="store_true", help="print full JSON report to stdout")
    args = ap.parse_args()

    repos = args.repos or DEFAULT_REPOS
    report = [evaluate_repo(r) for r in repos]

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_report(report)

    if args.snapshot:
        with open(BASELINE_FILE, "w", encoding="utf-8") as fp:
            json.dump(_sets_only(report), fp, indent=2, sort_keys=True)
        print(f"\nBaseline written to {BASELINE_FILE}")
        return 0

    if args.check:
        if not os.path.exists(BASELINE_FILE):
            print("\nNo baseline; run with --snapshot first.", file=sys.stderr)
            return 2
        with open(BASELINE_FILE, encoding="utf-8") as fp:
            baseline = json.load(fp)
        current = _sets_only(report)
        if current == baseline:
            print("\n[check] reached sets + vuln_cross_ref match baseline. OK")
            return 0
        print("\n[check] sets DIFFER from baseline:", file=sys.stderr)
        for repo in sorted(set(baseline) | set(current)):
            for analyzer in ANALYZERS:
                b = baseline.get(repo, {}).get(analyzer, {})
                c = current.get(repo, {}).get(analyzer, {})
                # Layer 1: the hard reached-set contract.
                b_sets = b.get("sets", {})
                c_sets = c.get("sets", {})
                for key in ("reached_purls", "reached_services", "endpoint_reached_purls"):
                    _diff_set(repo, analyzer, key, b_sets.get(key, []), c_sets.get(key, []))
                # Layer 2 (R4.0): the VDR accuracy cross-ref.
                b_xref = b.get("vuln_cross_ref", {})
                c_xref = c.get("vuln_cross_ref", {})
                for key in ("reached_set", "endpoint_reached_set", "not_reached_set"):
                    _diff_set(
                        f"{repo} [vuln_cross_ref]",
                        analyzer,
                        key,
                        b_xref.get(key, []),
                        c_xref.get(key, []),
                    )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
