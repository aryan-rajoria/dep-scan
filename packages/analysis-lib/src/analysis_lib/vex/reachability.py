"""Map reachability results to CSAF VEX status.

dep-scan's reachability analyzer records which purls carry reachable flows
(``vdr_result.reached_purls``). This module turns that into VEX semantics:

* reachable   -> ``known_affected``
* unreachable -> ``known_not_affected`` + flag ``vulnerable_code_not_in_execute_path``
* unknown     -> ``under_investigation`` (no reachability data available)

Only product_ids that resolve in the product tree are emitted, so a status or
flag can never reference an undefined product.
"""

from typing import Dict, List, Tuple

from analysis_lib.vex.product_tree import resolve_purl

# CSAF VEX status buckets.
KNOWN_AFFECTED = "known_affected"
KNOWN_NOT_AFFECTED = "known_not_affected"
UNDER_INVESTIGATION = "under_investigation"

# CSAF flag label for code that is present but never executed. In CSAF the flag
# label is itself the VEX justification value (there is no separate field).
NOT_IN_PATH_LABEL = "vulnerable_code_not_in_execute_path"


def _affected_purls(vuln: Dict) -> List[str]:
    """Return the purls of the products this vulnerability attaches to.

    ``affects[].versions[].status`` is intentionally ignored: it describes which
    version fixes the CVE, not whether the installed product is affected at
    runtime. The ``ref`` is the installed product's purl.
    """
    purls = []
    for a in vuln.get("affects", []) or []:
        ref = a.get("ref")
        if ref:
            purls.append(ref)
    return purls


def classify(
    vuln: Dict,
    purl_to_id: Dict[str, str],
    reached_purls: Dict[str, int],
) -> Tuple[Dict[str, List[str]], List[Dict], List[str]]:
    """Classify a vulnerability's affected products into VEX status buckets.

    :return: ``(product_status, flags, score_product_ids)`` where every id is
        guaranteed to resolve in the product tree.
    """
    has_reachability = bool(reached_purls)

    status_buckets: Dict[str, List[str]] = {
        KNOWN_AFFECTED: [],
        KNOWN_NOT_AFFECTED: [],
        UNDER_INVESTIGATION: [],
    }
    not_affected_ids: List[str] = []
    score_product_ids: List[str] = []

    for purl in _affected_purls(vuln):
        product_id = resolve_purl(purl_to_id, purl)
        if not product_id:
            # Unknown to the product tree -> skip so no status/flag references
            # an undefined product.
            continue
        score_product_ids.append(product_id)
        if not has_reachability:
            status_buckets[UNDER_INVESTIGATION].append(product_id)
            continue
        if reached_purls.get(purl) or reached_purls.get(product_id):
            status_buckets[KNOWN_AFFECTED].append(product_id)
        else:
            status_buckets[KNOWN_NOT_AFFECTED].append(product_id)
            not_affected_ids.append(product_id)

    flags: List[Dict] = []
    if not_affected_ids:
        flags.append(
            {
                "label": NOT_IN_PATH_LABEL,
                "product_ids": sorted(set(not_affected_ids)),
            }
        )

    # Drop empty buckets; callers serialize what remains.
    product_status = {k: sorted(set(v)) for k, v in status_buckets.items() if v}
    return product_status, flags, sorted(set(score_product_ids))
