"""Compose a single CSAF vulnerability from a VDR vulnerability record.

Brings together the product-id map (product_tree), reachability
classification, CVSS scoring, references and CWE handling into one
:class:`analysis_lib.vex.models.Vulnerability`.

Notable behaviour:

* CWE ids are emitted as ``CWE-<n>`` with the exact MITRE name; if the name is
  unknown the CWE is omitted rather than emitted as a placeholder.
* CSAF 2.0 allows only one ``cwe`` per vulnerability, so any additional CWEs
  become developer notes; CSAF 2.1 carries them all in ``cwes``.
* Notes without non-empty text are never generated.
* ``product_status`` and ``flags`` come from reachability, not version ranges.
"""

from typing import Any, Dict, List, Optional

from analysis_lib.config import CWE_MAP
from analysis_lib.vex.cvss import parse_ratings
from analysis_lib.vex.models import Flag, Note, Reference, Score, Vulnerability
from analysis_lib.vex.reachability import classify
from analysis_lib.vex.refs import build_references_and_ids

_DESCRIPCTION_CATEGORY = "description"
_DETAILS_CATEGORY = "details"
_OTHER_CATEGORY = "other"


def _resolve_cwes(cwes: List[Any]) -> List[Dict[str, str]]:
    """Resolve raw CWE ids to ``[{"id": "CWE-<n>", "name": <MITRE name>}]``.

    Ids whose MITRE name is unknown are dropped so a placeholder never reaches
    the document. Order is preserved so the first entry is the primary CWE.
    """
    resolved: List[Dict[str, str]] = []
    for cwe_id in cwes:
        try:
            numeric = int(cwe_id)
        except (TypeError, ValueError):
            continue
        name = CWE_MAP.get(numeric)
        if not name:
            continue
        resolved.append({"id": f"CWE-{numeric}", "name": name})
    return resolved


def _extra_cwe_notes(cwes: List[Dict[str, str]]) -> List[Note]:
    """Developer notes for CWEs beyond the first (used only for CSAF 2.0, which
    permits a single ``cwe`` per vulnerability)."""
    notes: List[Note] = []
    for cwe in cwes[1:]:
        notes.append(
            Note(
                category=_OTHER_CATEGORY,
                text=cwe["name"],
                title=f"Additional CWE: {cwe['id']}",
                audience="developers",
            )
        )
    return notes


def _build_notes(vuln: Dict[str, Any], extra_cwe_notes: List[Note]) -> List[Note]:
    """Assemble notes that always carry non-empty text."""
    notes: List[Note] = list(extra_cwe_notes)

    description = (vuln.get("description") or "").replace("\n", " ").strip()
    if description:
        notes.append(Note(category=_DESCRIPCTION_CATEGORY, text=description))
    detail = (vuln.get("detail") or "").replace("\n", " ").strip()
    if detail:
        notes.append(Note(category=_DETAILS_CATEGORY, text=detail))
    recommendation = (vuln.get("recommendation") or "").replace("\n", " ").strip()
    if recommendation:
        notes.append(
            Note(
                category=_OTHER_CATEGORY,
                text=recommendation,
                title="Recommended Action",
            )
        )
    return notes


def _build_acknowledgements(source: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not source or not source.get("name"):
        return []
    org = source["name"].replace(" Advisory", "")
    if source.get("url"):
        return [{"organization": org, "urls": [source["url"]]}]
    return [{"organization": org}]


def build_vulnerability(
    vuln: Dict[str, Any],
    purl_to_id: Dict[str, str],
    reached_purls: Dict[str, int],
    csaf_version: str = "2.1",
) -> Optional[Vulnerability]:
    """Map one VDR vulnerability to a CSAF :class:`Vulnerability`.

    Returns ``None`` when the vulnerability touches no product known to the
    product tree (it would otherwise have an empty product_status, which CSAF
    forbids for a vulnerability that has no other anchors).
    """
    product_status, flags, score_product_ids = classify(vuln, purl_to_id, reached_purls)
    if not product_status and not score_product_ids:
        return None

    cwes = _resolve_cwes(vuln.get("cwes") or [])
    # 2.0 keeps a single cwe and spills the rest into notes; 2.1 keeps them all.
    extra_cwe_notes = _extra_cwe_notes(cwes) if csaf_version == "2.0" else []
    notes = _build_notes(vuln, extra_cwe_notes)
    references, ids = build_references_and_ids(
        vuln.get("references") or [], vuln.get("advisories") or []
    )

    raw_scores = parse_ratings(vuln.get("ratings") or [], csaf_version)
    scores: List[Score] = []
    if score_product_ids and raw_scores:
        for body in raw_scores:
            scores.append(
                Score(
                    products=score_product_ids,
                    cvss_v2=body.get("cvss_v2"),
                    cvss_v3=body.get("cvss_v3"),
                    cvss_v4=body.get("cvss_v4"),
                )
            )

    flag_models = [Flag(label=f["label"], product_ids=f["product_ids"]) for f in flags]
    reference_models = [
        Reference(summary=r["summary"], url=r["url"], category=r.get("category"))
        for r in references
    ]

    cve = vuln.get("id") if str(vuln.get("id", "")).startswith("CVE") else None
    title = vuln.get("bom-ref") or vuln.get("id") or "vulnerability"

    return Vulnerability(
        cve=cve,
        title=title,
        cwes=cwes,
        notes=notes,
        product_status=product_status,
        scores=scores,
        flags=flag_models,
        references=reference_models,
        ids=ids,
        acknowledgments=_build_acknowledgements(vuln.get("source") or {}),
        discovery_date=vuln.get("published") or vuln.get("updated"),
        disclosure_date=vuln.get("published") or vuln.get("updated"),
    )
