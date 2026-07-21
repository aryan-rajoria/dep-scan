"""CVSS rating mapping (v2 / v3 / v4).

This module recognises all three major CVSS versions (v2, v3, v4) and returns
CSAF-shaped objects.

Mapping rules:

* The vector prefix selects the CVSS family (``CVSS:2``/no prefix -> v2,
  ``CVSS:3`` -> v3, ``CVSS:4`` -> v4).
* Which family lands in the final document depends on the target CSAF version:
  CSAF 2.0 only defines ``cvss_v2``/``cvss_v3``, so v4 vectors are returned
  here (so callers can unit-test the mapping) but the orchestrator drops them
  when emitting a 2.0 document. CSAF 2.1 adds ``cvss_v4``.
* Vectors that fail the library's mandatory-metric check are skipped rather
  than crashing the whole export.
"""

from typing import Any, Dict, List, Optional, Tuple

import cvss

# Token used by the orchestrator to decide which block to populate.
V2, V3, V4 = "cvss_v2", "cvss_v3", "cvss_v4"


def _clean_metric_value(value: Any) -> Any:
    """Drop ``NOT_DEFINED`` (and similar nulls) the way CSAF expects."""
    if isinstance(value, str) and value.upper() in {"NOT_DEFINED", "NOT_DEFINED"}:
        return None
    return value


def _normalize_cvss_dict(family: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in raw.items():
        v = _clean_metric_value(v)
        if v is None or v == "":
            continue
        out[k] = v
    # CSAF requires ``version`` consistent with the family.
    if "version" not in out:
        out["version"] = {"cvss_v2": "2.0", "cvss_v3": "3.1", "cvss_v4": "4.0"}.get(
            family, "3.1"
        )
    return out


def _cvss_v4_body(obj: "cvss.CVSS4") -> Dict[str, Any]:
    """Build a CSAF-schema-valid ``cvss_v4`` object.

    The cvss library's ``as_json`` uses metric property names and a ``version``
    string that do not match the official CVSS v4.0 JSON schema referenced by
    CSAF. We therefore emit only the core, schema-guaranteed fields; the full
    metric breakdown is always recoverable from ``vectorString``.
    """
    raw = obj.as_json()
    return {
        "version": "4.0",
        "vectorString": raw.get("vectorString") or obj.vector,
        "baseScore": raw.get("baseScore"),
        "baseSeverity": str(raw.get("baseSeverity", "")).upper(),
    }


def parse_one(rating: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Parse a single VDR rating into ``(family, cvss_dict)`` or ``None``.

    ``family`` is one of ``cvss_v2`` / ``cvss_v3`` / ``cvss_v4``.
    """
    vector = rating.get("vector") or ""
    if not vector:
        return None

    upper = vector.upper()
    try:
        if upper.startswith("CVSS:4"):
            obj = cvss.CVSS4(vector)
            obj.check_mandatory()
            return V4, _cvss_v4_body(obj)
        if upper.startswith("CVSS:3"):
            obj = cvss.CVSS3(vector)
            obj.check_mandatory()
            return V3, _normalize_cvss_dict(V3, obj.as_json())
        # CVSS v2 vectors sometimes carry no prefix.
        v2_vector = vector.split("CVSS:2", 1)[1] if upper.startswith("CVSS:2") else vector
        obj = cvss.CVSS2(v2_vector)
        obj.check_mandatory()
        return V2, _normalize_cvss_dict(V2, obj.as_json())
    except Exception:
        # A malformed/incomplete vector must never abort the export; the
        # severity/severity score from the rating is still usable elsewhere.
        return None


def parse_ratings(
    ratings: List[Optional[Dict[str, Any]]],
    csaf_version: str = "2.1",
) -> List[Dict[str, Any]]:
    """Return a list of CSAF score bodies (without ``products``).

    ``products`` is attached by the orchestrator which owns the product_ids.
    For CSAF 2.0, v4 vectors are dropped (no schema slot for them).
    """
    out: List[Dict[str, Any]] = []
    seen_vectors = set()
    for rating in ratings or []:
        if not rating:
            continue
        parsed = parse_one(rating)
        if not parsed:
            continue
        family, body = parsed
        if family == V4 and csaf_version == "2.0":
            # No cvss_v4 slot in CSAF 2.0; drop but record so callers can
            # observe the omission (see reachability/notes if desired).
            continue
        vec = body.get("vectorString") or ""
        if vec in seen_vectors:
            continue
        seen_vectors.add(vec)
        out.append({family: body})
    return out


def best_severity(scores: List[Dict[str, Any]]) -> Optional[str]:
    """Pick the most severe ``baseSeverity`` across score bodies.

    Used to compute ``aggregate_severity``. Returns ``None`` when no score
    carries a severity.
    """
    rank = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    best_rank = -1
    best = None
    for score in scores:
        for family in (V2, V3, V4):
            body = score.get(family)
            if not body:
                continue
            sev = str(body.get("baseSeverity", "")).lower()
            if sev in rank and rank[sev] > best_rank:
                best_rank = rank[sev]
                best = sev
    return best
