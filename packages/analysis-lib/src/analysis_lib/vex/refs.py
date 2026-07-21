"""Reference and id building for CSAF vulnerabilities.

Reuses :func:`analysis_lib.utils.get_ref_summary_helper` so reference
classification lives in a single place in the codebase.

Schema rules enforced here:

* Every reference has a non-empty ``summary`` and a ``url`` that is a valid
  http(s) IRI.
* Every id has non-empty ``system_name`` and ``text``.
"""

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from analysis_lib.config import REF_MAP
from analysis_lib.utils import get_ref_summary_helper

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# Advisory tokens worth surfacing as CSAF ids (GHSA, RHSA, CVE, etc.). The
# character class is case-insensitive; the matched token is uppercased.
_ADVISORY_TOKEN_RE = re.compile(
    r"\b((?:GHSA|RHSA|RHBA|DSA|USN|NTAP|ZDI|CVE|ALBA|ALS2|ASFA)-[0-9A-Za-z:\-]{4,})\b"
)
_VALID_SCHEMES = {"http", "https"}


def _is_real_url(url: str) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return parsed.scheme in _VALID_SCHEMES and bool(parsed.netloc)


def _extract_advisory_token(url: str, title: str) -> str:
    """Pull a recognizable advisory/CVE id out of a url or title."""
    for source in (url, title or ""):
        m = _ADVISORY_TOKEN_RE.search(source)
        if m:
            return m.group(1).upper()
        m = _CVE_RE.search(source)
        if m:
            return m.group(0).upper()
    return ""


def _summarize(url: str, fallback_name: str) -> str:
    """Return a non-empty CSAF summary for a url."""
    _, _, summary = get_ref_summary_helper(url, REF_MAP)
    if summary and summary != "Other":
        return summary
    if fallback_name:
        return fallback_name
    return summary or "External"


def build_references_and_ids(
    references: List[Dict[str, Any]],
    advisories: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Build CSAF ``references`` and ``ids`` lists from VDR inputs.

    :return: ``(references, ids)`` each de-duplicated and schema-clean.
    """
    refs_out: List[Dict[str, str]] = []
    ids_out: List[Dict[str, str]] = []
    seen_refs = set()
    seen_ids = set()

    # VDR references carry id/source; advisories carry title/url.
    combined = []
    for r in references or []:
        url = (r.get("source") or {}).get("url") or r.get("url") or ""
        combined.append(
            {
                "url": url,
                "id": r.get("id") or "",
                "name": (r.get("source") or {}).get("name") or "",
                "title": r.get("title") or "",
            }
        )
    for a in advisories or []:
        combined.append(
            {
                "url": a.get("url") or "",
                "id": "",
                "name": "",
                "title": a.get("title") or "",
            }
        )

    for entry in combined:
        url = entry["url"].strip()
        if not _is_real_url(url):
            continue
        summary = _summarize(url, entry["name"])
        if not summary:
            continue
        ref_key = (summary, url)
        if ref_key not in seen_refs:
            seen_refs.add(ref_key)
            refs_out.append({"summary": summary, "url": url, "category": "external"})

        token = (entry["id"] or _extract_advisory_token(url, entry["title"])).strip()
        if not token:
            continue
        text = token.upper()
        id_key = (summary, text)
        if id_key in seen_ids:
            continue
        seen_ids.add(id_key)
        ids_out.append({"system_name": summary, "text": text})

    ids_out.sort(key=lambda i: (i["system_name"], i["text"]))
    refs_out.sort(key=lambda r: (r["url"], r["summary"]))
    return refs_out, ids_out
