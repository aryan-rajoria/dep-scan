"""Document tracking metadata.

CSAF requires ``tracking.revision_history`` to be a non-empty array regardless
of document status, and the document ``version`` to be consistent with the
latest revision number. This module builds a tracking block that always
contains at least the initial revision entry.
"""

from typing import Any, Dict, Optional

from analysis_lib.vex.dates import now_csaf, to_csaf_datetime
from analysis_lib.vex.models import RevisionEntry, Tracking

INITIAL_SUMMARY = "Initial"


def _now() -> str:
    return now_csaf()


def _fmt_date(value: Optional[str], fallback: str) -> str:
    """Normalize an ISO-ish date to a CSAF RFC 3339 timestamp (UTC ``Z``)."""
    return to_csaf_datetime(value, fallback) or fallback


def build_tracking(raw: Optional[Dict[str, Any]], generated_id: str = "") -> Tracking:
    """Build a schema-valid :class:`Tracking` from raw ``csaf.toml`` data.

    Guarantees:
    * ``revision_history`` has at least one entry.
    * ``version`` is consistent with the latest revision number.
    * ``initial_release_date`` / ``current_release_date`` are non-empty.
    """
    raw = raw or {}
    now = _now()
    status = raw.get("status") or "draft"

    # Seed revision history from raw, then ensure at least one entry exists.
    revisions = []
    for entry in raw.get("revision_history") or []:
        if not entry or not isinstance(entry, dict):
            continue
        number = str(entry.get("number") or "").strip()
        date = _fmt_date(entry.get("date"), now)
        summary = (entry.get("summary") or "").strip()
        if number and date:
            revisions.append(
                RevisionEntry(date=date, number=number, summary=summary or INITIAL_SUMMARY)
            )

    initial_date = _fmt_date(raw.get("initial_release_date"), now)
    current_date = _fmt_date(raw.get("current_release_date"), initial_date)

    if not revisions:
        revisions.append(RevisionEntry(date=initial_date, number="1", summary=INITIAL_SUMMARY))

    # Keep revisions sorted by number; the document version always tracks the
    # latest revision number rather than an arbitrary hand-set value.
    revisions.sort(key=lambda r: int(r.number) if r.number.isdigit() else 0)
    version = revisions[-1].number

    tracking_id = (raw.get("id") or "").strip() or generated_id or f"{now}_v{version}"

    return Tracking(
        status=status,
        version=version,
        id=tracking_id,
        current_release_date=current_date,
        initial_release_date=initial_date,
        revision_history=revisions,
    )
