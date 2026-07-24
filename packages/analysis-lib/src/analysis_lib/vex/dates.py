"""RFC 3339 date-time handling for CSAF.

CSAF §2.3 / §6.1.37 require every ``date-time`` field to be a valid RFC 3339
timestamp *with* a timezone designator (``Z`` or an explicit offset). A naive
``2026-07-24T03:45:16`` is rejected by conformant validators.

This module is the single authority for producing CSAF timestamps: both the
document tracking dates and the per-vulnerability disclosure/discovery dates go
through :func:`to_csaf_datetime` so the output is always timezone-aware and
normalized to UTC ``Z``.
"""

import re
from datetime import datetime, timezone
from typing import Optional

from vdb.lib import convert_time

# RFC 3339 §5.6 date-time with a mandatory timezone. CSAF §2.3 further requires
# the ``T`` separator and the ``Z`` UTC designator to be *upper case*, so the
# pattern deliberately does not accept lowercase ``t``/``z``.
RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


def is_rfc3339(value: str) -> bool:
    """True when ``value`` is a CSAF-acceptable RFC 3339 date-time."""
    return bool(isinstance(value, str) and RFC3339_RE.match(value))


def now_csaf() -> str:
    """Current time as a CSAF-valid UTC timestamp (``...Z``)."""
    return _to_z(datetime.now(timezone.utc))


def to_csaf_datetime(value: Optional[str], fallback: Optional[str] = None) -> Optional[str]:
    """Normalize an ISO-ish timestamp to CSAF RFC 3339 (UTC ``Z``).

    Naive timestamps are assumed to be UTC. Returns ``fallback`` when ``value``
    is empty or unparseable; ``fallback`` itself is normalized so a caller can
    safely pass another raw timestamp as the default.
    """
    normalized = _normalize(value)
    if normalized is not None:
        return normalized
    if fallback is None:
        return None
    return _normalize(fallback) or fallback


def _normalize(value: Optional[str]) -> Optional[str]:
    if not value or not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    # Already conformant -> normalize casing/offset to UTC Z for consistency.
    dt = _parse(value)
    if dt is None:
        return None
    return _to_z(dt)


def _parse(value: str) -> Optional[datetime]:
    # Try Python's ISO parser first (handles offsets and 'Z' on 3.11+),
    # then fall back to vdb's tolerant converter for odd VDR formats.
    candidate = value.replace("Z", "+00:00").replace("z", "+00:00")
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        pass
    try:
        converted = convert_time(value)
        if isinstance(converted, datetime):
            return converted
    except Exception:
        pass
    return None


def _to_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    # Preserve sub-second precision when present rather than truncating it.
    if dt.microsecond:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f").rstrip("0") + "Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
