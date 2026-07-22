"""Product tree builder.

The product tree is the single authority for product identity in a CSAF VEX
document. Every ``product_id`` referenced from ``product_status``, ``scores``,
``flags`` and ``remediations`` must resolve to an entry here.

The component's purl is used directly as the ``product_id``. Purls are already
unique, stable and human-readable, so using them as the id removes the need for
a separate id-assignment scheme, makes the ``purl -> product_id`` map an
identity map (so a VDR ``affects[].ref`` resolves trivially), and satisfies the
CSAF schema, which imposes no format on ``product_id`` beyond ``minLength: 1``.

The ``product_identification_helper`` shape differs by CSAF version: 2.0 carries
a single ``purl`` string, while 2.1 carries a ``purls`` array.
"""

from typing import Any, Dict, Tuple

from packageurl import PackageURL

DEFAULT_VERSION = "2.1"


def _human_name(component: Dict[str, Any]) -> str:
    """Build a readable product name from a CycloneDX component."""
    group = component.get("group") or ""
    name = component.get("name") or "unknown"
    version = component.get("version") or ""
    parts = [f"{group}/" if group else "", name]
    label = "".join(parts)
    if version:
        label = f"{label} @ {version}"
    return label


def _sorted_components(bom: Dict[str, Any]):
    """Return a deterministically-ordered list of components + metadata root.

    Determinism matters: the product tree feeds golden tests and downstream
    diffing tools, so the same BOM must always produce the same tree.
    """
    components = []
    root = bom.get("metadata", {}).get("component") or {}
    if root:
        components.append(root)
    for c in bom.get("components", []) or []:
        components.append(c)
    # Sort by purl for stable output; components without a purl sort last by name.
    return sorted(components, key=lambda c: c.get("purl") or c.get("name") or "")


def build_product_tree(
    bom: Dict[str, Any],
    version: str = DEFAULT_VERSION,
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """Build the CSAF ``product_tree`` and the ``purl -> product_id`` map.

    :param bom: The CycloneDX BOM (CDX or VDR) as a dict.
    :param version: Target CSAF version (``"2.0"`` or ``"2.1"``); controls the
        ``product_identification_helper`` shape.
    :return: ``(product_tree, purl_to_id)`` where ``product_tree`` is ready for
        serialization and ``purl_to_id`` maps every component purl to its
        product_id (currently the identity map, exposed for clarity).
    """
    full_product_names = []
    purl_to_id: Dict[str, str] = {}
    seen_ids = set()

    for component in _sorted_components(bom):
        purl = component.get("purl")
        if not purl:
            # Without a purl we have no stable identity; skip rather than
            # fabricate an id that product_status could never resolve.
            continue
        canonical = _canonical_purl(purl)
        product_id = canonical
        if product_id in seen_ids:
            continue
        seen_ids.add(product_id)
        purl_to_id[purl] = product_id
        # Also map the canonical form so lookups by either form resolve.
        if canonical != purl:
            purl_to_id[canonical] = product_id

        helper: Dict[str, Any] = (
            {"purls": [canonical]} if version == "2.1" else {"purl": canonical}
        )
        entry = {
            "name": _human_name(component),
            "product_id": product_id,
            "product_identification_helper": helper,
        }
        if component.get("cpe"):
            helper["cpe"] = component["cpe"]
        full_product_names.append(entry)

    product_tree = {"full_product_names": full_product_names}
    return product_tree, purl_to_id


def _canonical_purl(purl: str) -> str:
    """Canonicalize a purl so ``@``-namespace encoding does not split identity."""
    try:
        return str(PackageURL.from_string(purl))
    except ValueError:
        return purl


def resolve_purl(purl_to_id: Dict[str, str], purl: str) -> str:
    """Resolve a possibly-non-canonical purl to its ``product_id``.

    Returns an empty string when the purl is unknown — the caller treats an
    empty product_id as "drop this product reference" rather than emitting an
    id that the product tree does not define.
    """
    if not purl:
        return ""
    if purl in purl_to_id:
        return purl_to_id[purl]
    return purl_to_id.get(_canonical_purl(purl), "")


def referenced_product_ids(doc: Dict[str, Any]) -> set:
    """Collect every product_id referenced anywhere in a CSAF document.

    Used by the post-build integrity check that the JSON Schema cannot express
    (cross-referencing ``product_status``/``scores``/``flags``/``remediations``
    back into ``product_tree``).
    """
    referenced = set()
    for vuln in doc.get("vulnerabilities", []) or []:
        for ids in (vuln.get("product_status") or {}).values():
            referenced.update(ids)
        for score in vuln.get("scores", []) or []:
            referenced.update(score.get("products", []) or [])
        for flag in vuln.get("flags", []) or []:
            referenced.update(flag.get("product_ids", []) or [])
        for rem in vuln.get("remediations", []) or []:
            referenced.update(rem.get("product_ids", []) or [])
    return referenced


def defined_product_ids(doc: Dict[str, Any]) -> set:
    """Collect every product_id defined in the ``product_tree``."""
    defined = set()
    tree = doc.get("product_tree") or {}
    for fpn in tree.get("full_product_names", []) or []:
        if fpn.get("product_id"):
            defined.add(fpn["product_id"])
    return defined
