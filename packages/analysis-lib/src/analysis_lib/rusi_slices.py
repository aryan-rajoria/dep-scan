"""Rusi (Rust Source Inspector) report -> atom reachables-slice converter.

dep-scan's reachability engine is **purl-keyed and file-format-driven, not
slicer-aware** (see ``reachability.py``). Dropping a correctly-shaped
``*reachables.slices*.json`` whose ``purls`` carry the SAME versioned purls as
the Cargo BOM lights up ``FrameworkReachability`` / ``SemanticReachability``
with zero analyzer changes. This module produces that file from a rusi report.

The single most important correctness detail is the **purl reconciler** (see
:func:`reconcile_purl`). rusi emits versioned purls only for workspace
packages; external crates get unversioned ``pkg:cargo/sqlx`` (and pseudo
``pkg:cargo/fs``), while the Cargo BOM carries versioned
``pkg:cargo/sqlx@0.6.2``. Exact-purl matching silently misses every
dependency-level finding, so we reconcile by crate NAME (mirroring rusi's own
``-``/``_`` normalization and percent-encoding) onto the BOM's versioned purls.

Public surface:
    - :func:`build_bom_purl_index` -- name -> versioned-purl from BOM components
    - :func:`reconcile_purl` -- rusi purl -> BOM versioned purl (or ``None``)
    - :func:`convert_rusi_report` -- rusi.json + BOM -> atom-shaped slice list
    - :func:`write_slices_file` -- convenience writer
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote

# rusi reports are detected by SHAPE, not the opaque ``schema_version`` URL
# prefix. A rusi report is a JSON object carrying its producer identity
# (``tool``/``runtime``) alongside at least one analysis section the converter
# consumes (``call_graph``/``data_flow``). Detection by shape means a forward
# schema bump -- or a report with a missing ``schema_version`` field -- cannot
# break recognition, and it cleanly separates a genuine rusi report from an
# atom-produced ``*-semantics.slices.json`` that reuses the same path cdxgen
# writes the rusi report to under --profile research (atom slices never carry
# these keys as objects).
RUSI_PRODUCER_KEYS = ("tool", "runtime")
RUSI_SECTION_KEYS = ("call_graph", "data_flow")

# Rust stdlib + rustc-internal pseudo-crates that rusi emits as unversioned
# ``pkg:cargo/<name>`` (e.g. ``pkg:cargo/fs`` for ``fs::read_to_string``).
# These never correspond to real Cargo dependencies, so they are dropped
# unconditionally to avoid noise and accidental matches. Kept conservative:
# only names that are DEFINITELY stdlib/rustc-internal, never a real crate a
# security analyst would care about. ``libc``/``hashbrown``/``cfg_if`` are
# deliberately excluded -- they are real crates people depend on.
RUST_STDLIB_PSEUDO_CRATES = frozenset(
    {
        "std",
        "core",
        "alloc",
        "fs",
        "proc_macro",
        "test",
        "panic_unwind",
        "panic_abort",
        "unwind",
        "profiler_builtins",
        "rustc_std_workspace_core",
        "rustc_std_workspace_alloc",
        "rustc_std_workspace_std",
        "rustc_demangle",
        "addr2line",
        "gimli",
        "object",
        "miniz_oxide",
    }
)

# rusi dataflow source/sink categories -> dep-scan SERVICE_TAGS vocabulary
# (config.py). Mapping is conservative: only categories whose intent clearly
# maps to an existing service tag. Sinks describe where tainted data lands
# (``sql-query``, ``network-request`` ...); sources describe where it enters
# (``http-request`` = an HTTP request was observed, i.e. the app serves/exposes
# a web endpoint). Both are legitimate ``reached_services`` signals. This lets
# SemanticReachability populate ``reached_services`` when the user selects it;
# FrameworkReachability ignores tags entirely so this is harmless for the
# default analyzer.
RUSI_CATEGORY_TO_SERVICE_TAG = {
    # sinks
    "sql-query": "sql",
    "network-request": "http",
    "network-connect": "http",
    "html-response": "web",
    # sources
    "http-request": "http",
}

# SERVICE_TAG used for HTTP api_endpoint handler flows. ``api`` is a SERVICE_TAG
# (config.py) so SemanticReachability attributes the framework crate on the
# endpoint path to ``reached_services``. Combined with a BOM that types the
# framework crate as ``framework``, the same flow also lights up
# ``endpoint_reached_purls`` -> ``Endpoint-Reachable`` insight.
RUSI_ENDPOINT_SERVICE_TAG = "api"


# ---------------------------------------------------------------------------
# Purl parsing + reconciliation
# ---------------------------------------------------------------------------


def _parse_purl(purl: Optional[str]) -> Tuple[str, str]:
    """Split ``pkg:<type>/<name>[@<version>][?qualifiers]`` into (name, type).

    Returns ("", "") for non-purl / malformed input. ``name`` is URL-decoded
    and version/qualifiers stripped. Namespace is not currently used by cargo
    purls so we keep just the final path segment; the parsed name mirrors the
    BOM component name for type=cargo.
    """
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return "", ""
    body = purl[len("pkg:") :]
    ptype, _, rest = body.partition("/")
    if not rest:
        return "", ptype
    # strip qualifiers
    rest = rest.split("?", 1)[0]
    # strip version (first @ at the path level; purl version lives after the
    # last @ in the final path segment)
    name_segment = rest.rsplit("/", 1)[-1]
    name = name_segment.split("@", 1)[0]
    return unquote(name), ptype


def _normalize_crate_name(name: str) -> str:
    """Normalize a cargo crate name for matching.

    Cargo manifest names use ``-`` but Rust code / module paths use ``_``
    (``vulnerable-web-app`` vs ``vulnerable_web_app``); rusi's own
    ``package_purl_index`` indexes both forms. We canonicalize to lowercase
    with ``_`` -> ``-``.
    """
    return (name or "").replace("_", "-").lower()


def build_bom_purl_index(
    bom_components: Optional[Iterable[dict]],
    extra_components: Optional[Iterable[dict]] = None,
) -> Dict[str, str]:
    """Build a ``normalized-crate-name -> versioned purl`` index from a BOM.

    Indexes every component whose purl parses as type ``cargo`` (regardless of
    CycloneDX ``type`` -- ``application`` for the workspace root, ``library``
    for deps). Also accepts an ``extra_components`` iterable (e.g. the
    metadata.component root) for BOMs that put the workspace app there only.

    If two components share a normalized name, the FIRST seen wins (stable).
    """
    index: Dict[str, str] = {}
    for c in list(bom_components or []) + list(extra_components or []):
        if not isinstance(c, dict):
            continue
        purl = c.get("purl", "")
        name, ptype = _parse_purl(purl)
        if ptype != "cargo" or not name:
            # Fall back to the component's declared name (some BOMs omit purl
            # on the root metadata component but keep ``name``).
            cname = c.get("name", "")
            if cname and _looks_like_cargo_component(c):
                index.setdefault(_normalize_crate_name(cname), purl)
            continue
        index.setdefault(_normalize_crate_name(name), purl)
    return index


def _looks_like_cargo_component(c: dict) -> bool:
    """Heuristic: is this a cargo component when the purl is missing/odd?"""
    purl = c.get("purl", "")
    if purl.startswith("pkg:cargo/"):
        return True
    # ``bom-ref`` often echoes the purl scheme for cargo components
    bom_ref = c.get("bom-ref", "") or ""
    return "pkg:cargo/" in str(bom_ref)


def reconcile_purl(rusi_purl: Optional[str], bom_index: Dict[str, str]) -> Optional[str]:
    """Map a rusi purl onto a BOM versioned purl by crate NAME.

    Rules (in order):
      1. Non-cargo / malformed -> ``None``.
      2. Stdlib/pseudo crate (see :data:`RUST_STDLIB_PSEUDO_CRATES`) ->
         ``None`` -- always dropped.
      3. Normalized name found in the BOM index -> the BOM's versioned purl.
      4. Not in the BOM -> ``None``. An unmatched rusi purl cannot correspond
         to a BOM component, so emitting it would only add noise (it would
         never increment ``reached_purls``).

    This mirrors rusi's own ``-``/``_`` normalization and percent-encoding so
    an unversioned ``pkg:cargo/sqlx`` from rusi matches a BOM
    ``pkg:cargo/sqlx@0.6.2``.
    """
    name, ptype = _parse_purl(rusi_purl)
    if ptype != "cargo" or not name:
        return None
    nkey = _normalize_crate_name(name)
    if nkey in RUST_STDLIB_PSEUDO_CRATES:
        return None
    return bom_index.get(nkey)


def reconcile_purls(rusi_purls: Iterable[str], bom_index: Dict[str, str]) -> List[str]:
    """Reconcile + de-duplicate a collection of rusi purls to BOM purls.

    Returns a sorted list (deterministic) of non-None reconciled purls.
    """
    seen = set()
    out = []
    for rp in rusi_purls or []:
        vp = reconcile_purl(rp, bom_index)
        if vp and vp not in seen:
            seen.add(vp)
            out.append(vp)
    return sorted(out)


# ---------------------------------------------------------------------------
# Atom-shaped slice emission
# ---------------------------------------------------------------------------


def _pos_line(pos: Optional[dict]) -> int:
    try:
        return int((pos or {}).get("line") or 0)
    except (TypeError, ValueError):
        return 0


def _pos_col(pos: Optional[dict]) -> int:
    try:
        return int((pos or {}).get("column") or 0)
    except (TypeError, ValueError):
        return 0


def _flow_identity(flow: dict) -> bytes:
    """Stable identity hash for dedup (mirrors reachability._flow_identity)."""
    return hashlib.md5(
        json.dumps(flow, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).digest()


def _build_node_tags(
    purl: Optional[str],
    category: str,
    rule_name: str,
    service_tag: Optional[str] = None,
) -> str:
    """Compose the per-node ``tags`` comma-string.

    Format (per plan §4.2): ``"<versioned-purl>, <service-tag>, rust,
    <rule_name>"``. The token IMMEDIATELY after the purl is always the service
    tag when one applies, so ``SemanticReachability._flow_service_purls``
    positional association attributes the service to THIS purl (and not to a
    different purl that happens to share the flow).

    ``service_tag`` overrides the category-derived tag (used for endpoint
    flows whose "category" is synthetic). When unset, the tag is derived from
    ``category`` via :data:`RUSI_CATEGORY_TO_SERVICE_TAG`.
    """
    parts: List[str] = []
    if purl:
        parts.append(purl)
    if service_tag is None:
        service_tag = RUSI_CATEGORY_TO_SERVICE_TAG.get(category or "")
    # The token right after the purl MUST be the service tag when one exists,
    # otherwise a plain category/rust token so no false service attribution
    # occurs.
    parts.append(service_tag or category or "rust")
    if service_tag:
        # keep the raw category too for debuggability when it mapped to a tag
        if category and category != service_tag:
            parts.append(category)
    if "rust" not in parts[-2:] and parts[-1] != "rust":
        parts.append("rust")
    if rule_name:
        parts.append(rule_name)
    return ", ".join(parts)


def convert_rusi_report(
    report: dict,
    bom_index: Dict[str, str],
) -> List[dict]:
    """Convert a parsed rusi report into an atom-shaped reachables slice list.

    Emits three kinds of flows (all atom-shaped ``{"flows": [...], "purls": [...]}``):

      1. **Dataflow flows** -- one per rusi ``data_flow.slices[]`` entry. These
         carry the richest taint evidence. Purls = reconciled versioned purls
         of every crate the slice touches (slice purls + sourcePurl/targetPurl
         + node purls + external symbols matched by qualified name from the
         call graph). External-crate call nodes are tagged with the dependency
         purl + the slice's sink-category service tag so the service is
         positionally attributed to the dependency crate.
      2. **Call-graph flows** -- one per call-graph edge targeting an EXTERNAL
         crate. This registers pure-call reachability (a crate is used but no
         taint slice runs through it), which is essential for dependency-CVE
         reachability where the vulnerable code lives inside the dependency.
         Each flow carries an honest 2-node path: the enclosing caller function
         (source) -> the external symbol call (sink), enriched with the atom
         fields the explainer reads (``parentFileName``, ``label``, ``name``,
         ``parentMethodName``, ``isExternal``).
      3. **Endpoint flows** -- one per rusi ``api_endpoints[]`` entry. The
         framework crate (axum/actix-web/rocket) is tagged with the endpoint
         service tag so SemanticReachability attributes it to
         ``reached_services``; with a BOM that types the framework crate as
         ``framework``, this also lights up ``endpoint_reached_purls``
         (-> ``Endpoint-Reachable`` insight).

    Deterministic: purls sorted, flows deduped by identity, final flow list
    sorted by (purls, first-node id).
    """
    if not isinstance(report, dict):
        return []

    cg = report.get("call_graph") or {}
    cg_nodes = {n.get("id"): n for n in cg.get("nodes", []) if isinstance(n, dict)}
    df = report.get("data_flow") or {}
    df_nodes = {n.get("id"): n for n in df.get("nodes", []) if isinstance(n, dict)}

    # Build a symbol -> reconciled purl map from call-graph edges to external
    # crates. Lets us attribute external crates to dataflow slice nodes that
    # name the callee (e.g. slice node ``sqlx::query`` -> ``pkg:cargo/sqlx@...``)
    # even when the slice's own purls only carry the workspace purl.
    #
    # Matching is by QUALIFIED NAME only (``sqlx::query``), never the bare
    # short name (``query``). Two crates can expose a same-named fn, so a
    # short-name key would mis-attribute one crate's call to the other. The
    # qualified name carries the crate path and is unique per external symbol.
    external_call_records: List[dict] = []
    symbol_to_purl: Dict[str, str] = {}
    for e in cg.get("edges", []) or []:
        if not isinstance(e, dict):
            continue
        tgt = cg_nodes.get(e.get("target_id")) or {}
        if not (tgt.get("external") or tgt.get("purl")):
            continue
        rpurl = tgt.get("purl") or ""
        if not rpurl:
            continue
        vpurl = reconcile_purl(rpurl, bom_index)
        if not vpurl:
            continue
        qualified = tgt.get("qualified_name") or ""
        rec = {
            "callee": qualified or tgt.get("name") or "",
            "qualified": qualified,
            "purl": vpurl,
            "position": tgt.get("position") or e.get("position") or {},
            "source": e.get("source_name") or "",
            "rule_name": "call-graph",
        }
        external_call_records.append(rec)
        # index by qualified name ONLY (see note above).
        if qualified:
            symbol_to_purl.setdefault(qualified, vpurl)

    flows: List[dict] = []

    # --- 1. dataflow slice flows -----------------------------------------
    for sl in df.get("slices", []) or []:
        if not isinstance(sl, dict):
            continue
        flow_purls: set = set()
        flow_nodes: List[dict] = []

        # slice-level purls + source/target purls
        for rp in sl.get("purls", []) or []:
            vp = reconcile_purl(rp, bom_index)
            if vp:
                flow_purls.add(vp)
        for key in ("sourcePurl", "targetPurl"):
            vp = reconcile_purl(sl.get(key, ""), bom_index)
            if vp:
                flow_purls.add(vp)

        # source_name / sink_name may name an external crate directly
        for key in ("source_name", "sink_name"):
            nm = sl.get(key, "")
            if nm in symbol_to_purl:
                flow_purls.add(symbol_to_purl[nm])

        rule_name = sl.get("rule_name") or ""
        sink_category = sl.get("sink_category") or ""
        node_ids_list = sl.get("node_ids", []) or []
        last_idx = len(node_ids_list) - 1

        # traverse witness nodes
        for idx, nid in enumerate(node_ids_list):
            n = df_nodes.get(nid) or {}
            npurl = reconcile_purl(n.get("purl", ""), bom_index)
            nm = n.get("name") or ""
            sym_purl = symbol_to_purl.get(nm)
            if sym_purl:
                flow_purls.add(sym_purl)
            if npurl:
                flow_purls.add(npurl)
            pos = n.get("position") or {}
            # When this node names a known EXTERNAL symbol, the node represents
            # the call INTO the dependency crate. Tag it with the DEPENDENCY
            # purl (not the workspace purl rusi attaches to the call site) and
            # propagate the slice's sink category so the service tag lands on
            # the dependency -- where the vulnerable code actually lives. This
            # is what makes ``reached_services`` attribute the service to
            # ``pkg:cargo/sqlx@<v>`` instead of the workspace app.
            tag_purl = sym_purl or npurl
            node_category = n.get("category") or (sink_category if sym_purl else "")
            is_external = sym_purl is not None
            # Map the analyzer node role to an atom label so the explainer
            # (flow_to_str / flow_to_source_sink) picks a good description.
            if is_external:
                node_label = "CALL"
            elif idx == 0:
                node_label = "METHOD_PARAMETER_IN"
            elif idx == last_idx:
                node_label = "RETURN"
            else:
                node_label = "IDENTIFIER"
            enclosing = n.get("function") or sl.get("sink_function") or ""
            flow_nodes.append(
                {
                    "id": nid,
                    "tags": _build_node_tags(tag_purl, node_category, rule_name),
                    "code": nm,
                    "fullName": enclosing,
                    "lineNumber": _pos_line(pos),
                    "columnNumber": _pos_col(pos),
                    "parentFileName": (pos or {}).get("filename", ""),
                    "label": node_label,
                    "name": nm,
                    "parentMethodName": enclosing,
                    "isExternal": is_external,
                }
            )

        if not flow_purls:
            continue

        # ensure every node carries a reconciled purl in its tags so
        # SemanticReachability's positional association can fire for the
        # slice purls too (at least one node must name each reached purl)
        represented = set()
        for fn in flow_nodes:
            t = fn.get("tags", "")
            for piece in t.split(","):
                piece = piece.strip()
                if piece.startswith("pkg:"):
                    represented.add(piece)
        missing = flow_purls - represented
        if missing:
            # attach the first missing purl to the sink-side node (last node);
            # atom shape only requires the purl to appear in some node's tags
            if flow_nodes:
                sink_node = flow_nodes[-1]
                for m in sorted(missing):
                    extra_tag = _build_node_tags(m, sink_category, rule_name)
                    sink_node["tags"] = sink_node["tags"] + ", " + extra_tag

        flows.append({"flows": flow_nodes, "purls": sorted(flow_purls)})

    # --- 2. call-graph external-crate flows ------------------------------
    # Each external-crate call becomes an honest 2-node flow: the enclosing
    # caller function (source) -> the external symbol call (sink). This lets
    # the flow pass the explainer's >= 2-node gate and renders a readable
    # source -> sink path. The source node intentionally carries lineNumber 0
    # so the explainer's consecutive same-loc dedup does not eat the sink node
    # (both nodes share the same call-site file).
    for rec in external_call_records:
        callee = rec.get("callee") or ""
        source = rec.get("source") or ""
        pos = rec.get("position") or {}
        parent_file = (pos or {}).get("filename", "")
        flow_hash = hashlib.md5((callee + "|" + source).encode("utf-8")).hexdigest()[:16]
        caller_short = source.rsplit("::", 1)[-1] if source else callee
        callee_short = callee.rsplit("::", 1)[-1] if callee else ""
        source_node = {
            "id": "rusi-cg-src-" + flow_hash,
            "tags": _build_node_tags(None, "call-graph", "call-graph"),
            "code": source or callee,
            "fullName": source,
            "lineNumber": 0,
            "columnNumber": 0,
            "parentFileName": parent_file,
            "label": "IDENTIFIER",
            "name": caller_short,
            "parentMethodName": source,
            "isExternal": False,
        }
        sink_node = {
            "id": "rusi-cg-" + flow_hash,
            "tags": _build_node_tags(rec["purl"], "call-graph", "call-graph"),
            "code": callee,
            "fullName": callee,
            "lineNumber": _pos_line(pos),
            "columnNumber": _pos_col(pos),
            "parentFileName": parent_file,
            "label": "CALL",
            "name": callee_short,
            "parentMethodName": source,
            "isExternal": True,
        }
        flows.append({"flows": [source_node, sink_node], "purls": [rec["purl"]]})

    # --- 3. api_endpoint handler flows ----------------------------------
    # Each HTTP endpoint rusi discovered becomes a flow whose purls carry the
    # framework crate (axum/actix-web/rocket, reconciled) and the handler's
    # home crate. The framework-crate node is tagged with the endpoint service
    # tag so SemanticReachability attributes it to ``reached_services``; when
    # the BOM types that framework crate as ``framework`` the same flow also
    # lights up ``endpoint_reached_purls`` -> ``Endpoint-Reachable`` insight.
    for ep in report.get("api_endpoints", []) or []:
        if not isinstance(ep, dict):
            continue
        fw_vpurl = reconcile_purl(ep.get("purl", ""), bom_index)
        pkg_path = ep.get("package_path") or ""
        handler_vpurl = bom_index.get(_normalize_crate_name(pkg_path))
        ep_purls = {p for p in (fw_vpurl, handler_vpurl) if p}
        if not ep_purls:
            continue
        method = ep.get("method") or ""
        path = ep.get("path") or ""
        framework = ep.get("framework") or ""
        handler = ep.get("handler") or ""
        pos = ep.get("position") or {}
        rule = "endpoint" + (f"-{framework}" if framework else "")
        # Node carries the framework purl + endpoint service tag so the
        # framework crate is positionally associated with the endpoint
        # service (api). A handler-crate node carries the workspace purl
        # without a service tag so it is reached but not mis-attributed.
        ep_nodes: List[dict] = []
        if fw_vpurl:
            ep_nodes.append(
                {
                    "id": "rusi-ep-"
                    + hashlib.md5(
                        (method + "|" + path + "|" + handler).encode("utf-8")
                    ).hexdigest()[:16],
                    "tags": _build_node_tags(
                        fw_vpurl,
                        "endpoint",
                        rule,
                        service_tag=RUSI_ENDPOINT_SERVICE_TAG,
                    ),
                    "code": f"{method} {path}".strip(),
                    "fullName": handler,
                    "lineNumber": _pos_line(pos),
                    "columnNumber": _pos_col(pos),
                    "parentFileName": (pos or {}).get("filename", ""),
                    "label": "CALL",
                    "name": path or handler,
                    "parentMethodName": handler,
                    "isExternal": True,
                }
            )
        if handler_vpurl and handler_vpurl != fw_vpurl:
            ep_nodes.append(
                {
                    "id": "rusi-ep-h-" + hashlib.md5(handler.encode("utf-8")).hexdigest()[:16],
                    "tags": _build_node_tags(handler_vpurl, "endpoint", rule),
                    "code": handler,
                    "fullName": handler,
                    "lineNumber": _pos_line(pos),
                    "columnNumber": _pos_col(pos),
                    "parentFileName": (pos or {}).get("filename", ""),
                    "label": "IDENTIFIER",
                    "name": handler.rsplit("::", 1)[-1] if handler else "",
                    "parentMethodName": handler,
                    "isExternal": False,
                }
            )
        flows.append({"flows": ep_nodes, "purls": sorted(ep_purls)})

    # dedup identical flows by identity, then sort for determinism
    seen: set = set()
    unique: List[dict] = []
    for f in flows:
        ident = _flow_identity(f)
        if ident in seen:
            continue
        seen.add(ident)
        unique.append(f)
    unique.sort(key=lambda f: (tuple(f.get("purls", [])), _sort_key_flows(f.get("flows", []))))
    return unique


def _sort_key_flows(flows: List[dict]) -> str:
    if not flows:
        return ""
    return str(flows[0].get("id", ""))


def write_slices_file(slice_path: str, flows: List[dict]) -> None:
    """Write the atom-shaped slice list atomically and deterministically."""
    os.makedirs(os.path.dirname(os.path.abspath(slice_path)) or ".", exist_ok=True)
    payload = json.dumps(flows, sort_keys=True, separators=(",", ":"))
    tmp = slice_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fp:
        fp.write(payload)
    os.replace(tmp, slice_path)


def is_rusi_report(report) -> bool:
    """Return True if ``report`` has the structural shape of a rusi report.

    Detection is by shape: a dict carrying a rusi producer identity
    (``tool`` or ``runtime``) AND at least one analysis section we consume
    (``call_graph`` or ``data_flow``). This avoids coupling dep-scan to the
    opaque ``schema_version`` URL prefix (which can bump) and reliably
    distinguishes a genuine rusi report from an atom semantics slice that
    happens to share the ``<type>-semantics.slices.json`` path.
    """
    if not isinstance(report, dict):
        return False
    has_producer = any(isinstance(report.get(k), dict) for k in RUSI_PRODUCER_KEYS)
    has_section = any(isinstance(report.get(k), dict) for k in RUSI_SECTION_KEYS)
    return has_producer and has_section
