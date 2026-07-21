"""Unit tests for the analysis_lib.vex package.

These tests assert real behavior -- schema validity against the bundled CSAF
2.0 and 2.1 schemas, reference resolution, reachability semantics and
serialization invariants -- rather than dict-equality against hand-authored
fixtures.
"""

import json
import os
from pathlib import Path

import pytest

from analysis_lib.vex import models
from analysis_lib.vex.cvss import best_severity, parse_one, parse_ratings
from analysis_lib.vex.csaf import build_csaf
from analysis_lib.vex.emit import export_csaf, output_path, validate
from analysis_lib.vex.product_tree import (
    build_product_tree,
    defined_product_ids,
    referenced_product_ids,
    resolve_purl,
)
from analysis_lib.vex.reachability import classify, KNOWN_AFFECTED, KNOWN_NOT_AFFECTED
from analysis_lib.vex.refs import build_references_and_ids
from analysis_lib.vex.tracking import build_tracking

DATA_DIR = Path(__file__).resolve().parent / "data"

VERSIONS = ["2.0", "2.1"]


# ---------------------------------------------------------------------------
# models
# ---------------------------------------------------------------------------


def test_models_clean_drops_empty_containers():
    assert models._clean({"a": None, "b": "", "c": [], "d": {}, "e": "x"}) == {"e": "x"}
    assert models._clean([None, "", [], {}, "keep"]) == ["keep"]


def test_full_product_name_helper_2_0_uses_purl():
    fpn = models.FullProductName(name="x", product_id="pkg:x@1", purl="pkg:x@1", cpe="cpe:2.3")
    out = fpn.to_dict("2.0")
    assert out["product_identification_helper"]["purl"] == "pkg:x@1"
    assert out["product_identification_helper"]["cpe"] == "cpe:2.3"


def test_full_product_name_helper_2_1_uses_purls_list():
    fpn = models.FullProductName(name="x", product_id="pkg:x@1", purl="pkg:x@1")
    out = fpn.to_dict("2.1")
    assert out["product_identification_helper"]["purls"] == ["pkg:x@1"]


def test_vulnerability_omits_note_without_text():
    # A note with empty text must never reach the serialized vulnerability.
    vuln = models.Vulnerability(
        cve="CVE-2024-1",
        title="t",
        cwes=[],
        notes=[
            models.Note(category="description", text=""),
            models.Note(category="description", text="real"),
        ],
        product_status={"known_affected": ["pkg:x@1"]},
        scores=[],
        flags=[],
        references=[],
        ids=[],
    )
    out = vuln.to_dict()
    assert [n["text"] for n in out["notes"]] == ["real"]


def test_vulnerability_cwe_2_0_single_object():
    vuln = models.Vulnerability(
        cve="CVE-2024-1",
        title="t",
        cwes=[
            {"id": "CWE-787", "name": "Out-of-bounds Write"},
            {"id": "CWE-125", "name": "Out-of-bounds Read"},
        ],
        notes=[],
        product_status={},
        scores=[],
        flags=[],
        references=[],
        ids=[],
    )
    out = vuln.to_dict("2.0")
    # 2.0 permits a single cwe object.
    assert out["cwe"] == {"id": "CWE-787", "name": "Out-of-bounds Write"}
    assert "cwes" not in out


def test_vulnerability_cwe_2_1_array_with_version():
    vuln = models.Vulnerability(
        cve="CVE-2024-1",
        title="t",
        cwes=[
            {"id": "CWE-787", "name": "Out-of-bounds Write"},
            {"id": "CWE-125", "name": "Out-of-bounds Read"},
        ],
        notes=[],
        product_status={},
        scores=[],
        flags=[],
        references=[],
        ids=[],
    )
    out = vuln.to_dict("2.1")
    assert "cwe" not in out
    assert [c["id"] for c in out["cwes"]] == ["CWE-787", "CWE-125"]
    assert all(c["version"] == models.CWE_CATALOG_VERSION for c in out["cwes"])


def test_score_2_0_flat_and_2_1_content_wrapped():
    s = models.Score(products=["pkg:b@1"], cvss_v3={"baseScore": 9.8})
    flat = s.to_dict("2.0")
    assert "cvss_v3" in flat and "content" not in flat
    wrapped = s.to_dict("2.1")
    assert wrapped["content"]["cvss_v3"] == {"baseScore": 9.8}
    assert wrapped["products"] == ["pkg:b@1"]


def test_flag_has_no_justification_field():
    f = models.Flag(label="vulnerable_code_not_in_execute_path", product_ids=["pkg:b@1"])
    out = f.to_dict()
    assert out == {
        "label": "vulnerable_code_not_in_execute_path",
        "product_ids": ["pkg:b@1"],
    }
    assert "justification" not in out


def test_disclosure_vs_release_date_by_version():
    common = dict(
        cve="CVE-2024-1",
        title="t",
        cwes=[],
        notes=[],
        product_status={"known_affected": ["pkg:x@1"]},
        scores=[],
        flags=[],
        references=[],
        ids=[],
        disclosure_date="2024-01-01T00:00:00",
    )
    v20 = models.Vulnerability(**common).to_dict("2.0")
    v21 = models.Vulnerability(**common).to_dict("2.1")
    assert v20["release_date"] == "2024-01-01T00:00:00" and "disclosure_date" not in v20
    assert v21["disclosure_date"] == "2024-01-01T00:00:00" and "release_date" not in v21


# ---------------------------------------------------------------------------
# product_tree
# ---------------------------------------------------------------------------


def _sample_bom():
    return {
        "metadata": {
            "component": {
                "name": "juice-shop",
                "version": "20.1.1",
                "purl": "pkg:npm/juice-shop@20.1.1",
            }
        },
        "components": [
            {
                "name": "express",
                "version": "4.22.2",
                "purl": "pkg:npm/express@4.22.2",
            },
            {
                "group": "@codemirror",
                "name": "lang-json",
                "version": "6.0.2",
                "purl": "pkg:npm/@codemirror/lang-json@6.0.2",
            },
        ],
    }


def test_product_tree_purl_is_product_id():
    tree, pmap = build_product_tree(_sample_bom())
    ids = {p["product_id"] for p in tree["full_product_names"]}
    assert "pkg:npm/juice-shop@20.1.1" in ids
    assert "pkg:npm/express@4.22.2" in ids
    # The product_id IS the purl (single source of truth).
    assert resolve_purl(pmap, "pkg:npm/express@4.22.2") == "pkg:npm/express@4.22.2"


def test_product_tree_helper_shape_by_version():
    tree20, _ = build_product_tree(_sample_bom(), "2.0")
    tree21, _ = build_product_tree(_sample_bom(), "2.1")
    assert all("purl" in p["product_identification_helper"] for p in tree20["full_product_names"])
    assert all("purls" in p["product_identification_helper"] for p in tree21["full_product_names"])


def test_product_tree_resolves_at_namespace_encoding():
    # affects[].ref may use the raw '@' form while the canonical purl uses '%40'.
    _, pmap = build_product_tree(_sample_bom())
    assert resolve_purl(pmap, "pkg:npm/@codemirror/lang-json@6.0.2") == resolve_purl(
        pmap, "pkg:npm/%40codemirror/lang-json@6.0.2"
    )


def test_product_tree_unknown_purl_resolves_empty():
    _, pmap = build_product_tree(_sample_bom())
    # Unknown purls resolve to "" so callers never reference an undefined product.
    assert resolve_purl(pmap, "pkg:npm/does-not-exist@1.0.0") == ""


def test_product_tree_is_deterministic():
    bom = _sample_bom()
    t1, _ = build_product_tree(bom)
    t2, _ = build_product_tree(bom)
    assert t1 == t2


def test_referenced_and_defined_collectors():
    doc = {
        "product_tree": {
            "full_product_names": [
                {"product_id": "A"},
                {"product_id": "B"},
            ]
        },
        "vulnerabilities": [
            {
                "product_status": {"known_affected": ["A"], "known_not_affected": ["B"]},
                "scores": [{"products": ["A"]}],
                "flags": [{"product_ids": ["B"]}],
                "remediations": [{"product_ids": ["A"]}],
            }
        ],
    }
    assert referenced_product_ids(doc) == {"A", "B"}
    assert defined_product_ids(doc) == {"A", "B"}


# ---------------------------------------------------------------------------
# cvss
# ---------------------------------------------------------------------------


_V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
_V2 = "AV:N/AC:L/Au:N/C:P/I:P/A:P"


def test_parse_one_v3():
    family, body = parse_one({"vector": _V3})
    assert family == "cvss_v3"
    assert body["baseScore"] == 9.8
    assert body["baseSeverity"] == "CRITICAL"


def test_parse_one_v2():
    family, body = parse_one({"vector": _V2})
    assert family == "cvss_v2"
    assert body["baseScore"] == 7.5


def test_parse_one_v4_minimal_valid_body():
    family, body = parse_one({"vector": _V4})
    assert family == "cvss_v4"
    # Only the core, schema-guaranteed fields are emitted; version is "4.0".
    assert set(body) == {"version", "vectorString", "baseScore", "baseSeverity"}
    assert body["version"] == "4.0"
    assert body["baseSeverity"] == body["baseSeverity"].upper()


def test_parse_ratings_drops_v4_for_csaf_2():
    assert parse_ratings([{"vector": _V4}], "2.0") == []
    kept = parse_ratings([{"vector": _V4}], "2.1")
    assert kept and "cvss_v4" in kept[0]


def test_parse_ratings_malformed_vector_skipped():
    # Missing mandatory metrics must not crash the export.
    assert parse_ratings([{"vector": "CVSS:4.0/AV:N"}], "2.1") == []
    assert parse_ratings([{"vector": "nonsense"}], "2.0") == []


def test_parse_ratings_dedupes_identical_vectors():
    out = parse_ratings([{"vector": _V3}, {"vector": _V3}], "2.0")
    assert len(out) == 1


def test_best_severity_picks_highest():
    scores = parse_ratings([{"vector": _V3}], "2.0") + parse_ratings([{"vector": _V2}], "2.0")
    assert best_severity(scores) == "critical"


# ---------------------------------------------------------------------------
# refs
# ---------------------------------------------------------------------------


def test_refs_skips_non_url():
    references = [{"id": "x", "source": {"name": "N", "url": "not-a-url"}}]
    refs, ids = build_references_and_ids(references, [])
    assert refs == []
    assert ids == []


def test_refs_emits_summary_and_url():
    references = [
        {
            "id": "CVE-2021-1234",
            "source": {
                "name": "NVD",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234",
            },
        }
    ]
    refs, ids = build_references_and_ids(references, [])
    assert refs == [
        {
            "summary": "CVE Record",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234",
            "category": "external",
        }
    ]
    assert {"system_name": "CVE Record", "text": "CVE-2021-1234"} in ids


def test_refs_advisory_token_extracted_from_title():
    advisories = [
        {
            "title": "GitHub Advisory GHSA-w5hq-g745-h8pq",
            "url": "https://github.com/uuidjs/uuid/security/advisories/GHSA-w5hq-g745-h8pq",
        }
    ]
    _, ids = build_references_and_ids([], advisories)
    texts = [i["text"] for i in ids]
    assert "GHSA-W5HQ-G745-H8PQ" in texts


def test_refs_dedup():
    references = [
        {"id": "CVE-2021-1234", "source": {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234"}},
        {"id": "CVE-2021-1234", "source": {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234"}},
    ]
    refs, ids = build_references_and_ids(references, [])
    assert len(refs) == 1
    assert len(ids) == 1


# ---------------------------------------------------------------------------
# reachability
# ---------------------------------------------------------------------------


def _purl_map():
    bom = {
        "components": [
            {"name": "express", "version": "4.22.2", "purl": "pkg:npm/express@4.22.2"},
            {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
            {"name": "ghost", "version": "1.0.0", "purl": "pkg:npm/ghost@1.0.0"},
        ]
    }
    _, pmap = build_product_tree(bom)
    return pmap


def test_reachability_reachable_is_known_affected():
    pmap = _purl_map()
    vuln = {"affects": [{"ref": "pkg:npm/express@4.22.2"}]}
    status, flags, scores = classify(vuln, pmap, {"pkg:npm/express@4.22.2": 240})
    assert status == {KNOWN_AFFECTED: ["pkg:npm/express@4.22.2"]}
    assert flags == []
    assert scores == ["pkg:npm/express@4.22.2"]


def test_reachability_unreachable_gets_flag_with_justification_label():
    pmap = _purl_map()
    vuln = {"affects": [{"ref": "pkg:npm/left-pad@1.3.0"}]}
    status, flags, scores = classify(vuln, pmap, {"pkg:npm/express@4.22.2": 1})
    assert status == {KNOWN_NOT_AFFECTED: ["pkg:npm/left-pad@1.3.0"]}
    assert len(flags) == 1
    # In CSAF the flag label is itself the justification value.
    assert flags[0]["label"] == "vulnerable_code_not_in_execute_path"
    assert "justification" not in flags[0]
    assert flags[0]["product_ids"] == ["pkg:npm/left-pad@1.3.0"]
    assert scores == ["pkg:npm/left-pad@1.3.0"]


def test_reachability_unknown_when_no_reachability_data():
    pmap = _purl_map()
    vuln = {"affects": [{"ref": "pkg:npm/ghost@1.0.0"}]}
    status, flags, scores = classify(vuln, pmap, {})
    assert status == {"under_investigation": ["pkg:npm/ghost@1.0.0"]}
    assert flags == []


def test_reachability_drops_unknown_purl():
    pmap = _purl_map()
    vuln = {"affects": [{"ref": "pkg:npm/does-not-exist@9.9.9"}]}
    status, flags, scores = classify(vuln, pmap, {"pkg:npm/express@4.22.2": 1})
    assert status == {}
    assert flags == []
    assert scores == []


# ---------------------------------------------------------------------------
# tracking
# ---------------------------------------------------------------------------


def test_tracking_always_has_revision_entry():
    t = build_tracking({})
    out = t.to_dict()
    assert len(out["revision_history"]) >= 1
    assert out["version"] == out["revision_history"][-1]["number"]


def test_tracking_preserves_existing_revisions():
    raw = {
        "status": "final",
        "version": "1",
        "initial_release_date": "2024-01-01T00:00:00",
        "current_release_date": "2024-02-01T00:00:00",
        "revision_history": [
            {"date": "2024-01-01T00:00:00", "number": "1", "summary": "Initial"}
        ],
    }
    out = build_tracking(raw).to_dict()
    assert len(out["revision_history"]) == 1
    assert out["status"] == "final"
    assert out["version"] == "1"


def test_tracking_bumps_version_to_match_revisions():
    raw = {
        "status": "final",
        "version": "5",
        "revision_history": [{"date": "2024-01-01T00:00:00", "number": "1", "summary": "Initial"}],
    }
    out = build_tracking(raw).to_dict()
    assert out["version"] == "1"


# ---------------------------------------------------------------------------
# orchestrator (build_csaf) + emit (path safety, schema validation)
# ---------------------------------------------------------------------------

DEMO_BOM_PATH = DATA_DIR / "vex" / "demo_bom.json"


def _load_demo():
    with open(DEMO_BOM_PATH) as fh:
        return json.load(fh)


@pytest.mark.parametrize("version", VERSIONS)
def test_build_csaf_schema_valid_and_semantically_correct(version):
    bom = _load_demo()
    # express is reachable, everything else is not.
    reached = {"pkg:npm/express@4.22.2": 10}
    doc = build_csaf(bom, bom["vulnerabilities"], reached_purls=reached, csaf_version=version)

    errors = validate(doc, version)
    assert errors == [], f"Expected 0 schema errors for {version}, got:\n" + "\n".join(errors[:10])
    # No product reference is left undefined in the product tree.
    assert referenced_product_ids(doc) <= defined_product_ids(doc)

    by_cve = {v.get("cve"): v for v in doc["vulnerabilities"]}
    metric_key = "metrics" if version == "2.1" else "scores"

    def _cvss(vuln, family):
        for m in vuln.get(metric_key, []):
            body = m.get("content", m)
            if family in body:
                return True
        return False

    # Reachable -> known_affected, no flag.
    express = by_cve["CVE-2024-10001"]
    assert express["product_status"]["known_affected"] == ["pkg:npm/express@4.22.2"]
    assert express.get("flags", []) == []
    assert _cvss(express, "cvss_v3")
    # CWE carries the CWE- prefix and known MITRE name.
    if version == "2.0":
        assert express["cwe"]["id"] == "CWE-787"
        assert express["cwe"]["name"] == "Out-of-bounds Write"
    else:
        assert express["cwes"][0]["id"] == "CWE-787"

    # Unreachable -> known_not_affected + execute-path flag.
    left_pad = by_cve["CVE-2024-20002"]
    assert left_pad["product_status"]["known_not_affected"] == ["pkg:npm/left-pad@1.3.0"]
    assert any(f["label"] == "vulnerable_code_not_in_execute_path" for f in left_pad["flags"])

    # Unknown CWE name -> cwe omitted entirely.
    ghost = by_cve["CVE-2024-30003"]
    assert "cwe" not in ghost and "cwes" not in ghost
    assert _cvss(ghost, "cvss_v2")

    # Revision history is always populated.
    assert len(doc["document"]["tracking"]["revision_history"]) >= 1
    # No note without text.
    for v in doc["vulnerabilities"]:
        for n in v.get("notes", []):
            assert n.get("text")


def test_build_csaf_asserts_no_dangling_refs():
    bom = _load_demo()
    doc = build_csaf(bom, bom["vulnerabilities"], reached_purls={}, csaf_version="2.1")
    assert referenced_product_ids(doc) <= defined_product_ids(doc)


def test_build_csaf_2_1_has_schema_uri_2_0_does_not():
    bom = _load_demo()
    doc21 = build_csaf(bom, bom["vulnerabilities"], csaf_version="2.1")
    doc20 = build_csaf(bom, bom["vulnerabilities"], csaf_version="2.0")
    assert doc21["$schema"].endswith("v2.1/schema/csaf.json")
    assert doc21["document"]["csaf_version"] == "2.1"
    assert "$schema" not in doc20
    assert doc20["document"]["csaf_version"] == "2.0"


def test_output_path_never_touches_vdr_or_bom():
    # A .vdr.json input must yield a standalone .csaf.json output.
    out = output_path("/proj/reports/sbom-js-build.vdr.json", "/proj/reports")
    assert out == "/proj/reports/sbom-js-build.csaf.json"
    assert out.endswith(".csaf.json")
    assert not out.endswith(".vdr.json")
    out_cdx = output_path("/proj/reports/sbom-js-build.cdx.json", "/proj/reports")
    assert out_cdx == "/proj/reports/sbom-js-build.csaf.json"


@pytest.mark.parametrize("version", VERSIONS)
def test_export_csaf_writes_csaf_file_and_leaves_vdr_intact(tmp_path, version):
    bom = _load_demo()
    # Stage a fake VDR file alongside the output dir to prove it is never touched.
    vdr_path = tmp_path / "demo.vdr.json"
    vdr_path.write_text('{"vdr": true}')
    reached = {"pkg:npm/express@4.22.2": 1}

    class _Result:
        pkg_vulnerabilities = bom["vulnerabilities"]
        reached_purls = reached

    outfile, errors = export_csaf(
        _Result(),
        src_dir=str(tmp_path),
        reports_dir=str(tmp_path),
        bom_file=str(vdr_path),
        bom=bom,
        csaf_version=version,
    )
    assert outfile.endswith(".csaf.json")
    assert errors == []
    # The VDR file must be untouched.
    assert json.loads(vdr_path.read_text()) == {"vdr": True}
    assert Path(outfile).exists()


# ---------------------------------------------------------------------------
# juice-shop e2e (environment-gated; runs when fixtures are available so the
# full real-world document stays under schema/reachability assertion).
# ---------------------------------------------------------------------------

JUICE_SHOP_DIR = os.getenv("DEPSCAN_JUICE_SHOP_DIR", "/Users/prabhu/sandbox/juice-shop")
JUICE_SHOP_BOM = os.path.join(JUICE_SHOP_DIR, "reports", "sbom-js-build.cdx.json")
JUICE_SHOP_VDR = os.path.join(JUICE_SHOP_DIR, "reports", "sbom-js-build.vdr.json")
JUICE_SHOP_SLICES = os.path.join(JUICE_SHOP_DIR, "reports", "js-reachables.slices.json")

juice_shop_present = all(
    os.path.exists(p) for p in (JUICE_SHOP_BOM, JUICE_SHOP_VDR, JUICE_SHOP_SLICES)
)


@pytest.mark.skipif(not juice_shop_present, reason="juice-shop fixtures not available")
@pytest.mark.parametrize("version", VERSIONS)
def test_juice_shop_csaf_is_schema_valid_and_reachability_aware(version):
    import urllib.parse as _up

    bom = json.load(open(JUICE_SHOP_BOM))
    vdr = json.load(open(JUICE_SHOP_VDR))
    reached = {}
    for slice_obj in json.load(open(JUICE_SHOP_SLICES)) or []:
        for p in slice_obj.get("purls") or []:
            key = _up.unquote(p)
            reached[key] = reached.get(key, 0) + 1
    doc = build_csaf(bom, vdr.get("vulnerabilities", []), reached_purls=reached, csaf_version=version)
    # Zero schema errors and no dangling product references.
    assert validate(doc, version) == []
    assert referenced_product_ids(doc) <= defined_product_ids(doc)
    # Reachability is reflected: some known_affected and some known_not_affected
    # carrying the execute-path flag.
    statuses = set()
    for v in doc["vulnerabilities"]:
        statuses.update((v.get("product_status") or {}).keys())
    assert "known_affected" in statuses
    assert "known_not_affected" in statuses
    assert any(
        f.get("label") == "vulnerable_code_not_in_execute_path"
        for v in doc["vulnerabilities"]
        for f in v.get("flags", [])
    )
