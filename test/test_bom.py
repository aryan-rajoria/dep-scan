import os

from depscan.lib.bom import (
    get_pkg_by_type,
    get_pkg_list,
    parse_bom_ref,
    update_tools_metadata,
)


def test_get_pkg():
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom.xml"
    )
    pkg_list = get_pkg_list(test_bom)
    assert len(pkg_list) == 157
    for pkg in pkg_list:
        assert pkg["vendor"] != "maven"
        assert " " not in pkg["name"]
        assert pkg["version"]
    test_py_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-py.xml"
    )
    pkg_list = get_pkg_list(test_py_bom)
    assert len(pkg_list) == 31
    for pkg in pkg_list:
        assert pkg["vendor"] == "pypi"
        assert " " not in pkg["name"]
        assert pkg["version"]
    test_dn_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-dotnet.xml"
    )
    pkg_list = get_pkg_list(test_dn_bom)
    assert len(pkg_list) == 38
    for pkg in pkg_list:
        assert pkg["vendor"]
        assert " " not in pkg["name"]
        assert pkg["version"]

    test_dn_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-dotnet2.xml"
    )
    pkg_list = get_pkg_list(test_dn_bom)
    assert len(pkg_list) == 6
    for pkg in pkg_list:
        assert pkg["vendor"]
        assert " " not in pkg["name"]
        assert pkg["version"]


def test_parse():
    assert parse_bom_ref("pkg:maven/org.projectlombok/lombok@1.18.4?type=jar") == {
        "vendor": "org.projectlombok",
        "name": "lombok",
        "version": "1.18.4",
        "licenses": None,
    }

    assert parse_bom_ref("pkg:maven/org.projectlombok/lombok@1.18.4") == {
        "vendor": "org.projectlombok",
        "name": "lombok",
        "version": "1.18.4",
        "licenses": None,
    }

    assert parse_bom_ref("pkg:pypi/atomicwrites@1.3.0") == {
        "vendor": "pypi",
        "name": "atomicwrites",
        "version": "1.3.0",
        "licenses": None,
    }

    assert parse_bom_ref("pkg:npm/body-parser@1.18.3") == {
        "vendor": "npm",
        "name": "body-parser",
        "version": "1.18.3",
        "licenses": None,
    }

    assert parse_bom_ref("pkg:npm/@cyclonedx/cdxgen@1.10.0") == {
        "vendor": "@cyclonedx",
        "name": "cdxgen",
        "version": "1.10.0",
        "licenses": None,
    }
    assert parse_bom_ref("pkg:golang/cloud.google.com/go@v0.34.0") == {
        "vendor": "cloud.google.com",
        "name": "go",
        "version": "0.34.0",
        "licenses": None,
    }
    assert parse_bom_ref("pkg:golang/cloud.google.com/go/bigquery@v1.0.1") == {
        "vendor": "go",
        "name": "bigquery",
        "version": "1.0.1",
        "licenses": None,
    }
    assert parse_bom_ref(
        "pkg:golang/github.com%2FAzure%2Fazure-amqp-common-go/v2@v2.1.0"
    ) == {
        "vendor": "azure-amqp-common-go",
        "name": "v2",
        "version": "2.1.0",
        "licenses": None,
    }
    assert parse_bom_ref(
        "pkg:golang/github.com%2FAzure/go-autorest@v13.0.0%2Bincompatible"
    ) == {
        "vendor": "Azure",
        "name": "go-autorest",
        "version": "13.0.0+incompatible",
        "licenses": None,
    }
    assert parse_bom_ref(
        "pkg:golang/github.com%2Fdocker/docker@v0.7.3-0.20190327010347-be7ac8be2ae0"
    ) == {
        "vendor": "docker",
        "name": "docker",
        "version": "0.7.3-0.20190327010347-be7ac8be2ae0",
        "licenses": None,
    }


def test_get_pkg_by_type():
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-docker.json"
    )
    pkg_list = get_pkg_list(test_bom)
    assert len(pkg_list) == 1824
    filtered_list = get_pkg_by_type(pkg_list, "npm")
    assert len(filtered_list) == 1823


# ---------------------------------------------------------------------------
# T5 — CycloneDX 1.7 parse/emit readiness
# ---------------------------------------------------------------------------


def test_get_pkg_list_parses_cyclonedx_1_7_xml():
    """A CycloneDX 1.7 XML BOM (cdxgen 12.8 default) must parse cleanly,
    including the licenses section under the 1.7 namespace."""
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-1.7.xml"
    )
    pkg_list = get_pkg_list(test_bom)
    assert pkg_list is not None
    assert len(pkg_list) == 2
    by_name = {p["name"]: p for p in pkg_list}
    assert "lodash" in by_name
    assert by_name["lodash"]["version"] == "4.17.21"
    # Licenses must be extracted from the 1.7 namespace
    assert "MIT" in by_name["lodash"]["licenses"]
    assert "BSD-3-Clause" in by_name["django"]["licenses"]


def test_update_tools_metadata_preserves_existing_spec_version():
    """When a source BOM has specVersion 1.7, update_tools_metadata must not
    downgrade it to 1.6."""
    bom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {"tools": {}},
    }
    result = update_tools_metadata({}, bom_data, "1.0.0")
    assert result["specVersion"] == "1.7"


def test_update_tools_metadata_defaults_for_new_bom():
    """A from-scratch VDR (no source BOM) gets a valid specVersion."""
    result = update_tools_metadata(None, None, "1.0.0")
    assert result["specVersion"]  # some valid version
    assert result["bomFormat"] == "CycloneDX"


def test_export_bom_preserves_source_spec_version(tmp_path):
    """VDR specVersion must be ≥ source specVersion (never downgraded)."""
    from depscan.lib.bom import export_bom

    bom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {"tools": {"components": []}},
        "components": [],
    }
    vdr_file = str(tmp_path / "test.vdr.json")
    export_bom(bom_data, "1.0.0", [], vdr_file)
    import json

    with open(vdr_file) as f:
        vdr = json.load(f)
    assert vdr["specVersion"] == "1.7"
