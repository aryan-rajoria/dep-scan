from depscan.lib.package_query.metadata import npm_metadata, pypi_metadata, cargo_metadata

# Dict mapping project type to risk audit
risk_audit_map = {
    "npm": npm_metadata,
    "nodejs": npm_metadata,
    "js": npm_metadata,
    "javascript": npm_metadata,
    "ts": npm_metadata,
    "typescript": npm_metadata,
    "python": pypi_metadata,
    "py": pypi_metadata,
    "pypi": pypi_metadata,
    "cargo": cargo_metadata,
    "rust": cargo_metadata,
}


def risk_audit(project_type, scoped_pkgs, private_ns, pkg_list):
    """
    Method to perform risk audit for packages using package managers api

    :param scoped_pkgs: A list of scoped packages.
    :param project_type: Project type
    :param private_ns: Private namespace
    :param pkg_list: List of packages
    :return: Results of risk audit
    """
    audit_fn = risk_audit_map[project_type]
    results = audit_fn(scoped_pkgs, pkg_list, private_ns)
    return results
