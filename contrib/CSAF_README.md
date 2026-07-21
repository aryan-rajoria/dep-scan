## Purpose

Generate [CSAF VEX](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html)
documents populated with vulnerability results and reachability analysis from
OWASP dep-scan.

### How-to

1. Run depscan with the `--csaf` option:

   ```bash
   depscan --bom reports/sbom-build.cdx.json --reports-dir reports --src . --csaf
   ```

2. dep-scan writes a CSAF VEX document named `<base>.csaf.json` (e.g.
   `sbom-build.csaf.json`) into the reports directory. The VDR/BOM file is
   **never** modified.

3. If no `csaf.toml` exists in the target directory, dep-scan writes a starter
   template and **continues** with sensible defaults -- you do not need to run
   the command twice. Edit the toml to customize publisher/tracking metadata
   and rerun to pick up your changes.

### Output naming and the VDR safety guarantee

The output filename is derived from the BOM base name with the `.csaf.json`
suffix (for `sbom-js-build.cdx.json` you get `sbom-js-build.csaf.json`). The
emit layer asserts the output path always ends in `.csaf.json` and never
equals the BOM/VDR path, so the CSAF export cannot overwrite the VDR (a
regression that existed in v6).

### Reachability -> VEX status

When reachability artifacts (e.g. `blint`/`atom` slices) are available,
dep-scan folds them into the VEX assessment:

| Reachability | CSAF `product_status`           | Flag / justification                              |
|--------------|---------------------------------|---------------------------------------------------|
| Reachable    | `known_affected`                | -                                                 |
| Unreachable  | `known_not_affected`            | `component_not_present` / `vulnerable_code_not_in_execute_path` |
| Unknown      | `under_investigation`           | -                                                 |

This is the whole point of a dep-scan VEX: vulnerabilities in dependencies
whose code is not on an executed path are marked `known_not_affected` with a
machine-readable justification, not merely "a fixed version exists".

### Schema validation

Every generated document is validated in-process against the official CSAF
2.0 (or 2.1) JSON schema bundled with the `analysis_lib.vex` package. Any
validation errors are logged with the document still written for debugging.

`--csaf-version {2.0,2.1}` selects the target schema (default `2.1`). Note
that CSAF 2.0 has no `cvss_v4` slot, so CVSS v4 vectors are retained only
when targeting 2.1; CVSS v2/v3 are always mapped. Validation resolves the
FIRST CVSS schemas from bundled copies, so it runs fully offline.

### The csaf.toml

The optional `csaf.toml` sets metadata outside the vulnerabilities section.
Required fields are in **bold**.

| TOML Field    | Subcategories                                                       | Comments                                                                                          |
|---------------|---------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| **document**  | **category**<br>**title**                                           | default category is `csaf_vex`.                                                                   |
| **publisher** | **category**<br>**name**<br>**namespace**<br>contact_details        | valid categories: coordinator, discoverer, other, translator, user, vendor.                       |
| note          | **category**<br>**text**<br>audience<br>title                       | notes without `text` are dropped (CSAF requires non-empty note text).                             |
| reference     | **summary**<br>**url**<br>category                                  | valid categories: self, external.                                                                 |
| **tracking**  | **status**<br>**version**<br>id<br>current_release_date<br>initial_release_date | dates default to now; version defaults to the latest revision number.                  |
| tracking.revision_history | date<br>number<br>summary                                 | the document always carries at least one revision entry (CSAF requires a non-empty array).        |

The `product_tree` is built automatically from the CycloneDX BOM components
(every component's purl becomes its `product_id`), so no manual product-tree
import is needed.

#### A few notes on tracking

`tracking.revision_history` is **always** non-empty: CSAF requires at least
one revision entry even for `draft` documents. The document `version` equals
the latest revision number. If you leave dates blank, dep-scan uses the
current UTC time.

### Validation

Validation runs automatically during generation. To validate a document
manually:

```bash
pip install check-jsonschema
check-jsonschema --schemafile contrib/csaf_2.0_schema.json path/to/your.csaf.json
```

### Questions? Comments? Suggestions?

Feel free to reach out to us on [discord](https://discord.gg/DCNxzaeUpd) or
start a discussion on the [OWASP dep-scan repo](https://github.com/owasp-dep-scan/dep-scan).
