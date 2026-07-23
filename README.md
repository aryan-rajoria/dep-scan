# Introduction

OWASP dep-scan is a next-generation security and risk audit tool based on known vulnerabilities, advisories, and license limitations for project dependencies. Both local repositories and container images are supported as the input, and the tool is ideal for integration with ASPM/VM platforms and in CI environments.

<img src="depscan-logo.png" width="200" height="auto" />

[![SBOM](https://img.shields.io/badge/SBOM-with_%E2%9D%A4%EF%B8%8F_by_cdxgen-FF753D)](https://github.com/cdxgen/cdxgen) [![release](https://github.com/owasp-dep-scan/dep-scan/actions/workflows/pythonpublish.yml/badge.svg)](https://github.com/owasp-dep-scan/dep-scan/actions/workflows/pythonpublish.yml)

## Contents

- [Features](#features)
    - [Precise reachable data-flows](#precise-reachable-data-flows)
    - [Reachability matrix](#reachability-matrix)
    - [Rust reachability (via rusi)](#rust-reachability-via-rusi)
    - [Go reachability (via golem)](#go-reachability-via-golem)
    - [.NET reachability (via dosai)](#net-reachability-via-dosai)
    - [JVM, JavaScript, Python, and PHP reachability (via atom)](#jvm-javascript-python-and-php-reachability-via-atom)
    - [Vulnerability Data sources](#vulnerability-data-sources)
    - [Linux distros](#linux-distros)
- [Quick Start](#quick-start)
    - [Scanning projects locally (Python version)](#scanning-projects-locally-python-version)
    - [Standalone binaries (no Python or Node.js required)](#standalone-binaries-no-python-or-nodejs-required)
    - [Scanning containers locally (Python version)](#scanning-containers-locally-python-version)
    - [Scanning projects locally (Docker container)](#scanning-projects-locally-docker-container)
    - [Server mode](#server-mode)
- [Local development](#local-development)
- [Documentation (depscan.readthedocs.io)](https://depscan.readthedocs.io)
- [License](#license)

## Features

- Scan most application code (local repos, Linux container images, Kubernetes manifests, and OS) to identify known CVEs with prioritization
- Perform advanced reachability analysis for multiple languages (see the [reachability matrix](#reachability-matrix) below)
- Package vulnerability scanning is performed locally and is quite fast. No server is used
- Generate Software Bill-of-Materials (SBOM) with Vulnerability Disclosure Report (VDR) information
- Generate a Common Security Advisory Framework (CSAF) 2.0/2.1 VEX document (check out the [CSAF Readme](contrib/CSAF_README.md))
- Perform deep packages risk audit for dependency confusion attacks and maintenance risks (see the [risk audit docs](https://depscan.readthedocs.io/adv-usage#package-risk-audit))

### Precise Reachable data-flows

Detailed data flows to identify both reachable and non-reachable paths in your application based on the full context.

![Reachable Flows](documentation/static/img/depscan-flows.png)

### Reachability matrix

dep-scan computes reachability for seven language ecosystems through four slicers. A vulnerable package whose code is actually on an executed path is marked **Reachable**, while a package that is merely declared in the BOM but never called is not. Every slicer feeds the same shared, purl-keyed reachability engine, so the behavior is uniform across languages. Reachability is on by default (`--reachability-analyzer FrameworkReachability`); `SemanticReachability` additionally attributes reached services, endpoints, and post-build (binary/container) reachability.

| Language / ecosystem               | Reachability engine                                   | Default analyzer        |
| ---------------------------------- | ----------------------------------------------------- | ----------------------- |
| Java / JVM (Groovy, Kotlin, Scala) | [atom](https://github.com/AppThreat/atom)             | `FrameworkReachability` |
| JavaScript / TypeScript            | atom                                                  | `FrameworkReachability` |
| Python                             | atom                                                  | `FrameworkReachability` |
| PHP                                | atom                                                  | `FrameworkReachability` |
| Rust                               | [rusi](https://github.com/appthreat/rusi)             | `FrameworkReachability` |
| Go                                 | [golem](https://github.com/cdxgen/cdxgen-plugins-bin) | `FrameworkReachability` |
| .NET (C#, VB, F#, R)               | [dosai](https://github.com/owasp-dep-scan/dosai)      | `FrameworkReachability` |

For the concepts behind reachability and prioritization, read the [reachability model](https://depscan.readthedocs.io/concepts/reachability-model) and [prioritization](https://depscan.readthedocs.io/concepts/prioritization) chapters. For per-language worked examples, see the [Language Guides](https://depscan.readthedocs.io/languages/rust-reachability). For the compliance story (VDR and CSAF VEX), see the [VDR guide](https://depscan.readthedocs.io/output/vdr-guide) and the [CSAF VEX guide](https://depscan.readthedocs.io/output/vex-csaf-guide).

### Rust reachability (via rusi)

Rust reachability is powered by [rusi (Rust Source Inspector)](https://github.com/appthreat/rusi), a Rust analysis engine that emits a call graph and interprocedural source-to-sink data-flow slices with PURL attribution. dep-scan converts that report into its shared purl-keyed reachability pipeline, so a vulnerable crate that is actually **called** (for example `time::now()` for RUSTSEC-2020-0071) is marked **Reachable** while a crate that is merely present in the BOM but never called is not. See the [Rust reachability guide](https://depscan.readthedocs.io/languages/rust-reachability) for a worked example on the in-repo `rustsec-app` fixture.

**How it runs.** Under `--profile research` (which dep-scan forces when reachability is on), `cdxgen` runs rusi via evinse for Rust projects and persists the full raw rusi report to the `*-semantics.slices.json` path. dep-scan then consumes that persisted report; it does **not** spawn rusi itself when cdxgen and the plugins are available. rusi is invoked directly only as a fallback.

**Enabling it.** Reachability is on by default for Rust (`--reachability-analyzer FrameworkReachability`); `SemanticReachability` additionally attributes reached services and endpoints.

```bash
# rust reachability is automatic; just scan the project
depscan -i ./my-rust-app -o ./reports --profile research

# point dep-scan at a dev build of rusi
DEPSCAN_RUSI_BINARY=/path/to/rusi depscan -i ./my-rust-app -o ./reports
```

**Locating the rusi binary.** dep-scan resolves rusi the same way cdxgen does: the `RUSI_CMD` env var, then `DEPSCAN_RUSI_BINARY`, then `rusi` on `PATH`, then the bundled `cdxgen-plugins-bin` layout (`<pluginsDir>/rusi/rusi-<platform>-<arch>`). When cdxgen spawns, dep-scan propagates `RUSI_CMD` and `CDXGEN_PLUGINS_DIR` to the subprocess so both sides use the same binary. If rusi cannot be found, Rust reachability is skipped with a warning (never a crash); other languages are unaffected.

**Backend safety.** The default `stable` backend (`--rust-analyzer-backend stable`) is syn-based parsing only and is safe on untrusted repositories. The `compiler` backend (`--rust-analyzer-backend compiler`, also implied by `--deep`) embeds nightly rustc and builds the target (runs `cargo`/`rustc`), so it is enabled only via explicit opt-in; consult the rusi threat model before pointing it at untrusted code.

### Go reachability (via golem)

Go reachability is powered by [golem (Go Source Inspector)](https://github.com/cdxgen/cdxgen-plugins-bin), a Go static-analysis engine shipped prebuilt via cdxgen-plugins-bin. golem emits a call graph, interprocedural source-to-sink data-flow slices, API endpoints, and symbol-usage evidence with PURL attribution. dep-scan converts that report into its shared purl-keyed reachability pipeline, so a vulnerable module that is actually **called** (for example `pgx.Connect` for a SQL-injection CVE) is marked **Reachable** while a module that is merely present in the BOM but never called is not. See the [Go reachability guide](https://depscan.readthedocs.io/languages/go-reachability) for a worked example on the in-repo `real-cve-app` fixture.

**How it runs.** dep-scan invokes golem directly when a Go project is detected (`-t go`) and reachability is on. golem requires a local Go toolchain (`go` on `PATH`) to load packages. The `--include-all-flows` flag is always passed so dependency-internal flows (the CVE-reachability signal) are retained.

**Enabling it.** Reachability is on by default for Go (`--reachability-analyzer FrameworkReachability`); `SemanticReachability` additionally attributes reached services and endpoints.

```bash
# go reachability is automatic; just scan the project
depscan -i ./my-go-app -o ./reports -t go

# point dep-scan at a specific golem binary
DEPSCAN_GOLEM_BINARY=/path/to/golem depscan -i ./my-go-app -o ./reports -t go

# forbid network access during analysis (requires warm module cache)
depscan -i ./my-go-app -o ./reports -t go --go-analyzer-network offline
```

**Locating the golem binary.** dep-scan resolves golem the same way cdxgen does: the `GOLEM_CMD` env var, then `DEPSCAN_GOLEM_BINARY`, then `golem` on `PATH`, then the bundled `cdxgen-plugins-bin` layout (`<pluginsDir>/golem/golem-<platform>-<arch>`). When cdxgen spawns, dep-scan propagates `GOLEM_CMD` and `CDXGEN_PLUGINS_DIR` to the subprocess so both sides use the same binary. If golem or the Go toolchain cannot be found, Go reachability is skipped with a warning (never a crash); other languages are unaffected.

**Safety.** golem loads packages via `golang.org/x/tools/go/packages` with full type/SSA info but does **not** run the program and does **not** run `go:generate`. Package loading uses the local Go toolchain, so module downloads can occur depending on the Go env. dep-scan defaults to `GOFLAGS=-mod=readonly` to prevent `go.mod` rewrites on untrusted repos. Use `--go-analyzer-network offline` (sets `GOPROXY=off`) to forbid all downloads; this requires a warm module cache (`GOMODCACHE`).

### .NET reachability (via dosai)

.NET reachability (C#/VB/F#/R) is powered by [dosai (Dotnet Source and Assembly Inspector)](https://github.com/owasp-dep-scan/dosai), a .NET analysis engine shipped prebuilt via cdxgen-plugins-bin. dosai inspects source (Roslyn) and assemblies (Reflection + IL) and emits a call graph, interprocedural source-to-sink data-flow slices, explicit per-package reachability (`PackageReachability` with `ReachabilityKind` and `Confidence`), weakness candidates (CWE-tagged), and dangerous-API reachability. dep-scan consumes dosai's **native** facts directly for the reachability verdict and emits an atom-shaped projection so a vulnerable NuGet package that is actually **called** (for example `Newtonsoft.Json.JsonConvert.DeserializeObject` on a controlled input) is marked **Reachable** while a package that is merely referenced but never called is not. See the [.NET reachability guide](https://depscan.readthedocs.io/languages/dotnet-reachability) for a worked example on the in-repo `reachable-app` and `unreachable-app` fixtures.

**How it runs.** Under `--profile research` (forced when reachability is on), `cdxgen` runs dosai and persists the combined native report `{Metadata, methods, dataflows}` to the `*-semantics.slices.json` path. dep-scan consumes that persisted report (the PRIMARY path) and does **not** spawn dosai itself when cdxgen and the plugins are available. dosai is invoked directly only as a fallback (`dataflows` + `methods` with `--pattern-packs all`).

**Enabling it.** Reachability is on by default for .NET projects (`-t dotnet`, `--reachability-analyzer FrameworkReachability`); `SemanticReachability` additionally attributes reached services and endpoints.

```bash
# .NET reachability is automatic; just scan the project
depscan -i ./my-dotnet-app -o ./reports -t dotnet

# point dep-scan at a specific dosai binary
DEPSCAN_DOSAI_BINARY=/path/to/dosai depscan -i ./my-dotnet-app -o ./reports -t dotnet

# prefer source vs assembly inspection explicitly
depscan -i ./my-dotnet-app -o ./reports -t dotnet --dotnet-analyzer-mode source
```

**Locating the dosai binary.** dep-scan resolves dosai the same way cdxgen does: the `DOSAI_CMD` env var, then `DEPSCAN_DOSAI_BINARY`, then `dosai`/`Dosai` on `PATH`, then the bundled `cdxgen-plugins-bin` layout (`<pluginsDir>/dosai/dosai-<platform>-<arch>`). When cdxgen spawns, dep-scan propagates `DOSAI_CMD` and `CDXGEN_PLUGINS_DIR` to the subprocess so both sides use the same binary. If dosai cannot be found, .NET reachability is skipped with a warning (never a crash); other languages are unaffected.

**Runtime requirement.** dosai needs a .NET runtime to load; dep-scan probes `dotnet --version` and skips gracefully with a diagnostic when absent. A self-contained `-full` dosai binary (from the [dosai releases](https://github.com/owasp-dep-scan/dosai/releases)) bundles the runtime and needs no SDK. For best versioned NuGet purls, scan a **restored** tree (`project.assets.json` / `*.deps.json` present); dosai falls back to versionless `System.*` framework purls otherwise. dep-scan does **not** run `dotnet restore` itself (untrusted-repo/network risk).

### JVM, JavaScript, Python, and PHP reachability (via atom)

Java and the wider JVM (Groovy, Kotlin, Scala), JavaScript and TypeScript, Python, and PHP share a single slicer, [atom](https://github.com/AppThreat/atom), which builds a language-agnostic intermediate representation and performs static slicing for reachability and usages. dep-scan consumes the resulting `*-reachables.slices.json` to mark vulnerable packages **Reachable** when they sit on a traced data-flow or call-graph path. See the [JVM, JS, Python, and PHP reachability guide](https://depscan.readthedocs.io/languages/jvm-js-python-php-reachability) for the per-language commands and the workflow to move from `FrameworkReachability` to `SemanticReachability`.

**Enabling it.** Use the `research` profile so cdxgen persists the atom slices; reachability is then on by default. Pass `--explain` for a detailed flow breakdown.

```bash
# Java / JVM
depscan --profile research -t java -i ./my-java-app -o ./reports --explain

# JavaScript / TypeScript
depscan --profile research -t js -i ./my-js-app -o ./reports --explain

# Python
depscan --profile research -t python -i ./my-python-app -o ./reports --explain

# PHP (ensure PHP >= 7.4 is installed, or use the container image)
depscan --profile research -t php -i ./my-php-app -o ./reports --explain
```

`SemanticReachability` adds endpoint, service, and post-build reachability tiers, which need lifecycle BOMs. The recommended workflow is to build the project and container images, generate the BOMs, and run dep-scan with `--bom-dir`. See the [semantic reachability guide](https://depscan.readthedocs.io/analyzers/semantic-reachability) for the full workflow.

### Clear insights about CVEs

Understand CVEs clearly without having to read through the description.

![Dependency Tree with Insights](documentation/static/img/tree1.png)

### Automatic prioritization

Only focus on CVEs that need your attention.

![Prioritization](documentation/static/img/prioritization.png)

### Stay proactive

Always stay a step ahead with advanced vulnerability and exploit prediction.

![Proactive Measures](documentation/static/img/proactive.png)

### Vulnerability Data sources

- OSV
- NVD
- GitHub
- NPM
- Linux [vuln-list](https://github.com/appthreat/vuln-list)

### Linux distros

- AlmaLinux
- Debian
- Alpine
- Amazon Linux
- Arch Linux
- RHEL/CentOS
- Rocky Linux
- Ubuntu
- OpenSUSE/SLES
- Photon
- Chainguard
- Wolfi OS

## Quick Start

dep-scan is ideal for use during continuous integration (CI) and as a local development tool.

### Scanning projects locally (Python version)

```bash
sudo npm install -g @cyclonedx/cdxgen
# Normal version recommended for most users (MIT)
pip install owasp-depscan

# For a full version with all extensions and server mode (Multiple Licenses)
pip install owasp-depscan[all]
```

This would install two commands called `cdxgen` and `depscan`.

You can invoke the scan command directly with the various options.

```bash
cd <project to scan>
depscan --src $PWD --reports-dir $PWD/reports
```

The full list of options is below:

```text
usage: depscan [-h] [--config CONFIG] [--no-banner] [-i SRC_DIR_IMAGE] [-o REPORTS_DIR] [--csaf]
               [--profile {appsec,research,operational,threat-modeling,license-compliance,generic,machine-learning,ml,deep-learning,ml-deep,ml-tiny}]
               [--lifecycle {pre-build,build,post-build} [{pre-build,build,post-build} ...]]
               [--technique {auto,source-code-analysis,binary-analysis,manifest-analysis,hash-comparison,instrumentation,filename} [{auto,source-code-analysis,binary-analysis,manifest-analysis,hash-comparison,instrumentation,filename} ...]]
               [--bom-engine {auto,CdxgenGenerator,CdxgenServerGenerator,CdxgenImageBasedGenerator,BlintGenerator} |
               --vulnerability-analyzer {auto,VDRAnalyzer,LifecycleAnalyzer}] [--reachability-analyzer {off,FrameworkReachability,SemanticReachability}] [--no-suggest]
               [--risk-audit] [--cdxgen-args CDXGEN_ARGS] [--private-ns PRIVATE_NS] [-t PROJECT_TYPE [PROJECT_TYPE ...]] [--bom BOM | --bom-dir BOM_DIR | --purl SEARCH_PURL]
               [--report-template REPORT_TEMPLATE] [--report-name REPORT_NAME] [--deep] [--fuzzy-search] [--search-order {purl,pcu,cpe,cpu,url}] [--no-universal]
               [--no-vuln-table] [--server] [--server-host SERVER_HOST] [--server-port SERVER_PORT] [--cdxgen-server CDXGEN_SERVER] [--debug] [-q | --explain] [-v]

Fully open-source security and license audit for application dependencies and container images based on known vulnerabilities and advisories.

options:
  -h, --help            show this help message and exit
  --config CONFIG       Path to the configuration file. Default: $PWD/.config/depscan.toml
  --no-banner           Do not display the logo and donation banner. Please make a donation to OWASP before using this argument.
  -i, --src SRC_DIR_IMAGE
                        Source directory or container image or binary file
  -o, --reports-dir REPORTS_DIR
                        Reports directory
  --csaf                Generate a OASIS CSAF VEX document
  --profile {appsec,research,operational,threat-modeling,license-compliance,generic,machine-learning,ml,deep-learning,ml-deep,ml-tiny}
                        Profile to use while generating the BOM. For granular control, use the arguments --bom-engine, --vulnerability-analyzer, or --reachability-analyzer.
  --lifecycle {pre-build,build,post-build} [{pre-build,build,post-build} ...]
                        Product lifecycle for the generated BOM. Multiple values allowed.
  --technique {auto,source-code-analysis,binary-analysis,manifest-analysis,hash-comparison,instrumentation,filename} [{auto,source-code-analysis,binary-analysis,manifest-analysis,hash-comparison,instrumentation,filename} ...]
                        Analysis technique to use for BOM generation. Multiple values allowed.
  --bom-engine {auto,CdxgenGenerator,CdxgenServerGenerator,CdxgenImageBasedGenerator,BlintGenerator}
                        BOM generation engine to use. Defaults to automatic selection based on project type and lifecycle.
  --vulnerability-analyzer {auto,VDRAnalyzer,LifecycleAnalyzer}
                        Vulnerability analyzer to use. Defaults to automatic selection based on bom_dir argument.
  --reachability-analyzer {off,FrameworkReachability,SemanticReachability}
                        Reachability analyzer to use. Default FrameworkReachability.
  --no-suggest          Disable suggest mode
  --risk-audit          Perform package risk audit (slow operation). Npm only.
  --cdxgen-args CDXGEN_ARGS
                        Additional arguments to pass to cdxgen
  --private-ns PRIVATE_NS
                        Private namespace to use while performing oss risk audit. Private packages should not be available in public registries by default. Comma separated
                        values accepted.
  -t, --type PROJECT_TYPE [PROJECT_TYPE ...]
                        Override project types if auto-detection is incorrect. Multiple values supported.
  --bom BOM             Examine using the given Software Bill-of-Materials (SBOM) file in CycloneDX format. Use cdxgen command to produce one.
  --bom-dir BOM_DIR     Examine all the Bill-of-Materials (BOM) files in the given directory.
  --purl SEARCH_PURL    Scan a single package url.
  --custom-data CUSTOM_DATA
                        Path to directory containing custom vulnerability data (JSON/YAML/TOML) to override/augment results.
  --report-template REPORT_TEMPLATE
                        Jinja template file used for rendering a custom report
  --report-name REPORT_NAME
                        Filename of the custom report written to the --reports-dir
  --deep                Perform deep scan by passing this --deep argument to cdxgen. Useful while scanning docker images and OS packages.
  --fuzzy-search        Perform fuzzy search by creating variations of package names. Use this when the input SBOM lacks a PURL.
  --search-order {purl,pcu,cpe,cpu,url}
                        Attributes to use while searching for vulnerabilities. Default: PURL, CPE, URL (pcu).
  --no-universal        Depscan would attempt to perform a single universal scan instead of individual scans per language type.
  --no-vuln-table       Do not print the table with the full list of vulnerabilities. This can help reduce console output.
  --server              Run depscan as a server
  --server-host SERVER_HOST
                        depscan server host
  --server-port SERVER_PORT
                        depscan server port
  --server-allowed-hosts [SERVER_ALLOWED_HOSTS ...]
                        List of allowed hostnames or IPs that can access the server (e.g., 'localhost 192.168.1.10'). If unspecified, no host allowlist is
                        enforced.
  --server-allowed-paths [SERVER_ALLOWED_PATHS ...]
                        List of allowed filesystem paths that can be scanned by the server. Restricts `path` parameter in /scan requests.
  --cdxgen-server CDXGEN_SERVER
                        cdxgen server url. Eg: http://cdxgen:9090
  --debug               Run depscan in debug mode.
  -q, --quiet           Makes depscan quiet.
  --explain             Makes depscan to explain the various analysis. Useful for creating detailed reports.
  --explanation-mode {Endpoints,EndpointsAndReachables,NonReachables,LLMPrompts}
                        Style of explanation needed. Defaults to Endpoints and Reachables.
  --annotate            Include the generated text VDR report as an annotation. Defaults to true when explain is enabled; false otherwise.
  -v, --version         Display the version
```

### Standalone binaries (no Python or Node.js required)

Pre-built single-file executables are attached to each [GitHub release](https://github.com/owasp-dep-scan/dep-scan/releases). They bundle a matching [cdxgen](https://github.com/cdxgen/cdxgen) SEA binary, so BOM generation works out of the box without installing Python, Node.js, or cdxgen.

| Platform              | Architecture  | Asset                       |
| --------------------- | ------------- | --------------------------- |
| Linux (glibc)         | x86_64        | `depscan-linux-amd64`       |
| Linux (glibc)         | arm64         | `depscan-linux-arm64`       |
| Linux (musl / Alpine) | x86_64        | `depscan-linux-amd64-musl`  |
| Linux (musl / Alpine) | arm64         | `depscan-linux-arm64-musl`  |
| macOS                 | Apple silicon | `depscan-darwin-arm64`      |
| macOS                 | Intel         | `depscan-darwin-amd64`      |
| Windows               | x86_64        | `depscan-windows-amd64.exe` |

Each asset has a matching `.sha256` file for verification.

```bash
# Example: Linux x86_64
curl -LO https://github.com/owasp-dep-scan/dep-scan/releases/latest/download/depscan-linux-amd64
curl -LO https://github.com/owasp-dep-scan/dep-scan/releases/latest/download/depscan-linux-amd64.sha256
sha256sum -c depscan-linux-amd64.sha256
chmod +x depscan-linux-amd64
./depscan-linux-amd64 --src $PWD --reports-dir $PWD/reports
```

> [!NOTE]
> The macOS binaries are currently unsigned. On first run macOS Gatekeeper may block them; clear the quarantine attribute with `xattr -d com.apple.quarantine ./depscan-darwin-arm64` (or allow the binary under System Settings, Privacy & Security).

> [!NOTE]
> The vulnerability database is still downloaded on first run. Only cdxgen is bundled, not the vuln DB. Set `VDB_DATABASE_URL` (for example `ghcr.io/appthreat/vdbxz-app-2y:v6.7.x` for a smaller, recent-years-only database) to control which database is fetched.

All standalone binaries bundle `blint`, but not its optional `nyxstone` disassembly backend (which has no wheels and no Windows support). Deep disassembly-based binary analysis is therefore unavailable in the standalone binaries; use the Python package (`pip install owasp-depscan[all]`) if you need it.

### Scanning containers locally (Python version)

Scan a Java project.

```bash
depscan --src <path> -o containertests -t java
```

Scan `latest` tag of the container `shiftleft/scan-slim`

```bash
depscan --src shiftleft/scan-slim -o containertests -t docker
```

Include `license` to the type to perform the license audit.

```bash
depscan --src shiftleft/scan-slim -o containertests -t docker license
```

You can also specify the image using the sha256 digest

```bash
depscan --src redmine@sha256:a5c5f8a64a0d9a436a0a6941bc3fb156be0c89996add834fe33b66ebeed2439e -o containertests -t docker
```

You can also save container images using docker or podman save command and pass the archive to depscan for scanning.

```bash
docker save -o /tmp/scanslim.tar shiftleft/scan-slim:latest
# podman save --format oci-archive -o /tmp/scanslim.tar shiftleft/scan-slim:latest
depscan --src /tmp/scanslim.tar -o reports -t docker
```

Refer to the docker tests under the GitHub action workflow for this repo for more examples.

### Scanning projects locally (Docker container)

`ghcr.io/owasp-dep-scan/dep-scan` container image can be used to perform the scan.

To scan with default settings

```bash
docker run --rm -v $PWD:/app ghcr.io/owasp-dep-scan/dep-scan depscan --src /app --reports-dir /app/reports
```

To scan with custom environment variables based configuration

```bash
docker run --rm \
    -e VDB_HOME=/db \
    -e GITHUB_TOKEN=<token> \
    -v /tmp:/db \
    -v $PWD:/app ghcr.io/owasp-dep-scan/dep-scan depscan --src /app --reports-dir /app/reports
```

In the above example, `/tmp` is mounted as `/db` into the container. This directory is then specified as `VDB_HOME` for caching the vulnerability information. This way the database can be cached and reused to improve performance.

### Server mode

dep-scan and cdxgen could be run in server mode. Use the included docker-compose file to get started.

```bash
git clone https://github.com/owasp-dep-scan/dep-scan
docker compose up
```

The bundled compose file sets `DEPSCAN_SERVER_API_KEY` to a development placeholder by default so the dep-scan service can bind to `0.0.0.0`. Override this value before exposing the service outside a local lab.

```bash
depscan --server --server-host 127.0.0.1 --server-port 7070
```

If you need to bind dep-scan to a non-local address, set an API key first:

```bash
export DEPSCAN_SERVER_API_KEY="change-this-before-production"
depscan --server --server-host 0.0.0.0 --server-port 7070
```

> [!IMPORTANT]
> dep-scan refuses to bind to a non-local address without either `DEPSCAN_SERVER_API_KEY` or an explicit opt-in via `DEPSCAN_SERVER_ALLOW_UNAUTHENTICATED_BIND=true`.

Use the `/scan` endpoint to perform scans.

> [!NOTE]
> The `type` parameter is mandatory in server mode. When API key authentication is enabled, send the key using `X-API-Key` or `Authorization: Bearer <key>`.

- Scanning a local directory.
  Scanning an SBOM file (present locally).

```bash
curl \
  -H 'X-API-Key: dev-only-change-me' \
  --json '{"path": "/tmp/vulnerable-aws-koa-app/sbom_file.json", "type": "js"}' \
  http://127.0.0.1:7070/scan
```

- Scanning a GitHub repo.

```bash
curl \
  -H 'Authorization: Bearer dev-only-change-me' \
  --json '{"url": "https://github.com/HooliCorp/vulnerable-aws-koa-app", "type": "js"}' \
  http://127.0.0.1:7070/scan \
  -o app.vdr.json
```

- Uploading an SBOM file and generating results based on it.

```bash
curl -X POST \
  -H 'X-API-Key: dev-only-change-me' \
  -H 'Content-Type: multipart/form-data' \
  -F 'file=@/tmp/app/sbom_file.json' \
  http://127.0.0.1:7070/scan?type=js
```

## Local development

Setup uv by following the official [documentation](https://docs.astral.sh/uv/).

```shell
uv sync --all-extras --all-packages
uv run depscan --help
uv run pytest
```

### Local VDB setup

```shell
vdb --clean
vdb --download-image
# To scan containers and OS images
# vdb --download-full-image
```

### Scan local depscan

```shell
uv run depscan --config .config/depscan-dev.toml
```

This would automatically use the configuration specified in the local config [file](./.config/depscan.toml).

## Documentation

Full documentation is at [depscan.readthedocs.io](https://depscan.readthedocs.io). Key pages:

- [Supported languages and reachability matrix](https://depscan.readthedocs.io/supported-languages)
- [Reachability analysis](https://depscan.readthedocs.io/reachability-analysis) (hub)
    - [The reachability model](https://depscan.readthedocs.io/concepts/reachability-model)
    - [How dep-scan prioritizes](https://depscan.readthedocs.io/concepts/prioritization)
    - [SBOM and evidence](https://depscan.readthedocs.io/concepts/sbom-and-evidence)
    - Language guides: [Rust](https://depscan.readthedocs.io/languages/rust-reachability), [Go](https://depscan.readthedocs.io/languages/go-reachability), [.NET](https://depscan.readthedocs.io/languages/dotnet-reachability), [JVM/JS/Python/PHP](https://depscan.readthedocs.io/languages/jvm-js-python-php-reachability)
    - Analyzers: [Framework reachability](https://depscan.readthedocs.io/analyzers/framework-reachability), [Semantic reachability](https://depscan.readthedocs.io/analyzers/semantic-reachability)
- Output and compliance: [VDR guide](https://depscan.readthedocs.io/output/vdr-guide), [CSAF VEX guide](https://depscan.readthedocs.io/output/vex-csaf-guide)
- [Customization through environment variables](https://depscan.readthedocs.io/env-var#customization-through-environment-variables)
- Advanced usage: [GitHub Security Advisory](https://depscan.readthedocs.io/adv-usage#github-security-advisory), [Suggest mode](https://depscan.readthedocs.io/adv-usage#suggest-mode), [Package Risk audit](https://depscan.readthedocs.io/adv-usage#package-risk-audit), [Live OS scan](https://depscan.readthedocs.io/adv-usage#live-os-scan), [License scan](https://depscan.readthedocs.io/adv-usage#license-scan), [Custom reports](https://depscan.readthedocs.io/adv-usage#custom-reports)

## License

MIT License

This project was donated to the OWASP Foundation in August 2023 by AppThreat Ltd.

## Funding

This project is funded through [NGI Zero Core](https://nlnet.nl/core), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/OWASP-dep-scan).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/core)
