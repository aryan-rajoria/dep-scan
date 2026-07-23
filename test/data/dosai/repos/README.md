# dosai reachability fixture repos

Hermetic .NET fixture projects for `test/test_dosai_integration.py`. Each is a
minimal net10.0 console app that references `Newtonsoft.Json 13.0.3`:

- **`reachable-app`** — reaches Newtonsoft via a recognized deserialization sink:
  a method-parameter `TextReader` source (`input.ReadLine()`) flows into the
  fully-qualified `Newtonsoft.Json.JsonConvert.DeserializeObject<T>(line)` sink.
  dosai flags `pkg:nuget/Newtonsoft.Json@13.0.3` as `Reachable` with
  `ReachabilityKind=DataFlowNode`, `Confidence=High`.
- **`unreachable-app`** — references the same package in the `.csproj` but never
  calls any Newtonsoft API (control). dosai must NOT flag a call/dataflow
  reachability for it.

## Why `bin/` and `obj/` are committed (force-added past .gitignore)

dosai performs static source/assembly inspection (no execution, no `dotnet
build`), but it resolves method symbols via Roslyn and attributes purls from the
restored/built dependency manifests. For hermetic, offline tests (no
`dotnet restore` in-test) each app commits the minimal set dosai reads:

- `Program.cs`, `*.csproj` — source + package reference.
- `obj/project.assets.json` — restore state (package → version mapping).
- `bin/Debug/net10.0/<app>.deps.json` — runtime dependency manifest dosai reads
  for purl attribution.
- `bin/Debug/net10.0/<app>.dll`, `<app>.pdb` — the app's own compiled assembly
  (dosai resolves the sink call against it; the portable PDB provides source
  locations).
- `bin/Debug/net10.0/Newtonsoft.Json.dll` — the referenced package assembly
  dosai binds the deserialization sink symbol against.

To rebuild from source (e.g. after editing `Program.cs`), run inside each app:

```bash
dotnet restore && dotnet build
```

then re-trim to the committed set (drop the native apphost, `runtimeconfig.json`,
and `obj/` build caches — keep only `obj/project.assets.json`).

## dosai recognition notes

dosai's default pattern packs recognize a **fully-qualified** deserialization
sink call (`Newtonsoft.Json.JsonConvert.DeserializeObject` /
`System.Text.Json.JsonSerializer.Deserialize`) seeded by a **method-parameter**
source (`input`, `request`, `[FromBody]`, or `Console.ReadLine`). An unqualified
call relying on a `using` directive, or a local-variable source like
`var x = Console.ReadLine()` assigned straight to an unqualified `Deserialize`,
does not reliably bind the sink symbol in a minimal project. These are dosai
analysis-content details; the dep-scan pipeline itself is verified independently
via the committed native samples under
`packages/analysis-lib/tests/data/dosai/`.
