# Provenance: how the data is produced

## Advisory intake

Safety has operated a vulnerability database for Python since 2016 and now
aggregates advisories continuously across five ecosystems from CVE/NVD, GitHub
Security Advisories, ecosystem trackers, and Safety's own research.
Every advisory gets a stable `safety_id`; CVE and GHSA identifiers are
preserved for cross-referencing.

## Vulnerable-symbol labeling

For each advisory, we identify the specific functions, methods, fields, and
other definitions that contain the vulnerability — not just the affected
package range. Security analysts examine the advisory, the upstream fix
(patch commits, security releases), and the package source, and record:

- the vulnerable source file (upstream-repo-relative path),
- each vulnerable definition: type, name, full signature, enclosing
  class/namespace, and fully-qualified symbol path,
- for Go, the receiver form (pointer vs. value), which method-set resolution
  requires,
- for native bindings (e.g. TensorFlow Python ops), the `origins` chain to the
  C++ implementation.

## Per-symbol version classification

Each labeled symbol carries its own enumerated list of affected versions,
computed by checking for the symbol's presence across every published release
of the package. This is why the per-symbol lists are strictly narrower than
the advisory's package-level range in 66% of records: advisories routinely
claim ranges that predate the vulnerable code's introduction (see the PyYAML
case study — advisory says 38 versions, the vulnerable symbol exists in 9).

Version lists are always concrete enumerated strings resolved against the
registry's actual published releases — never ranges — so consumers inherit no
ecosystem-specific version-semantics parsing.

## Human review

Findings are verified by security analysts. On a reviewed finding, the
analyst has checked the full record:

- the vulnerable-symbol identification (files, definitions, signatures),
- the per-symbol affected-version lists,
- the advisory mapping (CVE/GHSA identifiers), and
- the package coordinates.

## Callgraph generation

All callgraphs are produced by Safety's proprietary generators — static
analysis only; package code is never executed.

| Language | Input analyzed | Approach |
|---|---|---|
| Python | package source (sdist/wheel contents) | Proprietary static analyzer; resolves Python's dynamic dispatch constructs — decorators, metaclass registration, MRO dispatch, comprehensions, async/await, aliased imports. Symbol names match what consuming code imports. |
| Java | the published JAR (bytecode) | Proprietary bytecode analysis, producing the complete API-to-internal call structure of the artifact. |
| Go | module source at each tagged version | Proprietary whole-program static analysis. |
| C/C++ | native extension source of PyPI packages | Static analysis of the extension source, linking Python bindings to native kernels. |

Output is a uniform schema across languages (GraphSON 3.0, `FUNCTION`
vertices / `CALLS` edges — see [SCHEMAS.md](SCHEMAS.md)), with
ecosystem-native symbol naming that string-matches the findings feed.

Generators are validated against public benchmark suites and an in-house
corpus of 285 runnable applications with hand-written ground truth; accuracy
numbers, methodology, and baselines are in [BENCHMARKS.md](BENCHMARKS.md).
Generator releases are regression-gated against these baselines before they
ship, and the corpus is regenerated when the generators materially improve.

## Freshness

Findings are exported nightly and advisory metadata is updated continuously;
callgraphs for newly published releases are generated continuously, and the
full corpus is regenerated when the generators materially improve. See
[COVERAGE.md](COVERAGE.md#refresh-cadence).
