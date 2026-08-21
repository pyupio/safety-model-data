# Callgraph accuracy: methodology, baselines, and results

This page documents how we measure the accuracy of the callgraphs we sell, what
we measure against, and the current results. Two independent validation layers
exist:

1. **Academic benchmark suites** (PyCG, Jarvis, purpose-built fixtures,
   execution-trace ground truth) that score the callgraph generators themselves.
2. **An integration-test corpus** of 285 hand-written, runnable applications
   that scores the *end-to-end product*: does the callgraph of a real app join
   correctly against the per-release library callgraphs, including at the
   specific symbols named by CVEs?

## The two accuracy metrics

- **Precision (soundness):** the share of edges in the generated callgraph that
  represent true, valid calls. Low precision "hallucinates" execution paths,
  linking safe code to vulnerable symbols.
- **Recall (completeness):** the share of actual calls in the codebase captured
  by the graph. Low recall creates blind spots — a vulnerable symbol is
  reachable, but the path is missing from the graph.

These are in tension: an over-approximating analysis buys recall with spurious
edges; a conservative one buys precision with missed calls. **We prioritize
precision.** When a consumer of this data sees a path from code to a vulnerable
symbol, that path should actually exist. That design choice is what makes the
graphs usable as training labels: false edges teach a model wrong facts, while
missing edges merely reduce sample count.

## Python

**Generator:** proprietary static analysis operating directly on package
source (no execution, no imports).

**Benchmarks used:**

- [PyCG micro-benchmarks](https://arxiv.org/abs/2103.00587) — the standard
  suite of isolated Python language constructs.
- [Jarvis macro-benchmarks](https://arxiv.org/abs/2305.05949) — six real-world
  open-source codebases with ground-truth callgraphs.

**Baseline adjustments (all documented, applied symmetrically):**

- The original Jarvis ground truths were audited and corrected: legitimate call
  edges missing from the published datasets were added (e.g. `__setattr__`
  dispatch, property access, comprehension-internal calls), and incorrect edges
  removed. The full add/remove list per repository is available on request.
- Built-in function calls were filtered from both sides.
- External (out-of-package) calls, which our generator resolves but the
  reference ground truths do not track, were excluded from metric computation
  so expanded capability is not counted as false positives.

**Macro-benchmark results (Jarvis suite, corrected ground truth):**

| Codebase | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| bpytop | 100% | 75.86% | 86.27% | 264 | 0 | 84 |
| furl | 100% | 94.02% | 96.92% | 283 | 0 | 18 |
| rich-cli | 100% | 82.86% | 90.63% | 29 | 0 | 6 |
| sqlparse | 99.74% | 75.63% | 86.03% | 388 | 1 | 125* |
| sshtunnel | 100% | 85.05% | 91.92% | 91 | 0 | 16 |
| TextRank4ZH | 100% | 91.49% | 95.56% | 43 | 0 | 4 |
| **Average** | **99.96%** | **84.15%** | **91.22%** | | | |

\* a large share of sqlparse's false negatives are dynamic calls through
`getattr`, which we deliberately do not resolve (see limitations).

**Micro-benchmark coverage (PyCG suite, 119 constructs):** 89 supported
(74.8%), 13 pending (in active development), 16 missing (highly dynamic
features), 1 deliberately excluded.

**Known limitations (deliberate soundness trade-offs):** `eval`/`exec`/
`getattr` runtime-evaluated dispatch, `**kwargs` chaining across call
boundaries, complex lambda chains, and base-class dispatch to child overrides
are excluded or partially supported to avoid graph hallucination. A full
supported-feature list (functions/arguments, OOP and MRO, decorators, imports,
data structures, generators, async/await, external dependencies) is available
in the detailed benchmark report.

## Go

**Generator:** proprietary whole-program static analysis over the module
source.

**Benchmarks used:**

- **33 purpose-built micro-benchmark fixtures** covering Go dispatch constructs
  (interface dispatch, type assertions/switches, embedded structs, method
  values vs. expressions, closures, goroutines, defer/panic/recover, package
  init, channels, generics, reflection, unsafe pointers). Suite design modeled
  on public Java callgraph test suites.
- **Profiler benches (macro):** three real-world projects — gin, chi, gjson —
  with ground truth assembled from Go execution traces (`go test -trace`)
  plus a systematic 7-phase manual curation process (static-edge verification,
  dynamic-dispatch enumeration via full method-set search, subtractive
  reachability filtering, pointer-receiver disambiguation, and per-site
  resolution of function values, defers, goroutines, and reflection calls).

**Micro-benchmark results:** 29/33 fixtures pass, 4 partial, 0 failures.
130 of 139 required edges recovered (93.5% recall) with **100% precision** (all
19 forbidden-edge constraints satisfied). Each partial case maps to a
documented static-analysis limitation (channel type propagation, reflection
instantiation, unsafe pointer round-trips) and none produces a false edge.

**Macro-benchmark results:**

| Project | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| gin | 100.0% | 99.6% | 99.8% | 1783 | 0 | 8 |
| chi | 99.4% | 99.4% | 99.4% | 900 | 5 | 5 |
| gjson | 100.0% | 98.3% | 99.1% | 290 | 0 | 5 |
| **Average** | **99.8%** | **99.1%** | **99.4%** | | | |

**Known limitations:** certain highly dynamic constructs — interface values
passed across channels, reflection with runtime-constructed method names, and
some `unsafe.Pointer` cast patterns — can drop edges. Each case is documented
with a reproducing fixture in the detailed report, and none produces a false
edge.

## Java

**Generator:** proprietary bytecode analysis of the published artifact (JAR);
per-release library graphs describe the complete API-to-internal-call
structure of the artifact.

Java accuracy is currently validated through the integration-test corpus below
(99.4% cross-graph symbol join, ~104% recall against hand-written ground
truth). A dedicated Java benchmark report against public suites is in progress.

## End-to-end validation: the integration-test corpus

Benchmark suites validate generators in isolation. The integration-test corpus
validates what a buyer actually consumes: application callgraphs joined against
per-release library callgraphs at CVE-relevant symbols.

**Corpus construction.** 285 small, runnable, realistic applications (136
Python, 83 Maven, 66 Go), each pinning a version of a top-100 vulnerable
package that is *still affected* by a named CVE. Each app deliberately
exercises the package's common API **plus its hard-to-analyze constructs**
(decorators, metaclass registration, dependency injection, builder chains,
interface/virtual dispatch, callbacks the library invokes, reflection) —
precisely where callgraph construction tends to miss edges. Every app runs to
completion and exits 0. Each ships a hand-written `METHODS.md` ground truth:
one row per call into the target package with `file:line`, with the
CVE-relevant sink row explicitly marked.

**Results (current baseline):**

| Metric | Python | Java (Maven) | Go |
|---|---:|---:|---:|
| Examples scored | 124 | 75 | 64 |
| Ground-truth call rows | 1,214 | 1,242 | 579 |
| Captured symbols | 1,043 (~86%) | 1,297 (~104%*) | 1,032 (~178%*) |
| Cross-graph join: entrypoints resolved in library graph | 846/1,043 confirmed present | 1,289/1,297 (99.4%) | 1,004/1,007 (99.7%) |

\* over 100% reflects additional true edges beyond the hand-written rows
(Java: inherited/overloaded members; Go: conservative fan-out at interface
dispatch sites — extra candidate edges, not extra ground truth).

## Reproducing these results

The integration-test corpus (apps, ground truth, scoring scripts, baselines) is
a private repository that we make available to evaluators under NDA. The
`benchmarks/` directory of this repository is reserved for a self-serve version:
runnable benchmarks an evaluator can execute against sample data. Ask us for
early access.
