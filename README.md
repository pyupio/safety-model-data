# Safety — vulnerability reachability data for AI models

Safety builds security data for software supply chains: we've operated a
commercial vulnerability database since 2016, and it powers our own products
today. This repository is a technical introduction to the datasets we license
to AI labs and data platforms — with real samples, full schemas, measured
accuracy numbers, and the methodology behind them.

## Three terms, if you're new to this domain

**Advisory (CVE).** The public record of a vulnerability in an open-source
package — "package X, versions 2.0 through 2.14.1, can be exploited to run
attacker code." Advisories are indispensable but coarse: they name a package
and a version range, not the code.

**Reachability.** Making an advisory precise enough to act on. The first step
is identifying, for each advisory, the exact functions where the
vulnerability lives — the **vulnerable symbols** — and the exact releases
that contain them. That is what our reachability findings are. Once the
vulnerable function is known, "am I affected?" becomes a concrete question:
does any chain of calls connect the code you actually run to that function?
No chain, and the advisory is noise for you; a chain, and it is a real,
potentially exploitable exposure. Most "vulnerable dependency" alerts fail
this test — which is why function-level reachability, rather than
package-version matching, is what separates signal from noise.

**Callgraph.** The structure that answers the chain-of-calls question: a
directed graph of a program's functions — one vertex per function, one edge
per call (`A → B` means `A`'s body can invoke `B`). Ours are built by static
analysis (the code is parsed, never executed), which makes it tractable to
build one for every published release of a package. The hard part is getting
the edges right: dynamic dispatch — Python decorators and metaclasses, Java
virtual calls, Go interfaces — makes "which function does this call actually
land on?" a genuinely difficult inference problem, and it is exactly what our
generators are benchmarked on.

The datasets below are these three ideas industrialized: every advisory
mapped to its vulnerable symbols and the exact releases containing them, plus
the callgraph of every release so reachability can be computed — or learned.

## The datasets

Three feeds, designed to join:

| Dataset | Unit | Scale (Aug 2026) | What it gives a model |
|---|---|---|---|
| **Reachability findings** | one record per (package × advisory) | 13,832 records · 9,556 CVEs · 4,444 packages · 44,156 labeled symbols · 5 ecosystems | *Which functions are the vulnerability*, with signatures and fully-qualified names, and the exact releases each symbol is vulnerable in |
| **Per-release callgraphs** | one graph per (package × published version) | 559,368 graphs · ~8,300 packages · Python, Java, Go, C++ | The complete static call structure of every release — how any symbol is reached from the public API |
| **Advisory metadata** | one record per advisory | ~49,600 advisories · 5 ecosystems · CVSS v2/v3/v4, CWE, references, EPSS/KEV where populated | Severity and exploitability context, joined by ID |

Findings join advisory metadata on `safety_id`; findings join callgraphs on
(package, version, fully-qualified symbol name) — **string-exact, no fuzzy
matching**. Every pairing in [`samples/`](samples/) demonstrates that join on
real data.

## What makes it different

**Per-symbol version truth, not advisory ranges.** Public advisories say
"PyYAML < 5.3.1 is vulnerable." Our finding says the vulnerable method is
`FullConstructor.set_python_instance_state`, and that it exists in exactly 9
of the 38 versions the advisory covers — because the vulnerable class didn't
exist before 5.1. The per-symbol list is strictly narrower than the advisory
range in 66% of the corpus. That's the difference between a model learning
"old versions bad" and learning *which code is dangerous and when it entered
the codebase*.

**Longitudinal by construction.** Callgraphs cover every published release —
median 18–44 versions per package, deep histories into the thousands — so
vulnerable/fixed release pairs, API-evolution sequences, and
vulnerability-lifecycle traces come built in.

**Measured accuracy, precision-first.** The callgraph generators are
benchmarked against public suites (PyCG, Jarvis) and execution-trace ground
truth: **99.96% precision / 84% recall** for Python, **99.8% precision / 99.1%
recall** for Go, with every known limitation documented and reproducible.
We bias to precision deliberately: a false edge teaches a model a wrong fact;
a missing edge only costs a sample. Full methodology, baselines, and
per-project results: [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

**Human-reviewed.** Findings are verified by security analysts — the symbol
identification, the per-symbol version lists, the advisory mapping, and the
package coordinates are all checked before a record is marked reviewed.

**Fresh daily.** Findings export nightly and advisory metadata updates
continuously; new CVEs appear within days of publication. For eval builders this matters twice: benchmarks stay current,
and post-cutoff CVEs are contamination-free test material by construction.

**Cross-language depth.** Where the vulnerable code is native (TensorFlow
C++ kernels behind Python ops), findings carry the binding-to-implementation
chain, and native callgraphs exist for the C++ side.

## What labs use it for

- **Vulnerability localization** — advisory text → vulnerable symbol, at
  44k-symbol scale with signatures. Supervision for security code review.
- **Reachability reasoning** — "is this app affected?" requires tracing calls
  into a dependency's vulnerable symbol. The callgraphs provide labels
  for training and graders for RL: reward = did the model's claimed path exist.
- **Static-analysis distillation** — 559k graphs of 99.9%-precision call
  edges, including the hard cases (Python dynamic dispatch, Go interface
  dispatch, Java virtual calls), to teach models call resolution directly.
- **Contrastive pairs** — same package, adjacent releases, one vulnerable and
  one fixed, at scale; for patch understanding and diff-based reasoning.
- **Contamination-resistant evals** — the nightly feed yields test sets built
  from CVEs published after any model's training cutoff.

## Answers to the questions labs ask us

1. **"Send a sample and a schema."** → [`samples/`](samples/) has 13 verbatim
   finding records (Log4Shell, Spring4Shell, Struts/Equifax, lodash, gin, Go
   stdlib, cross-language TensorFlow, …), 6 full callgraphs, and an advisory
   record — plus [`samples/case-studies/`](samples/case-studies/) walking
   through how they compose. Complete data dictionary:
   [docs/SCHEMAS.md](docs/SCHEMAS.md). Nothing needed redaction: the feeds
   contain no customer data or PII by construction; the samples are
   byte-identical to production records.
2. **"Coverage, scale, refresh cadence."** →
   [docs/COVERAGE.md](docs/COVERAGE.md): per-ecosystem tables for both
   datasets, version-depth distributions, nightly refresh evidence.
3. **"Provenance, labeling process, human review."** →
   [docs/PROVENANCE.md](docs/PROVENANCE.md): advisory intake, how
   symbol labels and per-symbol version lists are produced, what reviewers
   check, and how the callgraphs are generated per language.
4. **"The benchmark behind the accuracy claim."** →
   [docs/BENCHMARKS.md](docs/BENCHMARKS.md): public-suite results with
   corrected ground truths, execution-trace methodology, and a 285-app
   end-to-end validation corpus with hand-written ground truth.
5. **"Rights and commercial structure."** →
   [docs/LICENSING.md](docs/LICENSING.md): what we own, how evaluation and
   licensing work (evaluation grant under NDA, then a license scoped to your
   uses — benchmarks, training, RL), and the restrictions that apply.

## See it work

```console
$ pip install zstandard   # only needed to read .zst directly

# The Log4Shell attack path, from the callgraph of log4j-core 2.14.1:
$ python3 scripts/callgraph_paths.py \
    samples/callgraphs/java/org.apache.logging.log4j__log4j-core-2.14.1-java.json.zst \
    'JndiManager\.lookup$'

== org.apache.logging.log4j.core.net.JndiManager.lookup
   ...StrSubstitutor.resolveVariable -> ...Interpolator.lookup
      -> ...JndiLookup.lookup -> ...JndiManager.lookup
```

`JndiManager.lookup` is one of the four symbols named by our CVE-2021-44228
finding record two directories away. Start with
[samples/case-studies/log4shell.md](samples/case-studies/log4shell.md).

## Repository layout

```
├── samples/
│   ├── findings/         13 verbatim finding records across all 5 ecosystems
│   ├── callgraphs/       6 full per-release callgraphs (zstd GraphSON)
│   ├── vulnerabilities/  advisory-metadata record (joins on safety_id)
│   └── case-studies/     walkthroughs pairing findings + callgraphs
├── docs/
│   ├── SCHEMAS.md        data dictionary for all three feeds
│   ├── COVERAGE.md       scale, coverage, refresh cadence
│   ├── PROVENANCE.md     how labels and graphs are produced; human review
│   ├── BENCHMARKS.md     accuracy methodology, baselines, results
│   └── LICENSING.md      rights and commercial structure
├── scripts/
│   └── callgraph_paths.py  trace call paths to any symbol in any graph
└── benchmarks/           (reserved) runnable benchmarks for evaluators
```

## Evaluating the data

Full-corpus evaluation access (S3 grant or snapshot export), the complete
benchmark reports, and the integration-test corpus are available under NDA —
see [docs/LICENSING.md](docs/LICENSING.md). The `benchmarks/` directory will
grow runnable benchmarks so evaluators can score the data themselves.

*Safety Cybersecurity — https://getsafety.com*
