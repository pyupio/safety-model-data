# Benchmarks (coming soon)

This directory is reserved for runnable benchmarks that let an evaluator score
the dataset directly, rather than taking our numbers on faith. Planned:

- **Callgraph accuracy** — score sampled per-release callgraphs against
  held-out ground truth (micro-fixtures plus hand-curated real-world edges),
  reproducing the precision/recall numbers in
  [docs/BENCHMARKS.md](../docs/BENCHMARKS.md).
- **Vulnerable-symbol identification** — given a CVE advisory and package
  source, can a model identify the vulnerable functions? Our findings provide
  the labels.
- **Reachability QA** — given an application and a vulnerable dependency
  version, determine whether the vulnerable symbol is reachable; scored against
  our integration-test corpus of runnable applications with hand-written
  ground truth.

Until this lands, see [docs/BENCHMARKS.md](../docs/BENCHMARKS.md) for the
methodology and current results, and [samples/](../samples/) for data you can
inspect today.
