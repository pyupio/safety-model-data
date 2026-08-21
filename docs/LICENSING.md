# Rights, restrictions, and commercial structure

## What Safety owns and can license

The datasets are Safety's original, independently produced analysis:

- **Findings** (vulnerable-symbol labels, per-symbol version classifications,
  review statuses) are produced by Safety's analysts and pipelines. They are
  factual annotations *about* open-source code — no third-party source code is
  reproduced in the records.
- **Callgraphs** are machine-generated structural metadata derived by Safety's
  proprietary static analyzers from publicly published packages. They contain
  symbol names and file paths, not source code bodies.
- **Advisory metadata** aggregates public advisory information (CVE, GHSA,
  CVSS, EPSS, KEV) under their respective public-source terms, enriched and
  normalized by Safety.

Safety has been building and commercially licensing its vulnerability database
since 2016; the same database powers Safety's commercial products and existing
data partnerships.

## Commercial structure

Two steps, kept deliberately simple:

1. **Evaluation** — a time-boxed grant of the full corpus (S3 access or
   snapshot export) for internal evaluation and data-quality assessment, under
   NDA. Includes the complete benchmark reports and the integration-test
   corpus behind the accuracy numbers.
2. **License** — a commercial license scoped to your intended uses —
   evaluation harnesses, published benchmarks, model training, RL environments
   and graders, or a combination — as a one-time snapshot or an annual
   subscription with the nightly-refreshed feed. Terms are negotiated per
   partner; we're flexible on scope and delivery.

Model weights trained on the data are yours — Safety claims no rights over
models.

## Restrictions

- **Don't replicate the database.** The data may not be used to reproduce or
  seed a competing vulnerability database. Everything built on top of it is
  yours — models, benchmarks, evals, and security products (including SCA
  tools) are all fair game.
- **Attribution** ("vulnerability data by Safety") in published benchmarks and
  research using the data.

Distribution rights are defined by the license scope: data platforms can
license the right to distribute the data onward to model providers.
