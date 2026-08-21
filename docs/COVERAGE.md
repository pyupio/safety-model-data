# Coverage, scale, and refresh cadence

Numbers below are from the 2026-08-20 snapshot. The corpus grows daily; treat
these as a floor, not a spec.

## Reachability findings

One record per (package × advisory), each carrying vulnerable symbols with
per-symbol enumerated version lists.

| Ecosystem | Records | Packages | Unique CVEs | Unique GHSAs | Vulnerable symbols labeled |
|---|---:|---:|---:|---:|---:|
| Python (PyPI) | 4,641 | 955 | 2,599 | 2,730 | 21,510 |
| Java (Maven) | 3,007 | 1,303 | 2,412 | 2,457 | 7,201 |
| JavaScript/TypeScript (npm) | 2,639 | 1,084 | 2,176 | 2,564 | 5,510 |
| Go (incl. stdlib) | 2,443 | 839 | 2,038 | 2,030 | 6,505 |
| C# (NuGet) | 1,102 | 263 | 341 | 388 | 3,430 |
| **Total** | **13,832** | **4,444** | **9,556** | **10,158** | **44,156** |

- **Version assertions:** 1.55M package-level and 2.29M symbol-level concrete
  version strings — all enumerated, zero ranges.
- **Symbol-level refinement:** in 66% of records the per-symbol version set is
  strictly narrower than the advisory's package-level set.
- **Temporal range:** advisories from 2002 through the snapshot date, skewed
  recent (2022–2026 account for ~65% of records). New CVEs are covered as they
  are published — the newest record in this snapshot is 2 days old.
- **Cross-language labels:** ~1,700 Python records trace vulnerable bindings
  to their native C++ implementations (`origins` blocks; TensorFlow family).
- **Go stdlib:** 163 CVEs in the Go standard library itself.

## Per-release callgraphs

One complete static callgraph per (package × published version), for packages
in the vulnerability corpus.

| Language | Callgraphs | Packages | Mean versions/pkg | Median | Compressed size |
|---|---:|---:|---:|---:|---:|
| Python (PyPI) | 236,046 | 4,303 | 55 | 18 | 48 GB |
| Java (Maven) | 197,098 | 2,746 | 72 | 22 | 252 GB |
| Go | 125,795 | 1,265 | 99 | 44 | 107 GB |
| C++ (native code of PyPI packages) | 429 | 10 | 43 | 23 | 2.5 GB |
| **Total** | **559,368** | **~8,300 coordinates** | | | **~409 GB** |

- Compression is zstd at roughly 20–35×; the decompressed corpus is on the
  order of 10 TB of graph JSON.
- Coverage is **longitudinal by design**: every published release of a covered
  package gets a graph, not just the latest. Deep histories include
  packages with 1,000–3,200 released versions each (e.g. `awscli` at 2,457
  releases on PyPI; `github.com/gravitational/teleport` at 3,211 tagged
  versions). This is what enables before/after-fix pairs and
  vulnerability-lifecycle sequences at scale.
- JavaScript and C# callgraphs are not yet produced (findings for those
  ecosystems are; the callgraph generators currently cover Python, Java, Go,
  and C/C++ native extensions).

## Advisory metadata feed

Severity (CVSS v2/v3/v4 with vectors and source attribution), CWE,
descriptions, and references, plus exploitability fields (EPSS
score/percentile, CISA KEV, PoC references) where populated — joinable to
findings on `safety_id`. Available for all five ecosystems — ~49,600
advisories in total:

| Ecosystem | Advisories |
|---|---:|
| Python (PyPI) | 21,732 |
| Java (Maven) | 9,201 |
| JavaScript (npm) | 7,442 |
| Go | 5,657 |
| .NET (NuGet) | 5,603 |

## Refresh cadence

- **Findings:** exported **nightly** (04:00 UTC), with an unbroken daily
  history.
- **Callgraphs:** graphs for newly published package releases are generated
  continuously — the corpus has new objects every day up to the snapshot
  date. The full corpus is regenerated when the generators materially improve;
  the current corpus was fully written within the five weeks preceding the
  snapshot.
- **Advisory metadata:** updated continuously as advisories are published and
  revised.
