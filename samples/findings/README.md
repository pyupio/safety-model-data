# Findings samples

Thirteen records from the reachability findings feed, copied verbatim — no
fields were removed or altered. The feed contains no customer data, telemetry,
or personal information by construction, so nothing required redaction; these
are byte-identical to production records. (Directory names here replace the `:`
of Maven coordinates with `__` for filesystem portability; the feed itself uses
`groupId:artifactId`.)

Each record identifies, for one (package, advisory) pair: the vulnerable source
files, the exact vulnerable symbols within them (with signatures and
fully-qualified names), and — per symbol — the concrete list of published
versions in which that symbol is present and vulnerable.

## What's here

| Record | Ecosystem | CVE | Why it's included |
|---|---|---|---|
| `java/.../org.apache.logging.log4j__log4j-core/SFTY-20211210-26603.json` | Maven | CVE-2021-44228 (Log4Shell) | The canonical showcase. 4 vulnerable symbols; advisory covers 52 versions but each symbol's own list is narrower (46/45/46) — per-symbol refinement on the most famous CVE of the decade. Pairs with the log4j-core 2.14.1 callgraph in [`../callgraphs/`](../callgraphs/) and the walkthrough in [`../case-studies/`](../case-studies/). |
| `java/.../org.springframework__spring-beans/SFTY-20220331-78173.json` | Maven | CVE-2022-22965 (Spring4Shell) | 251 affected versions enumerated; the two labeled symbols have dramatically different exposure windows (158 vs. 18 versions) — the starkest illustration that symbol-level ≠ package-level. |
| `java/.../org.apache.struts__struts2-core/SFTY-20181018-94182.json` | Maven | CVE-2017-5638 (the Equifax Struts RCE) | Multi-file finding: 4 symbols across 4 source files in the multipart/file-upload paths, each with its own version subset. |
| `python/pypi/requests/SFTY-20240520-16246.json` | PyPI | CVE-2024-35195 | Clean, small record for the most-downloaded Python package. Pairs with the requests 2.31.0 callgraph. |
| `python/pypi/pyyaml/SFTY-20200324-56526.json` | PyPI | CVE-2020-1747 | The advisory says 38 versions back to 3.01; the vulnerable symbol (`FullConstructor.set_python_instance_state`) only exists in 9 of them — `FullConstructor` was introduced in 5.1, and the per-symbol list knows it. Pairs with the pyyaml 5.3 callgraph. |
| `python/pypi/tensorflow-aarch64/SFTY-20220916-34369.json` | PyPI | CVE-2022-35935 | **Cross-language labeling.** The vulnerable Python binding (`gen_math_ops.sobol_sample`) carries an `origins` block tracing it to the native C++ kernel (`SobolSampleOp::Compute` in `sobol_op.cc`). We label the vulnerability where the developer sees it *and* where the code actually lives. |
| `javascript/npm/lodash/SFTY-20210506-90648.json` | npm | CVE-2021-23337 | `lodash.template` command injection; 113 affected versions enumerated. |
| `go/go/github.com/gin-gonic/gin/SFTY-20230512-40104.json` | Go | CVE-2023-29401 | Go method syntax (`(*gin.Context).FileAttachment`) with receiver-type metadata. Pairs with the gin 1.9.0 callgraph. |
| `go/go/github.com/golang-jwt/jwt{,/v4,/v5}/SFTY-20250321-*.json` | Go | CVE-2025-30204 | **One CVE, three records** — the same vulnerable symbol (`Parser.ParseUnverified`) tracked independently across the v3/v4/v5 module lines with per-line version lists (34/26/6 versions). Pairs with the jwt 3.2.2 callgraph. |
| `go/go/stdlib/SFTY-20210414-15758.json` | Go | CVE-2021-27919 | Coverage extends to the Go standard library itself (163 stdlib CVEs in the feed). |
| `csharp/nuget/newtonsoft.json/SFTY-20220622-76887.json` | NuGet | CVE-2024-21907 | C# example on the most-downloaded NuGet package; labels both the vulnerable type and the guarding `MaxDepth` property. |

`../vulnerabilities/` holds the Log4Shell record from the companion
advisory-metadata feed — same `safety_id`, carrying CVSS v2/v3/v4 vectors from
multiple sources, CWE classifications, description, and references, plus
exploitability fields (EPSS score/percentile, CISA KEV, proof-of-concept
references) where populated. The two feeds join on `safety_id`.

## Reading a record

```json
{
  "safety_id": "SFTY-20200324-56526",        // primary key, joins to the advisory feed
  "ghsa_id": "GHSA-6757-jp84-gxfx",          // GitHub advisory, when one exists
  "cve_id": "CVE-2020-1747",                 // CVE, when one is assigned
  "package_name": "pyyaml",                  // canonical registry name
  "review_status": "REVIEWED",               // human-verified
  "vulnerable_versions": [                   // package-level affected versions —
    {"source": "PYPI", "versions": ["3.01", "3.1", "...", "5.3b1", "5.3"]}
  ],                                         //   fully enumerated (38 here), never ranges
  "files": [
    {
      "file": "yaml/constructor.py",         // upstream-repo-relative path
      "language": "PYTHON",
      "definitions": [
        {
          "symbol_type": "METHOD",           // FUNCTION | METHOD | FIELD | GLOBAL_VARIABLE | BLOCK | PROPERTY
          "symbol_name": "set_python_instance_state",
          "signature": "set_python_instance_state(self, instance, state)",
          "fully_qualified_parent_name": "FullConstructor",
          "fully_qualified_symbol_name": "yaml.constructor.FullConstructor.set_python_instance_state",
          "vulnerable_versions": [           // per-SYMBOL affected versions — only 9 here:
            {"source": "PYPI", "versions": ["5.1b5", "...", "5.3"]}
          ]                                  //   FullConstructor didn't exist before 5.1, and the
                                             //   data knows it. Narrower than the package-level
                                             //   list in 66% of records.
        }
      ]
    }
  ]
}
```

Points worth noticing:

- **Versions are enumerated, never ranges.** Across all 3.8M version assertions
  in the feed there is not a single `>=`, `<`, `~`, `^`, or `*`. Consumers
  never parse PEP 440 vs. semver vs. Maven vs. NuGet vs. Go pseudo-version
  range semantics — membership is a string comparison.
- **The version list exists twice**: once at package level (the advisory claim)
  and once per symbol (our analysis of which releases actually contain the
  vulnerable code). They differ in 66% of records.
- **Symbol naming is ecosystem-native** and string-identical to the `NAME`
  vertices in the callgraph dataset, so the two datasets join without fuzzy
  matching (see the case studies).
- `fully_qualified_symbol_name` is populated for Python and Go; for Java, C#,
  and JavaScript/TypeScript, join on `fully_qualified_parent_name` +
  `symbol_name` + `signature`.
- `unclassified_versions` is a reserved field, currently always empty.
