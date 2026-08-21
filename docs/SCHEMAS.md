# Schemas & data dictionary

Three deliverables, designed to join on shared keys:

1. **Reachability findings** — per (package, advisory): the vulnerable symbols
   and the exact versions containing them.
2. **Per-release callgraphs** — per (package, version): the complete static
   callgraph.
3. **Advisory metadata** — per advisory: severity, CWE, EPSS, KEV,
   references.

Join keys: findings ↔ advisory metadata on `safety_id`; findings ↔ callgraphs
on (package, version, fully-qualified symbol name). Symbol names are
string-identical across the two datasets — no fuzzy matching required.

---

## 1. Reachability findings

**Shape:** one JSON document per (package × advisory).
**Path convention:** `{language}/{registry}/{package}/{SAFETY_ID}.json`, e.g.
`java/maven/org.apache.logging.log4j:log4j-core/SFTY-20211210-26603.json`.
**Ecosystems:** `python/pypi`, `java/maven`, `javascript/npm`, `go/go`
(including Go stdlib), `csharp/nuget`.

### Root object (all fields always present)

| Field | Type | Description |
|---|---|---|
| `safety_id` | string | Primary key, `SFTY-YYYYMMDD-NNNNN`; the date is the advisory's Safety publication date. Joins to the advisory-metadata feed. |
| `ghsa_id` | string \| null | GitHub Security Advisory ID, when one exists. |
| `cve_id` | string \| null | CVE ID, when one is assigned. |
| `package_name` | string | Canonical registry package name. Authoritative for package identity (prefer over the file path). |
| `review_status` | enum | `REVIEWED` (human-verified) or `AUTOMATED`. |
| `vulnerable_versions` | VersionBlock[] | Package-level affected versions (the advisory-level claim). |
| `files` | FileEntry[] | The vulnerable-symbol payload. |

### VersionBlock

| Field | Type | Description |
|---|---|---|
| `source` | enum | `PYPI` \| `NPM` \| `MAVEN` \| `NUGET` \| `GIT` (Go). |
| `versions` | string[] | **Fully enumerated concrete version strings — never ranges.** No consumer-side parsing of PEP 440 / semver / Maven / NuGet / Go pseudo-version semantics. |

### FileEntry

| Field | Type | Description |
|---|---|---|
| `file` | string | Source path relative to the upstream repository, e.g. `log4j-core/src/main/java/org/apache/logging/log4j/core/net/JndiManager.java`. |
| `language` | enum | `PYTHON` \| `JAVA` \| `GO` \| `CSHARP` \| `JAVASCRIPT` \| `TYPESCRIPT`. |
| `definitions` | Definition[] | The vulnerable symbols in this file. |

### Definition

| Field | Type | Presence | Description |
|---|---|---|---|
| `symbol_type` | enum | always | `FUNCTION` (53%) \| `METHOD` (43%) \| `FIELD` \| `GLOBAL_VARIABLE` \| `BLOCK` \| `PROPERTY`. |
| `symbol_name` | string | always | Bare identifier. |
| `signature` | string \| null | nullable | Full parameter list, e.g. `resolve_redirects(self, resp, req, stream=False, ...)`. |
| `fully_qualified_parent_name` | string \| null | nullable | Enclosing class / namespace / module; null for free functions. |
| `fully_qualified_symbol_name` | string \| null | 100% for Python & Go | Canonical resolvable symbol path — Python dotted (`flask.sessions.SecureCookieSessionInterface.get_signing_serializer`), Go dual-form (`(github.com/artdarek/go-unzip.Unzip).Extract`). For Java/C#/JS, join on parent + name + signature. |
| `receiver_type` | enum | Go methods only | `POINTER` \| `VALUE` — required for correct Go method-set resolution. |
| `vulnerable_versions` | VersionBlock[] | always | **Per-symbol** affected versions. Strictly narrower than the package-level list in 66% of records — the versions in which *this symbol* exists and is vulnerable, not the advisory's range. |
| `unclassified_versions` | VersionBlock[] | always | Reserved; currently always empty. |
| `origins` | OriginEntry[] | cross-language records | Native implementation behind a binding: same `{file, language, definitions}` shape, `language: "CPP"`, tracing e.g. a TensorFlow Python op to its C++ kernel (`SobolSampleOp::Compute` in `sobol_op.cc`). |

---

## 2. Per-release callgraphs

**Shape:** one zstd-compressed TinkerPop **GraphSON 3.0** document per
(package × released version).
**Key convention:** `callgraph/{language}/{registry}/{package}/{package}-{version}-{language}.json.zst`.
**Languages:** `python/pypi`, `java/maven`, `go/go`, plus `cpp/pypi` (native
callgraphs for Python packages whose vulnerable code lives in C++ extensions).

### Document

```
{"@type": "tinker:graph", "@value": {"vertices": [...], "edges": [...]}}
```

### Vertex (label: `FUNCTION`)

| Property | Type | Presence | Description |
|---|---|---|---|
| `id` | g:Int64 | always | Graph-local vertex ID (stable within a document, not across documents). |
| `NAME` | g:List<string> | always | Fully-qualified names. First element is canonical; additional elements are aliases (re-exports, inherited members). Ecosystem-native syntax: `yaml.full_load` (Python), `org.apache.logging.log4j.core.net.JndiManager.lookup` (Java), `(*github.com/golang-jwt/jwt.Parser).ParseUnverified` (Go). |
| `SYMBOL_NAME` | string | ~85% | Bare identifier. |
| `SIGNATURE` | string | Java & Go | Full signature, e.g. `lookup(org.apache.logging.log4j.core.LogEvent, java.lang.String)`. |
| `FILENAME` | string | in-package functions | Package-relative source path. Absent on vertices representing external references (stdlib, dependencies). |

### Edge (label: `CALLS`)

| Field | Description |
|---|---|
| `outV` | Caller vertex ID. |
| `inV` | Callee vertex ID. |

Graphs include the package's internal call structure plus resolved calls into
external dependencies and the standard library, so a package's callgraph both
(a) shows every path from its public API to any internal symbol and (b) names
the external symbols it can reach — which is what lets an application graph
join against its dependencies' graphs transitively.

Representative sizes (from [`../samples/callgraphs/`](../samples/callgraphs/)):
pyyaml 5.3 — 422 vertices / 623 edges (13 KB compressed); snakeyaml 1.33 —
2,587 / 11,272 (120 KB); log4j-core 2.14.1 — 19,547 / 72,856 (816 KB;
28 MB decompressed). Compression ratio is roughly 20–35×.

---

## 3. Advisory metadata (companion feed)

**Shape:** one JSON document per advisory, same path convention as findings;
joins on `safety_id`.

| Field | Description |
|---|---|
| `safety_id` | Join key. |
| `identifiers` | CVE, GHSA, and other identifiers. |
| `affected_packages` | Affected package coordinates and versions. |
| `severities` | CVSS v2 / v3 / v4 entries — vector strings, scores, and source attribution (NVD, GHSA, vendor). |
| `cwes` | CWE classifications. |
| `exploitability` | `epss` (score, percentile, last_updated), `cisa_kev` status, `proofs_of_concepts` references — populated where available. |
| `description` | Advisory description text. |
| `references` | Source URLs. |
| `sources` | Where the advisory was aggregated from. |
| `schema_version` | Currently `"1.0"`. |

See [`../samples/vulnerabilities/`](../samples/vulnerabilities/) for the
Log4Shell record as a concrete example.
