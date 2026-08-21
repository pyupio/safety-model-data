# Callgraph samples

Six per-release callgraphs, exactly as delivered from the corpus (zstd-compressed
TinkerPop GraphSON 3.0). Each is the complete static callgraph of one published
release of one package. Each version was chosen because it is affected by a
well-known CVE whose vulnerable symbols appear as vertices in the graph — and
five of the six pair directly with finding records in
[`../findings/`](../findings/), so you can verify the cross-dataset join
yourself.

| File | Ecosystem | Functions | Call edges | Paired CVE story |
|---|---|---:|---:|---|
| `java/org.apache.logging.log4j__log4j-core-2.14.1-java.json.zst` | Maven | 19,547 | 72,856 | CVE-2021-44228 (Log4Shell) — `JndiLookup.lookup` |
| `java/org.yaml__snakeyaml-1.33-java.json.zst` | Maven | 2,587 | 11,272 | CVE-2022-1471 — unsafe `Constructor` deserialization (`Constructor.getClassForName` and the reflective construction paths are in the graph; no finding record in the sample set) |
| `python/pyyaml-5.3-python.json.zst` | PyPI | 422 | 623 | CVE-2020-14343 — `yaml.full_load` FullLoader bypass |
| `python/requests-2.31.0-python.json.zst` | PyPI | 385 | 522 | CVE-2024-35195 — `Session` cert-verification bypass |
| `go/github.com__golang-jwt__jwt-3.2.2-go.json.zst` | Go | 326 | 782 | CVE-2025-30204 — `Parser.ParseUnverified` allocation |
| `go/github.com__gin-gonic__gin-1.9.0-go.json.zst` | Go | 948 | 1,378 | CVE-2023-29401 — `Context.FileAttachment` |

File names here replace the `:` of Maven coordinates with `__` for
filesystem portability. In the corpus itself, keys follow
`callgraph/{language}/{registry}/{package}/{package}-{version}-{language}.json.zst`
(Maven packages keyed as `groupId:artifactId`, Go packages by full module path).

## Format

Decompress with `zstd -d <file>`. Each document is one graph:

```json
{
  "@type": "tinker:graph",
  "@value": {
    "vertices": [
      {
        "@type": "g:Vertex",
        "id": {"@type": "g:Int64", "@value": 68719481313},
        "label": "FUNCTION",
        "properties": {
          "NAME":        {"@value": {"@type": "g:List", "@value": ["org.apache.logging.log4j.core.lookup.JndiLookup.lookup"]}},
          "SYMBOL_NAME": {"@value": "lookup"},
          "SIGNATURE":   {"@value": "lookup(org.apache.logging.log4j.core.LogEvent, java.lang.String)"},
          "FILENAME":    {"@value": "org/apache/logging/log4j/core/lookup/JndiLookup.java"}
        }
      }
    ],
    "edges": [
      {
        "@type": "g:Edge",
        "label": "CALLS",
        "outV": {"@type": "g:Int64", "@value": 68719476736},
        "inV":  {"@type": "g:Int64", "@value": 68719481313}
      }
    ]
  }
}
```

- **Vertices** are functions. `NAME` is a list — the first entry is the
  canonical fully-qualified name, any further entries are aliases (re-exports,
  inherited members). `SIGNATURE` is present for Java and Go. `FILENAME` is
  present for in-package functions and absent for external references.
- **Edges** are `CALLS` relations, caller (`outV`) → callee (`inV`).
- Naming is ecosystem-native: dotted FQNs for Python and Java
  (`yaml.full_load`, `org.yaml.snakeyaml.constructor.Constructor.getClassForName`),
  Go's dual form for functions and methods (`github.com/golang-jwt/jwt.Parse`,
  `(*github.com/golang-jwt/jwt.Parser).ParseUnverified`).

## Try it

Trace who can reach the Log4Shell sink:

```console
$ python3 ../../scripts/callgraph_paths.py \
    java/org.apache.logging.log4j__log4j-core-2.14.1-java.json.zst \
    'JndiLookup\.lookup$'

graph: 19547 functions, 72856 call edges
== org.apache.logging.log4j.core.lookup.JndiLookup.lookup
   ...StrSubstitutor.resolveVariable -> ...Interpolator.lookup -> ...AbstractLookup.lookup -> ...JndiLookup.lookup
   ...
```

That chain — message-format variable substitution resolving through the
interpolator into the JNDI lookup — is the actual Log4Shell attack path.
