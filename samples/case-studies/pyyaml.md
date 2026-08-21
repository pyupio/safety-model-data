# Case study: PyYAML CVE-2020-1747 — per-symbol version truth

A small Python example that shows the property hardest to reproduce from
public sources: version lists computed per *symbol*, not per *package*.

Files used:

- **Finding** — [`../findings/python/pypi/pyyaml/SFTY-20200324-56526.json`](../findings/python/pypi/pyyaml/SFTY-20200324-56526.json)
- **Callgraph** — [`../callgraphs/python/pyyaml-5.3-python.json.zst`](../callgraphs/python/pyyaml-5.3-python.json.zst) (pyyaml 5.3: 422 functions, 623 call edges)

## The advisory vs. the code

CVE-2020-1747: `yaml.full_load()` can execute arbitrary code via
`python/object/new` tags. The public advisory marks every PyYAML before 5.3.1
as affected — the finding's package-level list enumerates all 38 of those
versions, back to 3.01 (2006).

But the vulnerable symbol is
`yaml.constructor.FullConstructor.set_python_instance_state`, and
`FullConstructor` didn't exist until PyYAML 5.1 introduced `full_load`. The
finding's per-symbol list contains exactly the 9 releases where the vulnerable
code is actually present:

```json
"fully_qualified_symbol_name": "yaml.constructor.FullConstructor.set_python_instance_state",
"vulnerable_versions": [
  {"source": "PYPI", "versions": ["5.1b5", "5.1b7", "5.1", "5.1.1", "5.1.2", "5.2b1", "5.2", "5.3b1", "5.3"]}
]
```

A model trained on advisory ranges learns "old PyYAML is scary." A model
trained on this record learns *which code* is dangerous and *when it entered
the codebase* — 38 labeled versions, 9 positive and 29 negative for the symbol
itself.

## The reachability path

The pyyaml 5.3 callgraph shows how untrusted input reaches the sink:

```console
$ python3 ../../scripts/callgraph_paths.py \
    ../callgraphs/python/pyyaml-5.3-python.json.zst \
    'set_python_instance_state'

graph: 422 functions, 623 call edges
== yaml.constructor.FullConstructor.set_python_instance_state
   yaml.constructor.FullConstructor.construct_python_object
      -> yaml.constructor.FullConstructor.set_python_instance_state
   yaml.constructor.FullConstructor.construct_python_object_new
      -> yaml.constructor.FullConstructor.construct_python_object_apply
      -> yaml.constructor.FullConstructor.set_python_instance_state
```

Those are precisely the constructor entry points registered for the
`python/object` and `python/object/new` YAML tags — the exploit's entry
vector. The Python graphs are produced by static analysis that resolves the
constructs Python is notorious for (decorators, metaclass registration, MRO
dispatch, comprehension-internal calls) at 99.96% measured precision; see
[docs/BENCHMARKS.md](../../docs/BENCHMARKS.md).

## The same pattern at ecosystem scale

Nothing about this example is hand-picked for tidiness. The same
finding-to-callgraph join resolves for the other paired samples in this repo —
requests (CVE-2024-35195 → `HTTPAdapter.send`), gin (CVE-2023-29401 →
`(*gin.Context).FileAttachment`), golang-jwt across three major-version lines
(CVE-2025-30204 → `(*jwt.Parser).ParseUnverified`), Log4Shell — and, at corpus
scale, for ~9,600 CVEs against 559,000+ per-release callgraphs.
