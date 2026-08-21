#!/usr/bin/env python3
r"""Find call paths to a vulnerable symbol in a Safety per-release callgraph.

Callgraphs are TinkerPop GraphSON 3.0 documents: FUNCTION vertices linked by
CALLS edges (caller -> callee). Given a symbol pattern, this walks the graph
backwards from every matching vertex and prints the call chains that reach it,
i.e. the evidence that the vulnerable code is invocable from the rest of the
package's API surface.

Usage:
    python3 scripts/callgraph_paths.py <callgraph.json[.zst]> <symbol-regex> [--max-depth N] [--max-paths N]

Examples:
    # Who can reach the Log4Shell sink in log4j-core 2.14.1?
    python3 scripts/callgraph_paths.py \
        samples/callgraphs/java/org.apache.logging.log4j:log4j-core-2.14.1-java.json.zst \
        'JndiLookup\.lookup$'
"""

import argparse
import io
import json
import re
import sys
from collections import defaultdict


def load_graph(path):
    if path.endswith(".zst"):
        try:
            import zstandard
        except ImportError:
            import shutil
            import subprocess
            if not shutil.which("zstd"):
                sys.exit("reading .zst files requires `pip install zstandard` or the `zstd` CLI")
            out = subprocess.run(["zstd", "-d", "-c", path], capture_output=True, check=True)
            doc = json.loads(out.stdout)
        else:
            with open(path, "rb") as fh:
                reader = zstandard.ZstdDecompressor().stream_reader(fh)
                doc = json.load(io.TextIOWrapper(reader, encoding="utf-8"))
    else:
        with open(path) as fh:
            doc = json.load(fh)
    return doc["@value"]["vertices"], doc["@value"]["edges"]


def vertex_name(v):
    """Canonical fully-qualified name. NAME holds a list: [canonical, *aliases]."""
    prop = v["properties"].get("NAME")
    if prop is None:
        return None
    value = prop["@value"]
    if isinstance(value, dict):  # g:List wrapper
        return value["@value"][0]
    return value


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("callgraph")
    ap.add_argument("symbol", help="regex matched against fully-qualified function names")
    ap.add_argument("--max-depth", type=int, default=4)
    ap.add_argument("--max-paths", type=int, default=25)
    args = ap.parse_args()

    vertices, edges = load_graph(args.callgraph)
    names = {v["id"]["@value"]: vertex_name(v) for v in vertices}

    callers = defaultdict(list)  # callee id -> caller ids
    for e in edges:
        callers[e["inV"]["@value"]].append(e["outV"]["@value"])

    pattern = re.compile(args.symbol)
    targets = [vid for vid, name in names.items() if name and pattern.search(name)]
    if not targets:
        sys.exit(f"no vertex matches {args.symbol!r} (graph has {len(names)} functions)")

    print(f"graph: {len(vertices)} functions, {len(edges)} call edges")
    print(f"matched {len(targets)} vertex(es):\n")

    printed = 0
    for target in targets:
        print(f"== {names[target]}")
        # DFS backwards over CALLS edges, collecting caller chains.
        stack = [(target, [target])]
        seen_paths = 0
        while stack and seen_paths < args.max_paths:
            node, path = stack.pop()
            parents = [p for p in callers.get(node, []) if p not in path]
            if not parents or len(path) > args.max_depth:
                if len(path) > 1:
                    chain = " -> ".join(names[n] or "?" for n in reversed(path))
                    print(f"   {chain}")
                    seen_paths += 1
                    printed += 1
                continue
            for parent in parents:
                stack.append((parent, path + [parent]))
        if seen_paths == 0:
            print("   (no inbound callers in this graph)")
        print()

    if printed >= args.max_paths:
        print(f"(stopped after {args.max_paths} paths; raise --max-paths for more)")


if __name__ == "__main__":
    main()
