# Case study: Log4Shell, from advisory to attack path

This walkthrough uses three sample files — all verbatim production data — to
show how the datasets compose:

1. **Finding** — [`../findings/java/maven/org.apache.logging.log4j__log4j-core/SFTY-20211210-26603.json`](../findings/java/maven/org.apache.logging.log4j__log4j-core/SFTY-20211210-26603.json)
2. **Advisory metadata** — [`../vulnerabilities/java/maven/org.apache.logging.log4j__log4j-core/SFTY-20211210-26603.json`](../vulnerabilities/java/maven/org.apache.logging.log4j__log4j-core/SFTY-20211210-26603.json)
3. **Callgraph** — [`../callgraphs/java/org.apache.logging.log4j__log4j-core-2.14.1-java.json.zst`](../callgraphs/java/org.apache.logging.log4j__log4j-core-2.14.1-java.json.zst) (log4j-core 2.14.1: 19,547 functions, 72,856 call edges)

## 1. The finding: which symbols, in which releases

CVE-2021-44228 as published says, roughly, "log4j-core ≥2.0-beta9, <2.15.0 is
vulnerable." Our finding record says something much more specific — it names
four vulnerable symbols:

| Symbol | Signature | Vulnerable in |
|---|---|---:|
| `JndiManager.lookup` | `lookup(final String name)` | 46 versions |
| `JndiManager.<init>` | `JndiManager(final String name, final Context context)` | 45 versions |
| `JndiManager.JndiManagerFactory.createManager` | `createManager(final String name, final Properties data)` | 46 versions |
| `JmsAppender.Builder.build` | `build()` | 46 versions |

and gives each its own fully enumerated version list, distinct from the
advisory's 52-version package-level list. `JndiManager` didn't exist before
2.0-beta9's restructuring, and the per-symbol lists reflect exactly which
releases contain each piece of vulnerable code.

## 2. The advisory metadata: severity, exploitability, context

Joining on `safety_id` (SFTY-20211210-26603), the vulnerabilities feed
contributes CVSS v2/v3/v4 vectors and scores from multiple sources (NVD, GHSA),
four CWE classifications (CWE-20, -400, -502, -917), the advisory description,
and references; the schema also carries exploitability fields (EPSS
score/percentile, CISA KEV, proof-of-concept references) populated on part of
the feed. One key, two complementary records.

## 3. The callgraph: is the vulnerable code invocable, and from where?

The per-release callgraph of log4j-core 2.14.1 (the last version before the
first fix) contains the finding's symbols as vertices — the join is
string-exact on the fully-qualified name:

```console
$ python3 ../../scripts/callgraph_paths.py \
    ../callgraphs/java/org.apache.logging.log4j__log4j-core-2.14.1-java.json.zst \
    'JndiManager\.lookup$'

graph: 19547 functions, 72856 call edges
== org.apache.logging.log4j.core.net.JndiManager.lookup
   ...StrSubstitutor.resolveVariable
      -> ...Interpolator.lookup
      -> ...JndiLookup.lookup
      -> ...JndiManager.lookup
   ...JmsManager.send -> ... -> ...JmsManager.createConnection -> ...JndiManager.lookup
   ...
```

The first chain is the actual Log4Shell attack path: logging a
message containing `${jndi:ldap://...}` drives the string substitutor's
variable resolution (`StrSubstitutor.resolveVariable`) through the lookup
interpolator (`Interpolator.lookup`) into the JNDI lookup handler
(`JndiLookup.lookup`), which performs the remote JNDI fetch
(`JndiManager.lookup`). The graph also surfaces the secondary paths (JMS
appender configuration, JNDI context selector) that made partial mitigations
insufficient.

Because a callgraph exists for **every release** of the package, the same
query run against 2.15.0 or 2.17.0 shows how the reachable surface changed as
the fixes landed — a labeled, longitudinal record of a vulnerability's
lifecycle at function granularity.

## Why this matters for model training

Put the three together and you get supervision that doesn't exist in public
data:

- *"This function, with this signature, in this file, is the vulnerability"* —
  not "this package version range is bad."
- *"These are the call chains from the public API to it"* — mechanically
  derived, high-precision paths a model can learn to construct or verify.
- *"Here are 46 releases where this holds and the adjacent releases where it
  doesn't"* — natural positive/negative pairs for contrastive training, patch
  localization, and reachability RL tasks, across a quarter century of releases
  for 8,000+ packages.
