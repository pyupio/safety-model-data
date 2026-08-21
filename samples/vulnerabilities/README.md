# Advisory metadata sample

One record from the companion advisory-metadata feed: Log4Shell
(CVE-2021-44228), keyed by the same `safety_id` (SFTY-20211210-26603) as the
finding record in
[`../findings/java/maven/org.apache.logging.log4j__log4j-core/`](../findings/java/maven/org.apache.logging.log4j__log4j-core/).

It carries the advisory-level context the findings deliberately don't repeat:
identifiers, affected package coordinates, CVSS v2/v3/v4 vectors and scores
with source attribution, CWE classifications (CWE-20, -400, -502, -917 here),
description, references, and exploitability fields (EPSS score/percentile,
CISA KEV, proof-of-concept references) where populated.

Schema details: [docs/SCHEMAS.md](../../docs/SCHEMAS.md#3-advisory-metadata-companion-feed).
