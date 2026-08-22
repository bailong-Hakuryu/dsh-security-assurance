---
status: accepted
---

# Finding queries separate redacted summaries from revision detail

`listFindings` returns paginated authority-filtered Finding Summaries containing stable identity, current revision, validation class, bounded classification, Technical Severity and Policy Significance, sensitive-content indicators, and Assessment reference without source or Evidence payload. `getFinding` returns an authorized Finding Detail View with revision chain, Source Anchor projections, Validation Outcome, Severity Method inputs, Evidence Confidence rubric, Coverage relations, Risk Decision status, Evidence Link metadata, and disclosure-limited attack-path summary. Neither query returns mutable records or treats derived Markdown as authority.
