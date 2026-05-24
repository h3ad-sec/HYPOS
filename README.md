# HYPOS

**Hypothesis-Driven Threat Hunting Platform — Part of [H3AD-HUNT](https://h3ad-sec.github.io/H3AD-HUNT/)**

> Hunt smarter. Miss nothing.

HYPOS generates structured threat hunting hypotheses from MITRE ATT&CK techniques. It combines live STIX data with a curated hypothesis database to give analysts actionable hunting statements, detection logic, pivot points, and mitigation guidance.

## Features

- Full ATT&CK matrix view on load — 14-tactic grid of all parent techniques
- Per-technique hypothesis cards with severity rating
- Curated hypotheses with detection logic (Sigma title + query hint), pivot points, tools, threat actors, and mitigations
- MITRE analytics sourced from official STIX `detects` relationships
- Related technique suggestions based on shared tools and actors
- Tag search — find techniques by tool name or actor (e.g. `NanoDump`, `Lazarus`)
- Data source filter
- Export hypotheses as Markdown or JSON
- Keyboard shortcut: `/` to focus search
- Fully responsive — works on mobile, tablet, and desktop

## Curated Content

Curated techniques are marked with ★ in the matrix. Each curated entry includes:
- Hunting hypothesis statement
- Severity level
- Pivot indicators
- Associated tools and threat actors
- Detection logic references
- Mitigations with implementation detail

## Live Tool

[h3ad-sec.github.io/HYPOS](https://h3ad-sec.github.io/HYPOS/)

## Part of H3AD-SEC

HYPOS is a sub-tool under [H3AD-HUNT](https://h3ad-sec.github.io/H3AD-HUNT/), the threat hunting hub of the [H3AD-SEC](https://h3ad-sec.github.io) platform.


## H3AD-SEC Platform Modules

| Module | Tools |
|--------|-------|
| [H3AD-X](https://h3ad-sec.github.io/H3AD-X/) | X-VERDIKT, PARSE-X, DNSCOPE |
| [H3AD-AI](https://h3ad-sec.github.io/H3AD-AI/) | INSIGHT-AI, QUERYCRAFT-AI, FPLENS-AI, ATTMAP-AI, CHRONO-AI, MALBRIEF-AI |
| [H3AD-DETECT](https://h3ad-sec.github.io/H3AD-DETECT/) | TRACERULES |
| [H3AD-HUNT](https://h3ad-sec.github.io/H3AD-HUNT/) | HYPOS, PIVEX, TRACEPULSE |
| [H3AD-OPS](https://h3ad-sec.github.io/H3AD-OPS/) | QUICKTRACE, SHIFTLOG, PHISHOPS |
| [H3AD-DF](https://h3ad-sec.github.io/H3AD-DF/) | REGSCOPE |
| [H3AD-IR](https://h3ad-sec.github.io/H3AD-IR/) | — |
