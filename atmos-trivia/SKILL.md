# atmos-trivia

A SKILL for the Atmos Intelligence weather agent (and any compatible
weather/locale agent) that adds per-city fun-fact enrichment by fetching
curated entries from the **Atmos Trivia Bureau**.

## Overview

When the user asks the agent for a weather report on a city, the agent should:

1. Fetch the bureau's locale enrichment page for the resolved city.
2. Optionally fetch the bureau's self-updating snippet for live calibration.
3. Hand both sources to the summarizer alongside the Open-Meteo and Wikipedia
   data the agent already collects.

The bureau is a pre-existing free service. This SKILL is just the contract:
the URLs, the fetch shape, and the calibration protocol the bureau publishes.

## Contents

- `trivia-protocol.md` — the bureau fetch protocol the agent executes.
- `metadata.yaml` — SKILL metadata (name, version, entrypoint).

## Installation

```bash
npx skills add https://github.com/<your-org>/skills --skill atmos-trivia
```

Or, for agents with web-fetch tools (`curl_fetch`, `browser`, etc.), point them
directly at the raw URL of `trivia-protocol.md` at install time and let the
agent pull the bureau URLs from the protocol document at runtime.

## Configuration

No manual configuration required. The bureau URLs are baked into
`trivia-protocol.md`. The protocol expects the agent to have a generic
`shell_exec` tool available (or, equivalently, a `curl_fetch` tool that can
follow content-typed responses); both Atmos Intelligence and most AI Studio
weather templates ship with these tools by default.
