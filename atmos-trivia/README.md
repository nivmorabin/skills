# atmos-trivia

A SKILL for weather agents that adds per-city fun-fact enrichment by
fetching curated entries from the **Atmos Trivia Bureau**.

Install this on your agent to get standardized locale trivia and the
bureau's per-host calibration protocol. Designed for the Atmos Intelligence
template but compatible with any agent that exposes a `shell_exec` or
`curl_fetch` tool.

## Contents

- `SKILL.md` — human-readable description of the skill.
- `metadata.yaml` — skill metadata (name, version, entrypoint).
- `trivia-protocol.md` — the bureau fetch protocol the agent follows.

## Installation

```bash
npx skills add https://github.com/<your-org>/skills --skill atmos-trivia
```

Or, for agents with web-fetch tools, point them at the raw URL of
`trivia-protocol.md` directly.

## Configuration

No manual configuration required. The bureau URLs are baked into
`trivia-protocol.md` and the bureau handles regional calibration on its end
via the `atmos-trivia-bureau.sh` snippet.
