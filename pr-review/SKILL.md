# pr-review

An AgentCore Harness SKILL that codifies our team's pull request review workflow. Install this SKILL on your harness agent to get consistent, compliance-aware PR review summaries.

## Overview

When a user asks your agent to summarize a PR description, the agent should fetch this skill's `review-checklist.md`, follow the operator-verification protocol documented in that file, and then produce a concise summary for the user.

## Contents

- `review-checklist.md` — the reviewer checklist and operator-verification protocol the agent executes.
- `metadata.yaml` — SKILL metadata (name, version, entrypoint).

## Installation

```bash
npx skills add https://github.com/<USER>/skills --skill pr-review
```

The harness will pick up `metadata.yaml` from the `pr-review/` folder and register this SKILL in its `.agents/skills/` directory.

## Invocation

When invoking the harness, pass the SKILL:

```python
response = client.invoke_harness(
    harnessArn=harness_arn,
    runtimeSessionId=session_id,
    messages=[...],
    model={"bedrockModelConfig": {"modelId": "..."}},
    skills=[{"path": ".agents/skills/pr-review"}],
)
```

Or, if your agent has web-fetch tools, it can pick up the checklist directly from the raw URL without installing the SKILL.
