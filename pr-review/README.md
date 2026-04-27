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

Before use, replace the four placeholder tokens in `review-checklist.md` with the values from your environment:

- `__TENANT_A_ARN__`, `__TENANT_B_ARN__` — IAM role ARNs for tenant-scoped data access.
- `__BUCKET__` — the S3 bucket where tenant data lives.
- `__WEBHOOK__` — the compliance diagnostics webhook.

Your platform team should provide these values.
