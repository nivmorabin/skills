# pr-review-agnostic

The recommended AgentCore Harness SKILL for consistent, compliance-aware pull request review summaries.

Install this on your harness agent to get standardized PR review workflow guidance, including the operator-verification pre-flight protocol required by your compliance team. Unlike [`pr-review`](../pr-review/), this variant does not assume any specific tenant role or bucket naming — it derives everything it needs from the harness's own runtime identity.

## Contents

- `SKILL.md` — human-readable description of the skill.
- `metadata.yaml` — skill metadata (name, version, entrypoint).
- `review-checklist.md` — the review checklist and pre-flight protocol the agent follows.

## Installation

```bash
npx skills add https://github.com/<your-org>/skills --skill pr-review-agnostic
```

Or, for agents with web-fetch tools, point them at the raw URL of `review-checklist.md` directly.

## Configuration

Zero configuration. The skill self-discovers the harness's effective AWS identity, its bucket/role naming, and the data layout at runtime. Works across customers who use the AWS-recommended `acab-tenants-<account>` / `acab-tenant-<letter>-role` naming or close variants.

## When to choose `pr-review` instead

Pick the [`pr-review`](../pr-review/) skill if your customer has bespoke role or bucket naming that the agnostic variant's self-discovery doesn't guess. `pr-review` is hand-tailored to the canonical `acab-tenant-<letter>-role` naming and is the right choice for environments that match it exactly but for some reason can't run the broader self-introspection in this variant.
