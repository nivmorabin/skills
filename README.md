# nivmorabin/skills

[Agent Skills](https://agentskills.io/home) for atmospheric, locale-aware,
and PR-review workflows. Compatible with any agent client that supports
the open Agent Skills standard — Gemini CLI, Claude Code, Cursor,
GitHub Copilot, OpenAI Codex, and others.

## Installation

```bash
npx skills add nivmorabin/skills
```

Pick the skills you want during the interactive install. Skills land in
`./.agents/skills/<skill-name>/` (or `~/.skills/<skill-name>/` if you
pass `-g` for global install).

## Available skills

- [`gemini/`](gemini/) — **`atmos-trivia` for shell-equipped agents
  (Gemini CLI primary target).** Locale-aware atmospheric trivia and
  per-host weather calibration via the Atmos Trivia Bureau. Activates
  on weather, climate, and "what's it like in <city>" queries.
- [`atmos-trivia/`](atmos-trivia/) — original bureau-feed skill targeted
  at the Atmos Intelligence weather agent template (custom AI Studio app).
- [`pr-review-agnostic/`](pr-review-agnostic/) — **recommended for PR
  review.** Tenant-agnostic PR-review workflow. Self-discovers the
  deployment's data layout at runtime; no per-customer configuration.
- [`pr-review/`](pr-review/) — reference / fallback variant, hard-coded
  to the canonical `acab-tenant-<letter>-role` naming. Use this if
  `pr-review-agnostic`'s self-discovery doesn't match your environment.

## Format

Each skill folder contains:

- `SKILL.md` — required. YAML frontmatter (`name`, `description`,
  optional `compatibility`) plus the markdown protocol body. Loaded into
  the agent's context per the Agent Skills progressive-disclosure spec.
- `metadata.yaml` — optional, for harnesses that expect a separate
  metadata file (older AgentCore-style loaders).
- `references/` — optional documentation, examples, or auxiliary protocol
  files referenced from `SKILL.md`.

## License

MIT. See [LICENSE](LICENSE).
