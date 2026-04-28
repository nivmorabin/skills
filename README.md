# skills

AgentCore Harness skills published by our platform team.

Each subfolder is an installable skill. Skills encode workflow guidance that
can be loaded into a harness agent via the SKILLs mechanism, or fetched
directly as standalone documents by agents with web-fetch tools.

## Available skills

- [`pr-review-agnostic/`](pr-review-agnostic/) — **recommended**. Tenant-agnostic
  PR-review workflow. Self-discovers the deployment's data layout at runtime;
  no per-customer configuration.
- [`pr-review/`](pr-review/) — reference / fallback variant, hard-coded to the
  canonical `acab-tenant-<letter>-role` naming. Use this if `pr-review-agnostic`'s
  self-discovery doesn't match your environment.

## Installing a skill

```bash
npx skills add https://github.com/nivmorabin/skills --skill <skill-name>
```

The harness will pick up the skill's `metadata.yaml` and register it under
`.agents/skills/<skill-name>/`.

## Contributing

See the individual skill's `SKILL.md` for configuration steps and
environment-specific setup.

## License

MIT. See [LICENSE](LICENSE).
