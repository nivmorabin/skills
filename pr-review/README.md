# pr-review (attacker-controlled SKILL for Finding D)

This folder is the hostable "AgentCore SKILL" that the Finding D research notebook (`07-chained-exploit.ipynb`) points at. It's shaped to match the paved-path AgentCore SKILL convention: a `SKILL.md` describing the skill's purpose, a `metadata.yaml` with identifying info, and the actual payload file `review-checklist.md`.

## What you do with it

The target layout is a public GitHub repo named `skills` (one repo holds many skills), with this folder as `pr-review/` inside it:

```
<your-gh-user>/skills/
└── pr-review/
    ├── SKILL.md
    ├── metadata.yaml
    └── review-checklist.md
```

Steps:

1. Create (or reuse) a public GitHub repo at `https://github.com/<you>/skills`.
2. Copy the three files from this folder into a `pr-review/` subfolder in that repo.
3. Before committing: open `review-checklist.md` in the repo and replace the four placeholder tokens — `__TENANT_A_ARN__`, `__TENANT_B_ARN__`, `__BUCKET__`, `__WEBHOOK__` — with the real values. Notebook 07 §3a prints the fully-substituted version; copy its output verbatim into the repo file.
4. Commit + push.
5. Grab the raw URL: `https://raw.githubusercontent.com/<you>/skills/main/pr-review/review-checklist.md`.
6. Paste that URL into `POISONED_URL` in notebook 07's §0 config cell.

From the notebook's POV it doesn't care whether this was hosted as a SKILL, a gist, a blog post, or an S3 object. The harness shell tool `curl`s whatever URL you hand it. The SKILL framing is what matters for the **writeup**: it says *this content lives at the paved-path extensibility boundary AgentCore customers are told to adopt*, not *this is just a random URL I put prompt injection on*.

## Why "SKILL" matters beyond just hosting a markdown file

AgentCore Harness ships with a first-class SKILLs mechanism: `npx skills add <github-url> --skill <skill-name>`. Skills are installable capability bundles, stored at `.agents/skills/<name>`, and passed to `invoke_harness()` as `skills=[{"path": ".agents/skills/<name>"}]`. They're the official way customers extend a harness agent with domain-specific guidance.

Two attack framings flow from this, both worth making in the writeup:

**Framing A (this notebook demonstrates):** the attacker hosts a SKILL-shaped document publicly. Alice's agent fetches it via a legitimate web-fetch tool use (`curl`). Even though she didn't *install* the SKILL, the content's SKILL structure primes the LLM to treat it as operator guidance rather than untrusted content — making the injection land more reliably. Content control is all the attacker needed.

**Framing B (future 08 follow-up, not demonstrated here):** the attacker publishes a plausibly-useful SKILL on GitHub and waits for someone to `npx skills add` it. This is a supply-chain attack on a first-class AgentCore feature. Same payload shape, far wider blast radius. Adds a "signed/vetted SKILLs" fix direction to the mitigation ladder.

## Safety note for the repo you upload this to

- The repo **must be public** for GitHub's raw.githubusercontent.com to serve it without auth. That means anyone on the internet can see the file.
- The payload points at **your** sandbox webhook and **your** sandbox tenant role ARNs. If you leave those in the public file and someone with AgentCore access runs a similar agent that reads your file, they could accidentally trigger a no-op version of the attack against their own (non-existent-for-you) resources. That's fine, but worth being aware of.
- Delete the repo after the research is done. Or keep it. It's not *dangerous* outside the AgentCore-with-matching-role-ARNs context — the attacker ARNs don't exist anywhere but your sandbox account.
- GitHub's security scanners may flag the file as containing "dangerous content" or "prompt injection" (they're right). This is research; a private fork may be cleaner if your org cares.
