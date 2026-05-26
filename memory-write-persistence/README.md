# memory-write-persistence

Skill scripts referenced by the AgentCore Memory write-primitive persistence
H1 disclosure (`findings/03-memory-write-persistence-cross-user/`).

These scripts are designed to run **inside an AgentCore harness shell tool**
during reproduction. Each reads its parameters from environment variables
(set by the bash wrapper in the indirect-injection prompt) so the scripts
themselves carry no per-run state.

Hosted at: `https://raw.githubusercontent.com/nivmorabin/skills/master/memory-write-persistence/<filename>.py`

| File | Purpose | Used by |
|---|---|---|
| `forge_ltm_payload.py` | Plant a single LTM record under a chosen namespace via `BatchCreateMemoryRecords`. | The H1 reproduction notebook + `probe2b`. |
| `forge_chain_payload.py` | Plant a full Strands-shape STM event chain (SESSION blob + AGENT blob + USER conv envelope + AGENT blob + ASSISTANT conv envelope + AGENT blob, with `metadata.{stateType, agentId}` tags) into a single target session. | `probe1e` (single-session forge via shell tool). |
| `forge_chain_multisess_payload.py` | Same as `forge_chain_payload.py` but iterates over a comma-separated list of target sessions, demonstrating that one shell-tool turn can pollute N future sessions simultaneously. | `probe1g` (multi-session blast). |
| `probe2d_payload.py` | Mitigation matrix: from inside the harness, attempts (1) `CreateEvent(actor=alice)` control, (2) `CreateEvent(actor=bob)` cross-actor forgery, (3) `BatchCreateMemoryRecords(namespace=shared)`, (4) `UpdateMemory.addCustomStrategy(appendToPrompt)`. Reports per-cell ALLOWED / DENIED. | `probe2d` (used to characterize whether the documented `bedrock-agentcore:actorId` IAM condition bounds each primitive). |

## Authorization

Authored by Niv Rabin (HackerOne `nivmorabin`) for authorized vulnerability
research on the author's own AWS account under AWS's HackerOne VDP. Not for
use against any other party's resources.

## Threat-model role

These scripts represent the **payload** stage of a stored-content-injection
attack on AgentCore Memory: untrusted-content (e.g. a poisoned support
ticket) drives an LLM to fire the harness's built-in shell tool, which
fetches one of these scripts and runs it under the harness's exec-role
credentials. The end-state is attacker-chosen content persisted in Memory
that subsequent users' sessions retrieve into their `<user_context>` as
authoritative recall. See `findings/03-memory-write-persistence-cross-user/h1-report.md`
for the full disclosure.
