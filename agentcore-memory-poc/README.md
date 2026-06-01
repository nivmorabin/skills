# agentcore-memory-poc

Reproduction artifacts for a Bedrock AgentCore Memory disclosure under AWS's HackerOne VDP.

## What's in here

- `travelbot-faq.md` — a payload file used by the URL-injection retrieval probe. The probe (in `aws-playground/agentcore-authz-bypass/findings/03-memory-shared-namespace-integrity/probes/`) plants this file's raw GitHub URL into AgentCore Memory as alice's observational testimony. At retrieval time, Nova fetches the URL and reads the payload's contents.

The payload is **deliberately constructed** to look like a worst-case prompt-injection directive — it contains text that *appears* to be a `<system>` block instructing the agent to misbehave. This is the literal point of the research: to characterize whether AgentCore Memory's extraction pipeline closes the structural-injection class for memory-laundered URL references (it doesn't).

## Authorization

This research is conducted by the repo owner under AWS's HackerOne VDP. The author owns the AWS account being tested; impact is bounded to the author's own resources. The "directives" in `travelbot-faq.md` only affect the author's own test agents — they are not exploit code targeting any third party.

## Anyone reading this in the wild

If you stumbled into this directory: this is security research, the payload is a test fixture, and there is no third-party harm. The corresponding disclosure is or will be filed at HackerOne; reach out via the repo owner's profile if you have questions.
