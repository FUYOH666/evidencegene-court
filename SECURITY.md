# Security Policy

## Scope and intent

EvidenceGene Court is research software for autonomous DFIR triage. It is built
around an explicit threat model: **the AI agent is treated as untrusted.** The
architecture assumes the model may be wrong, jailbroken, or prompt-injected, and
prevents harm structurally rather than by instruction.

### What the architecture guarantees

- **No evidence modification.** The MCP server exposes no shell, write, or delete
  tool. Forensic tools open images read-only. Spoliation is not possible on the
  wire, regardless of model behavior.
- **No evidence-free findings.** The `FindingSerializer` rejects any finding whose
  `artifact_refs` are missing or absent from the store; references are re-derived
  from evidence, not trusted from the model.
- **Tamper-evident audit.** Every tool execution, agent message, and verdict is
  appended to a SHA-256 hash-chained JSONL log. `egc-court verify` replays it and
  detects single-byte modification.

### What it does NOT guarantee

- Forensic soundness / court admissibility. Like Protocol SIFT, this is research
  software. Use write blockers and verified hashes for real casework.
- Defense against a malicious *operator* with filesystem access to the audit log
  (they could delete it; tampering is still detectable on replay).

## Reporting a vulnerability

Email the maintainer (see GitHub profile) or open a private security advisory on
GitHub. Please do not file public issues for security-sensitive reports. We aim
to acknowledge within a few days.

## Handling evidence

Never commit evidence images, memory dumps, or case data. `.gitignore` blocks
common formats (`*.E01`, `*.mem`, `*.raw`, `*.zip`, `cases/`). Investigations run
locally; evidence does not leave the machine unless you configure a remote LLM.
