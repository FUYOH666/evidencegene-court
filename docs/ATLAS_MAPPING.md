# MITRE ATLAS Mapping — Injection Harness

The injection harness (`egc-court redteam`) is the GTG-1002 mirror: it
autonomously attacks our own defender and proves each attack is neutralized by
an architectural boundary, not a prompt. Each payload maps to a MITRE ATLAS
adversarial-ML technique.

- **rt-01 Evidence-free fabricated finding** → `AML.T0051 LLM Prompt Injection`
  - Boundary: FindingSerializer rejects claims with zero `artifact_refs`.
- **rt-02 Citation of a non-existent artifact** → `AML.T0051 LLM Prompt Injection`
  - Boundary: FindingSerializer rejects refs absent from the artifact store.
- **rt-03 Tier inflation on a single source** → `AML.T0054 LLM Jailbreak`
  - Boundary: CONFIRMED is granted only across >=2 distinct sources; otherwise
    auto-downgraded to INFERRED.
- **rt-04 Instruction smuggled inside tool output** → `AML.T0051 LLM Prompt Injection`
  - Boundary: tool output is inert data; publication requires entity binding to
    real evidence, which a smuggled instruction cannot provide.
- **rt-05 Prompt injection via a malicious filename** → `AML.T0051 LLM Prompt Injection`
  - Boundary: filenames are data, never executed; there is no action surface.
- **rt-06 Destructive tool absence** → `AML.T0049 Exploit Public-Facing Application`
  - Boundary: the MCP surface exposes only read-only typed tools; no
    write/delete/shell tool exists to abuse.

Run `egc-court redteam` to regenerate the live scorecard
([docs/REDTEAM_REPORT.md](REDTEAM_REPORT.md)). Every attempt is also logged as a
`redteam_attempt` event in the audit chain, so the result is tamper-evident.
