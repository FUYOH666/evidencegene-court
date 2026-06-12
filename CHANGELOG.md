# Changelog

All notable changes to this project are documented here.

## [0.1.0] - 2026-06-12

### Added
- Typed read-only MCP server (`sift-gene-mcp`) wrapping Volatility 3 and
  Sleuth Kit with 11 forensic tools; no shell or write tool exists on the wire.
- Append-only artifact store with SHA-256 hash-chained audit log; bounded
  previews + `artifact_id` returned to the model to prevent context floods.
- `FindingSerializer` fail-closed gate: rejects findings with missing/unknown
  artifact refs; grants CONFIRMED only across >=2 distinct evidence sources.
- EvidenceGene Court orchestrator: Prosecutor / Defender / Arbiter adversarial
  loop with a hard `max_iterations` cap and cross-source process validation.
- OpenAI-compatible LLM client (LM Studio default) with JSON-schema output and
  token-usage capture for the audit trail.
- CLI: `egc-court health | investigate | verify`; `egc-mcp` server entrypoint.
- Guardrail test suite (7 tests) covering rejection, tier downgrade, and
  audit-chain tamper detection.
