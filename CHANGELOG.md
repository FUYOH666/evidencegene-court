# Changelog

All notable changes to this project are documented here. This project adheres
to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-06-13

### Added
- **Injection Harness** (`egc-court redteam`) — GTG-1002 mirror: 6 deterministic
  attacks against the defender, each mapped to MITRE ATLAS, asserted defended;
  every attempt logged to the audit chain. Docs: `ATLAS_MAPPING.md`,
  `REDTEAM_REPORT.md`.
- **Counterfactual Ablation** (`egc-court ablate`) — recompute CONFIRMED findings
  with one source removed to prove cross-source dependence (falsifiability).
- **Jury of Models** (`egc-court jury`) — evidence collected once, court run per
  juror model, consensus promotion with `jury_votes`/`jury_size`; resilient to a
  juror that errors (it abstains).
- **ATT&CK kill-chain timeline + self-contained HTML report** (`egc-court report`),
  optional PDF via WeasyPrint.
- **Synthetic mini-fixture** (`egc-court fixture`) for fast, offline, token-free runs.
- New offline test suites: `test_binding`, `test_redteam`, `test_ablation`,
  `test_jury` (FakeChatClient), `test_report` (20 tests total).

### Changed
- Extracted pure `bind_claim`/`extract_entities` into `court/binding.py`.
- Refactored `Court` into `collect()` + `trial(model=...)` to enable the jury.
- `ArtifactStore.artifacts_containing` gains `exclude_sources`; added `sources()`.
- `ChatClient.complete_json` gains an optional per-call `model` override.

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
