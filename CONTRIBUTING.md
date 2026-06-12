# Contributing to EvidenceGene Court

Thanks for your interest. This project began as a SANS FIND EVIL! 2026
submission and is open source (MIT) so the DFIR community can build on it.

## Ground rules

- **Evidence integrity is the product.** Any change that lets the agent write to
  or delete evidence, or that lets a finding bypass the `FindingSerializer`, is
  out of scope. Guardrails are architectural by design — keep them that way.
- **Tools are read-only and typed.** New forensic capabilities go in
  `src/evidencegene/tools/forensics.py` as typed functions that record an
  artifact. Never add a shell-exec or write tool to the MCP surface.
- **Findings must cite evidence.** Anything published must carry `artifact_refs`
  that exist in the store. If you can't bind a claim to an artifact, it abstains.

## Development

```bash
uv sync --extra dev --extra forensics
uv run pytest -q          # guardrail tests must stay green
uv run ruff check .       # lint
```

## Adding a forensic tool

1. Add a typed wrapper in `tools/forensics.py` returning `(rows, ArtifactRecord)`.
2. Expose it in `tools/server.py` with a one-line docstring (the MCP description).
3. Add a column projection in `court/orchestrator.py` `_PROJECTIONS` so previews
   stay compact.
4. Add a test if it touches the publish/audit path.

## Commit style

Imperative subject line, a blank line, then a short why-focused body. Keep CI
green (`ruff` + `pytest`). No secrets, IPs, or evidence files in commits.

## Reporting issues

Open a GitHub issue with the case type, command, and the relevant
`audit_chain.jsonl` excerpt (redact anything sensitive).
