# Devpost submission — copy-paste pack

## General info

**Project name** (59 chars):

> EvidenceGene Court: Adversarial DFIR That Can't Hallucinate

**Elevator pitch** (196 chars):

> AI court — Prosecutor, Defender, Arbiter — investigates disk+memory through a
> typed read-only MCP server. Claims without real evidence refs are structurally
> rejected. Runs fully local on a laptop.

## Project story

### Inspiration

GTG-1002 was the wake-up call: attackers ran an MCP-orchestrated intrusion at
80–90% autonomy. The defensive answer can't be "prompt the model to be careful" —
Protocol SIFT's own brief admits it hallucinates more than anyone would like.
We asked: what if a hallucinated finding were not discouraged, but
**structurally impossible to publish**? Courts solved this centuries ago:
adversarial process plus rules of evidence. So we built one.

### What it does

EvidenceGene Court runs an autonomous incident response investigation over
disk and memory images:

1. A **typed, read-only MCP server** (`sift-gene-mcp`) wraps Volatility 3 and
   Sleuth Kit as 11 structured functions. No shell tool exists. No write tool
   exists. Evidence spoliation is impossible on the wire.
2. Every tool execution is stored in an **artifact store** with a SHA-256
   hash-chained audit log. The model receives bounded previews + `artifact_id`,
   never raw dumps — a 19,685-row netscan stays out of the context window.
3. Three agents argue: the **Prosecutor** proposes findings, the **Defender**
   attacks them with benign explanations, the **Arbiter** rules and may request
   follow-up tool runs (bounded by a hard iteration cap).
4. **Evidence binding**: the system does not trust the model's citations. It
   extracts the entities from each claim (binaries, IPs) and re-derives the
   artifact references by searching stored tool output. A claim about an entity
   that appears in no artifact gets zero refs.
5. The **FindingSerializer** fail-closes: no refs → rejected. Refs from one
   source → INFERRED. Refs spanning memory AND disk → CONFIRMED. Deadlock →
   ABSTAIN, published as an open question instead of a confident guess.

On DFIR Madness Case 001, the court autonomously identified the documented
implant (`coreupdater.exe`, outbound TCP to the documented C2 IP on 443) and
promoted it to CONFIRMED by corroborating memory against the disk timeline —
with every finding traceable to the exact tool execution that produced it.

The entire investigation runs **on one laptop with a local LLM** (LM Studio,
OpenAI-compatible). Evidence with PII or privileged material never leaves the
machine; one env var points the court at a cloud gateway if policy allows.

### How we built it

Python 3.12 + uv; the official MCP Python SDK (FastMCP) with Pydantic
structured output; Volatility 3 and Sleuth Kit as the forensic engines (both
ship on the SIFT Workstation); SQLite for artifacts; a JSONL hash chain for the
audit log; httpx against any OpenAI-compatible endpoint. The adversarial-court
and audit patterns are ported from our earlier open-source work on supervised
multi-agent QA (ConductGene) and attestation layers (AttestRWA).

### Challenges

- **Reasoning models are chaotic.** One local model put its entire answer in
  `reasoning_content`; another occasionally emitted literal `"..."` as a claim.
  We stopped trusting agents to be well-behaved: claims are reconciled across
  Prosecutor/Defender/Arbiter, refs are re-derived from evidence, and the
  serializer rejects whatever survives without proof. The day a model emitted
  placeholder refs, the gate rejected all four findings — the failure mode
  proved the architecture.
- **Volatility truncates process names** (`coreupdater.ex`), which silently
  breaks naive cross-source matching against the disk's `coreupdater.exe`.
  Entity extraction emits extension-less stems so one claim binds to both.
- **Context windows vs forensic data.** Raw tool output floods small local
  models. Artifact handles + per-tool column projection + noise filtering
  (listener sockets) keep prompts small without losing data — the full rows
  stay queryable by id.

### Accomplishments we're proud of

True-positive detection of a real implant on a public ground-truth case, zero
published false positives, a live demonstration of a blocked hallucination, and
an audit chain that detects single-byte tampering — all on a laptop.

### What we learned

Guardrails must not depend on model quality. When we swapped a 35B model for a
7B one, the findings got weaker but the rejection mechanism fired identically.
Accuracy is a property of the architecture; eloquence is a property of the
model.

### What's next

- Wrap more SIFT tools (Plaso timelines, EZ Tools registry/prefetch parsers).
- "Artifact Genes": persist analyst corrections as replayable triage rules.
- Hybrid-retrieval playbooks (Qdrant + BGE) for MITRE-grounded next-step hints.
- Upstream the typed-wrapper + evidence-binding pattern to Protocol SIFT.

## Built with

`python` · `uv` · `mcp` · `pydantic` · `volatility3` · `sleuthkit` · `sqlite`
· `httpx` · `lm-studio` · `qwen` · `github-actions`
