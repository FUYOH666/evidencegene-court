# Demo video script (target: 4:30 of max 5:00)

Format: screen recording of a terminal + repo, voice narration. One take per
scene; assemble in any editor. Terminal font large (18pt+), dark theme.

## Scene 1 — Hook (0:00–0:30)

Visual: README open on GitHub.

> "In November 2025, attackers ran an autonomous MCP-orchestrated intrusion at
> ninety percent autonomy. The defensive tooling we have hallucinates. This is
> EvidenceGene Court — an autonomous DFIR system where a hallucinated finding
> is not discouraged. It is structurally impossible to publish. Let me show
> you, on real evidence."

## Scene 2 — Architecture (0:30–1:15)

Visual: `docs/submission/architecture.png`.

> "Three boundaries. First: the agent only sees a typed, read-only MCP server —
> eleven functions over Volatility and Sleuth Kit. There is no shell tool and
> no write tool, so destroying evidence is impossible on the wire. Second:
> every tool result is stored in an artifact store with a SHA-256 hash chain;
> the model gets bounded previews and an artifact id, never raw dumps. Third:
> findings must cite artifacts — and the system re-derives those citations from
> the store itself. The model proposes claims; the evidence decides."

## Scene 3 — Live run (1:15–3:00)

Visual: terminal.

```bash
uv run egc-court health
uv run egc-court investigate \
  --memory cases/case001/citadeldc01.mem --source memory:dc01 \
  --disk "cases/case001/E01-DC01/20200918_0347_CDrive.E01" --disk-source disk:dc01
```

> "This is DFIR Madness Case 001 — a public case with documented ground truth.
> A two-gigabyte memory image and a four-and-a-half-gigabyte disk image.
> Watch the court: the Prosecutor proposes findings, the Defender attacks them
> with benign explanations, the Arbiter rules."
>
> (when results print) "The court found coreupdater.exe — the documented
> implant — with its command-and-control connection. And note the tier:
> the cross-source claim is CONFIRMED, because it is corroborated by memory
> AND the disk timeline. Single-source claims stay INFERRED. The system
> downgrades automatically — confidence is computed, not asserted."

## Scene 4 — Self-correction + blocked hallucination (3:00–4:00)

Visual: terminal.

```bash
# show an audit_chain.jsonl finding_rejected event from a real run
grep finding_rejected docs/submission/sample-run/audit_chain.jsonl | head -2

# live: inject an evidence-free claim
uv run python -c "
from evidencegene.artifacts.store import ArtifactStore
from evidencegene.attestation import FindingSerializer, Finding, Tier, FindingRejected
from evidencegene.config import settings
s = ArtifactStore(settings.artifact_db, settings.audit_log)
ser = FindingSerializer(s, settings.findings_log)
try:
    ser.publish(Finding(claim='backdoor totallyfake.exe beaconed to 6.6.6.6',
                        proposed_tier=Tier.CONFIRMED))
except FindingRejected as e:
    print('BLOCKED:', e.reason)"
```

> "Here is the part that matters. During testing, a model emitted placeholder
> citations — and the gate rejected every one of those findings. Now live: I
> inject a fabricated claim about a process that exists in no artifact. The
> serializer fail-closes. This is not a prompt rule the model can ignore —
> the rejection happens at the API boundary, and it is logged."

## Scene 4b — v0.2: attack the defender + jury (optional, +0:40)

Visual: terminal.

```bash
# GTG-1002 mirror: autonomously attack our OWN defender
uv run egc-court redteam        # -> 6/6 defended, each mapped to MITRE ATLAS

# falsifiability: remove a source, watch CONFIRMED collapse
uv run egc-court ablate         # -> coreupdater.exe CONFIRMED -> INFERRED

# jury of local models: promote only cross-model consensus
uv run egc-court jury --memory cases/case001/citadeldc01.mem --source memory:dc01
```

> "We don't just defend — we attack our own defender. The injection harness is
> the GTG-1002 mirror: six attacks mapped to MITRE ATLAS, six defended, each
> logged. Ablation proves findings are falsifiable: pull one source and the
> CONFIRMED tier collapses. And a jury of local models promotes only what they
> agree on — when one juror overflowed, it abstained instead of crashing the
> panel."

## Scene 5 — Audit trail + close (4:00–4:30)

Visual: terminal.

```bash
uv run egc-court verify
head -3 docs/submission/sample-run/findings.jsonl
```

> "Every finding traces to the exact tool execution that produced it, in a
> hash-chained log that detects single-byte tampering. And all of this ran on
> one laptop with a local model — the evidence never left the machine.
> EvidenceGene Court: the court is the architecture. Thank you."

## Recording checklist

- [ ] LM Studio running, model loaded
- [ ] `rm -f reports/runs/*` for a clean run
- [ ] Terminal: 120 cols, large font
- [ ] Mute notifications (macOS Focus mode)
- [ ] Export 1080p, <5:00, upload YouTube (public/unlisted)
