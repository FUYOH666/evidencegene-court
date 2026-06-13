"""Counterfactual ablation — falsifiability of CONFIRMED findings.

For each CONFIRMED finding, recompute its tier with one evidence source removed.
If the finding genuinely depends on cross-source corroboration, removing a
source collapses it (CONFIRMED -> INFERRED). This proves that the tier is a
property of the evidence, not of the model's confidence. Deterministic, no LLM.
"""

from dataclasses import dataclass

from evidencegene.artifacts.store import ArtifactStore
from evidencegene.attestation import Tier
from evidencegene.attestation.models import PublishedFinding
from evidencegene.court.binding import bind_claim


@dataclass
class AblationRow:
    finding_id: str
    claim: str
    original_tier: str
    removed_source: str
    resulting_tier: str
    collapsed: bool


def ablate(
    store: ArtifactStore, published_findings: list[PublishedFinding]
) -> list[AblationRow]:
    rows: list[AblationRow] = []
    for f in published_findings:
        if f.tier != Tier.CONFIRMED:
            continue
        for src in f.sources:
            bound = bind_claim(
                store, f.claim, f.detail, exclude_sources=frozenset({src})
            )
            rows.append(
                AblationRow(
                    finding_id=f.finding_id,
                    claim=f.claim,
                    original_tier=str(f.tier),
                    removed_source=src,
                    resulting_tier=str(bound.tier),
                    collapsed=bound.tier != Tier.CONFIRMED,
                )
            )
    return rows
