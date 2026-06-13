"""Finding model with attestation tiers (layered-trust pattern from AttestRWA)."""

from enum import StrEnum

from pydantic import BaseModel, Field


class Tier(StrEnum):
    CONFIRMED = "CONFIRMED"  # >=2 artifact refs from >=2 distinct evidence sources
    INFERRED = "INFERRED"  # exactly 1 artifact ref, or refs from a single source
    ABSTAIN = "ABSTAIN"  # court deadlock — published as an open question, not a claim


class Finding(BaseModel):
    """A claim about the case. Cannot be published without valid artifact refs."""

    claim: str = Field(description="One-sentence factual claim about the incident")
    detail: str = Field(default="", description="Supporting reasoning")
    artifact_refs: list[str] = Field(
        default_factory=list,
        description="artifact_id values from the audit store backing this claim",
    )
    proposed_tier: Tier = Field(default=Tier.INFERRED)
    mitre: list[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    agent: str = Field(default="arbiter", description="Court role that issued the finding")


class PublishedFinding(Finding):
    finding_id: str
    tier: Tier  # tier actually granted by the serializer (may be downgraded)
    published_at: str
    sources: list[str] = Field(default_factory=list)
    jury_votes: int = Field(default=0, description="How many juror models proposed this entity")
    jury_size: int = Field(default=0, description="Total jurors that voted")
