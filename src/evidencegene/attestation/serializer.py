"""FindingSerializer — the fail-closed gate.

Architectural rule, not a prompt rule:
  * a finding with zero valid ``artifact_refs`` is REJECTED;
  * a ref that does not exist in the artifact store is REJECTED;
  * CONFIRMED is GRANTED only when refs span >=2 distinct evidence sources —
    otherwise the tier is downgraded to INFERRED regardless of what the
    model asked for.

Every accept/reject decision is appended to the audit chain, so the
accuracy report can show blocked hallucination attempts verbatim.
"""

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

from evidencegene.artifacts.store import ArtifactStore
from evidencegene.attestation.models import Finding, PublishedFinding, Tier

logger = logging.getLogger(__name__)


class FindingRejected(Exception):
    def __init__(self, reason: str, finding: Finding) -> None:
        super().__init__(reason)
        self.reason = reason
        self.finding = finding


class FindingSerializer:
    def __init__(self, store: ArtifactStore, findings_path: Path) -> None:
        self._store = store
        self._path = findings_path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def publish(self, finding: Finding) -> PublishedFinding:
        invalid = [ref for ref in finding.artifact_refs if not self._store.exists(ref)]
        if invalid:
            self._reject(finding, f"unknown artifact_refs: {invalid}")
        if not finding.artifact_refs and finding.proposed_tier != Tier.ABSTAIN:
            self._reject(finding, "no artifact_refs — evidence-free claims are not publishable")

        sources = sorted(
            {
                meta.source
                for ref in finding.artifact_refs
                if (meta := self._store.meta(ref)) is not None
            }
        )
        tier = self._grant_tier(finding.proposed_tier, sources)

        published = PublishedFinding(
            **finding.model_dump(),
            finding_id=f"fnd-{uuid.uuid4().hex[:10]}",
            tier=tier,
            published_at=datetime.now(UTC).isoformat(),
            sources=sources,
        )
        with self._path.open("a", encoding="utf-8") as f:
            f.write(published.model_dump_json() + "\n")
        self._store.append_event(
            {
                "type": "finding_published",
                "finding_id": published.finding_id,
                "claim": published.claim,
                "tier": str(tier),
                "proposed_tier": str(finding.proposed_tier),
                "artifact_refs": finding.artifact_refs,
                "sources": sources,
            }
        )
        logger.info(
            "finding published",
            extra={"finding_id": published.finding_id, "tier": str(tier)},
        )
        return published

    def _grant_tier(self, proposed: Tier, sources: list[str]) -> Tier:
        if proposed == Tier.ABSTAIN:
            return Tier.ABSTAIN
        if len(sources) >= 2:
            return proposed  # CONFIRMED allowed only here
        if proposed == Tier.CONFIRMED:
            logger.warning("tier downgraded CONFIRMED->INFERRED: single evidence source")
            return Tier.INFERRED
        return proposed

    def _reject(self, finding: Finding, reason: str) -> None:
        self._store.append_event(
            {
                "type": "finding_rejected",
                "reason": reason,
                "claim": finding.claim,
                "agent": finding.agent,
                "artifact_refs": finding.artifact_refs,
            }
        )
        logger.warning("finding rejected", extra={"reason": reason, "claim": finding.claim})
        raise FindingRejected(reason, finding)

    def published(self) -> list[PublishedFinding]:
        if not self._path.exists():
            return []
        out = []
        with self._path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    out.append(PublishedFinding.model_validate(json.loads(line)))
        return out
