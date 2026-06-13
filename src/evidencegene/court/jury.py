"""Jury of Models — cross-model consensus on findings.

Evidence is collected once (tools are deterministic); the LLM court is then run
once per juror model. An entity (binary/IP) is promoted only if enough jurors
independently surface it, turning model disagreement into calibrated confidence.
This reuses our local LM Studio models as a real jury.
"""

import logging
from dataclasses import dataclass, field

from evidencegene.artifacts.store import ArtifactStore
from evidencegene.attestation import Finding, FindingRejected, FindingSerializer
from evidencegene.config import settings
from evidencegene.court.binding import bind_claim, extract_entities
from evidencegene.court.llm import LLMError
from evidencegene.court.orchestrator import CaseInput, Court

logger = logging.getLogger(__name__)


@dataclass
class JuryResult:
    published: list = field(default_factory=list)
    votes: dict[str, int] = field(default_factory=dict)  # entity -> juror count
    jury_size: int = 0
    rejected: list[dict] = field(default_factory=list)


def jury_models() -> list[str]:
    raw = [m.strip() for m in settings.jury_models.split(",") if m.strip()]
    return raw or [settings.llm_model]


class JuryCourt:
    def __init__(
        self, store: ArtifactStore, serializer: FindingSerializer, models: list[str] | None = None
    ) -> None:
        self._store = store
        self._serializer = serializer
        self._models = models or jury_models()
        self._court = Court(store, serializer)

    def investigate(self, case: CaseInput) -> JuryResult:
        summaries = self._court.collect(case)
        result = JuryResult(jury_size=len(self._models))

        # entity -> set of juror models that proposed it (set => one vote per juror)
        entity_jurors: dict[str, set[str]] = {}
        entity_claim: dict[str, dict] = {}

        for model in self._models:
            try:
                dispositions, _ = self._court.trial(summaries, case, model=model)
            except LLMError as exc:
                # A juror that errors (e.g. small context window) simply abstains;
                # the panel is resilient to a single flaky model.
                logger.warning("juror %s abstained: %s", model, exc)
                self._store.append_event(
                    {"type": "jury_ballot", "model": model, "abstained": True,
                     "error": str(exc)[:200]}
                )
                continue
            seen_entities: set[str] = set()
            for d in dispositions:
                claim = d.get("claim", "")
                detail = d.get("detail", "")
                for ent in extract_entities(f"{claim} {detail}"):
                    seen_entities.add(ent)
                    entity_claim.setdefault(ent, d)
            for ent in seen_entities:
                entity_jurors.setdefault(ent, set()).add(model)
            self._store.append_event(
                {"type": "jury_ballot", "model": model, "entities": sorted(seen_entities)}
            )

        result.votes = {ent: len(jurors) for ent, jurors in entity_jurors.items()}

        top_votes = max(result.votes.values(), default=0)
        if top_votes < settings.jury_min_votes:
            logger.info(
                "no entity reached the consensus threshold (top=%d, min_votes=%d); "
                "publishing nothing",
                top_votes,
                settings.jury_min_votes,
            )

        # Publish consensus entities (votes >= jury_min_votes), deduped by finding.
        published_claims: set[str] = set()
        for ent, votes in sorted(result.votes.items(), key=lambda kv: -kv[1]):
            if votes < settings.jury_min_votes:
                continue
            d = entity_claim[ent]
            claim = d.get("claim", "")
            if claim in published_claims:
                continue
            bound = bind_claim(self._store, claim, d.get("detail", ""))
            if not bound.refs:
                continue
            try:
                published = self._serializer.publish(
                    Finding(
                        claim=claim,
                        detail=d.get("detail", ""),
                        artifact_refs=bound.refs,
                        proposed_tier=bound.tier,
                        mitre=d.get("mitre", []),
                        agent="jury",
                    ),
                    jury_votes=votes,
                    jury_size=len(self._models),
                )
                result.published.append(published)
                published_claims.add(claim)
            except FindingRejected as exc:
                result.rejected.append({"claim": claim, "reason": exc.reason})

        self._store.append_event(
            {"type": "jury_consensus", "jury_size": len(self._models),
             "min_votes": settings.jury_min_votes, "votes": result.votes}
        )
        return result


__all__ = ["JuryCourt", "JuryResult", "jury_models"]
