"""Pure evidence-binding logic, shared by the court and the ablation module.

The model proposes a claim; this module re-derives the artifact references and
the attestation tier from the evidence store itself. Findings are therefore
bound to evidence, not to the model's say-so. The ``exclude_sources`` argument
lets the ablation module recompute a tier as if one evidence source were absent.
"""

import re
from dataclasses import dataclass, field

from evidencegene.artifacts.store import ArtifactStore
from evidencegene.attestation import Tier

_RE_FILE = re.compile(r"\b[\w-]+\.(?:exe|dll|sys|bat|ps1|vbs|scr)\b", re.IGNORECASE)
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_entities(text: str) -> set[str]:
    """Pull stable entity keys (binary names, IPv4s) for evidence binding.

    Volatility truncates ImageFileName (e.g. 'coreupdater.ex'), while the disk
    timeline has the full 'coreupdater.exe'. Emitting the extension-less stem
    lets a claim bind to BOTH sources, which is what unlocks CONFIRMED.
    """
    ents: set[str] = set()
    for m in _RE_FILE.finditer(text):
        name = m.group(0).lower()
        ents.add(name)
        ents.add(name.rsplit(".", 1)[0])
    ents |= {m.group(0) for m in _RE_IPV4.finditer(text)}
    return {e for e in ents if len(e) > 4}


@dataclass
class BoundClaim:
    refs: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    tier: Tier = Tier.INFERRED


def bind_claim(
    store: ArtifactStore,
    claim: str,
    detail: str = "",
    model_refs: tuple[str, ...] = (),
    exclude_sources: frozenset[str] = frozenset(),
) -> BoundClaim:
    """Re-derive artifact refs/tier from evidence. exclude_sources powers ablation.

    Tiering is computed, never asserted by the model:
      * refs spanning >=2 distinct sources -> CONFIRMED
      * refs from a single source          -> INFERRED
      * no entity found in evidence        -> empty refs (serializer rejects)
    """
    bound: dict[str, str] = {}
    for entity in extract_entities(f"{claim} {detail}"):
        for artifact_id, source in store.artifacts_containing(
            entity, exclude_sources=exclude_sources
        ):
            bound[artifact_id] = source
    for ref in model_refs:
        meta = store.meta(ref)
        if meta is not None and meta.source not in exclude_sources:
            bound[ref] = meta.source
    sources = sorted(set(bound.values()))
    tier = Tier.CONFIRMED if len(sources) >= 2 else Tier.INFERRED
    return BoundClaim(refs=sorted(bound), sources=sources, tier=tier)
