"""Tests for the shared evidence-binding logic (Phase 0 refactor)."""

import pytest

from evidencegene.artifacts.store import ArtifactStore
from evidencegene.attestation import Tier
from evidencegene.court.binding import bind_claim, extract_entities


@pytest.fixture
def store(tmp_path):
    return ArtifactStore(tmp_path / "art.sqlite3", tmp_path / "audit.jsonl")


def _seed_two_sources(store: ArtifactStore) -> None:
    store.record("vol_pslist", "memory:test", {}, [{"ImageFileName": "evil.exe", "PID": 1337}])
    store.record(
        "disk_file_timeline", "disk:test", {}, [{"name": "/Windows/Temp/evil.exe"}]
    )


def test_extract_entities_includes_stem_and_ip():
    ents = extract_entities("coreupdater.exe (PID 3644) beaconed to 13.37.13.37")
    assert "coreupdater.exe" in ents
    assert "coreupdater" in ents  # extension-less stem matches truncated vol names
    assert "13.37.13.37" in ents


def test_bind_claim_confirms_across_two_sources(store):
    _seed_two_sources(store)
    bound = bind_claim(store, "evil.exe is a malicious implant")
    assert bound.tier == Tier.CONFIRMED
    assert set(bound.sources) == {"memory:test", "disk:test"}
    assert len(bound.refs) == 2


def test_bind_claim_downgrades_when_one_source_excluded(store):
    _seed_two_sources(store)
    bound = bind_claim(
        store, "evil.exe is a malicious implant", exclude_sources=frozenset({"disk:test"})
    )
    assert bound.tier == Tier.INFERRED
    assert bound.sources == ["memory:test"]


def test_bind_claim_no_evidence_yields_empty_refs(store):
    _seed_two_sources(store)
    bound = bind_claim(store, "totallyfake.exe was seen")
    assert bound.refs == []
    assert bound.tier == Tier.INFERRED
