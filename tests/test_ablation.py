"""Tests for counterfactual ablation — deterministic, no LLM."""

import pytest

from evidencegene.analysis import ablate
from evidencegene.artifacts.store import ArtifactStore
from evidencegene.attestation import Finding, FindingSerializer, Tier


@pytest.fixture
def confirmed_setup(tmp_path):
    store = ArtifactStore(tmp_path / "art.sqlite3", tmp_path / "audit.jsonl")
    serializer = FindingSerializer(store, tmp_path / "findings.jsonl")
    store.record("vol_pslist", "memory:t", {}, [{"ImageFileName": "evil.exe", "PID": 1337}])
    store.record("disk_file_timeline", "disk:t", {}, [{"name": "/tmp/evil.exe"}])
    from evidencegene.court.binding import bind_claim

    bound = bind_claim(store, "evil.exe is malicious")
    serializer.publish(
        Finding(
            claim="evil.exe is malicious",
            artifact_refs=bound.refs,
            proposed_tier=Tier.CONFIRMED,
        )
    )
    return store, serializer


def test_confirmed_collapses_when_any_source_removed(confirmed_setup):
    store, serializer = confirmed_setup
    rows = ablate(store, serializer.published())
    assert rows, "expected ablation rows for the CONFIRMED finding"
    assert all(r.collapsed for r in rows)
    assert {r.removed_source for r in rows} == {"memory:t", "disk:t"}
    assert all(r.resulting_tier == "INFERRED" for r in rows)


def test_single_source_inferred_is_not_ablated(tmp_path):
    store = ArtifactStore(tmp_path / "a.sqlite3", tmp_path / "au.jsonl")
    serializer = FindingSerializer(store, tmp_path / "f.jsonl")
    rec = store.record("vol_pslist", "memory:t", {}, [{"ImageFileName": "evil.exe"}])
    serializer.publish(
        Finding(claim="evil.exe seen", artifact_refs=[rec.artifact_id], proposed_tier=Tier.INFERRED)
    )
    rows = ablate(store, serializer.published())
    assert rows == []  # only CONFIRMED findings are ablated
