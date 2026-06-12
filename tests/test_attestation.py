"""Guardrail tests — the architectural anti-hallucination boundary.

These prove the core claim of the project: a finding cannot be published
without valid, source-backed artifact references, regardless of what the
model asks for.
"""

import pytest

from evidencegene.artifacts.store import ArtifactStore
from evidencegene.attestation import Finding, FindingRejected, FindingSerializer, Tier


@pytest.fixture
def setup(tmp_path):
    store = ArtifactStore(tmp_path / "art.sqlite3", tmp_path / "audit.jsonl")
    serializer = FindingSerializer(store, tmp_path / "findings.jsonl")
    return store, serializer


def _record(store, source, tool="vol_pslist"):
    rec = store.record(tool, source, {"image": "x"}, [{"PID": 4, "name": "System"}])
    return rec.artifact_id


def test_finding_without_refs_is_rejected(setup):
    _, serializer = setup
    with pytest.raises(FindingRejected, match="no artifact_refs"):
        serializer.publish(Finding(claim="malware present", proposed_tier=Tier.INFERRED))


def test_finding_with_unknown_ref_is_rejected(setup):
    _, serializer = setup
    with pytest.raises(FindingRejected, match="unknown artifact_refs"):
        serializer.publish(
            Finding(claim="evil.exe injected", artifact_refs=["art-doesnotexist"])
        )


def test_single_source_cannot_reach_confirmed(setup):
    store, serializer = setup
    ref = _record(store, "memory:dc01")
    published = serializer.publish(
        Finding(claim="suspicious process", artifact_refs=[ref], proposed_tier=Tier.CONFIRMED)
    )
    assert published.tier == Tier.INFERRED  # downgraded — one source only


def test_two_sources_can_reach_confirmed(setup):
    store, serializer = setup
    ref_mem = _record(store, "memory:dc01")
    ref_disk = _record(store, "disk:dc01", tool="disk_file_timeline")
    published = serializer.publish(
        Finding(
            claim="persistence via service binary",
            artifact_refs=[ref_mem, ref_disk],
            proposed_tier=Tier.CONFIRMED,
        )
    )
    assert published.tier == Tier.CONFIRMED
    assert set(published.sources) == {"memory:dc01", "disk:dc01"}


def test_abstain_is_publishable_without_refs(setup):
    _, serializer = setup
    published = serializer.publish(
        Finding(claim="open question: unverified C2", proposed_tier=Tier.ABSTAIN)
    )
    assert published.tier == Tier.ABSTAIN


def test_audit_chain_verifies_after_activity(setup):
    store, serializer = setup
    ref = _record(store, "memory:dc01")
    serializer.publish(Finding(claim="x", artifact_refs=[ref]))
    ok, entries = store.verify_chain()
    assert ok
    assert entries >= 2


def test_audit_chain_detects_tampering(setup, tmp_path):
    store, serializer = setup
    ref = _record(store, "memory:dc01")
    serializer.publish(Finding(claim="x", artifact_refs=[ref]))
    audit = tmp_path / "audit.jsonl"
    lines = audit.read_text().splitlines()
    lines[0] = lines[0].replace("vol_pslist", "tampered")
    audit.write_text("\n".join(lines) + "\n")
    ok, _ = store.verify_chain()
    assert not ok
