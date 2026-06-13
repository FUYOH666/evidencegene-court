"""Tests for the injection harness — all deterministic, no LLM."""

import pytest

from evidencegene.artifacts.store import ArtifactStore
from evidencegene.attestation import FindingSerializer
from evidencegene.redteam import InjectionHarness
from evidencegene.redteam.payloads import PAYLOADS


@pytest.fixture
def harness(tmp_path):
    store = ArtifactStore(tmp_path / "art.sqlite3", tmp_path / "audit.jsonl")
    serializer = FindingSerializer(store, tmp_path / "findings.jsonl")
    return InjectionHarness(store, serializer), store


def test_all_attacks_are_defended(harness):
    h, _ = harness
    results = h.run_all()
    assert len(results) == len(PAYLOADS)
    bypassed = [r.payload_id for r in results if not r.defended]
    assert bypassed == [], f"defender bypassed by: {bypassed}"


def test_spoliation_surface_has_no_destructive_tools(harness):
    h, _ = harness
    results = {r.payload_id: r for r in h.run_all()}
    assert results["rt-06"].defended is True


def test_attempts_are_logged_to_audit_chain(harness):
    h, store = harness
    h.run_all()
    ok, entries = store.verify_chain()
    assert ok
    # at least one event per payload, plus tool records from rt-03/04/05
    assert entries >= len(PAYLOADS)
