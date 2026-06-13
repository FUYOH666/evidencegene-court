"""Tests for the jury of models — uses a FakeChatClient, no real LLM."""

import pytest

from evidencegene.artifacts.store import ArtifactStore
from evidencegene.attestation import FindingSerializer, Tier
from evidencegene.court.jury import JuryCourt
from evidencegene.court.orchestrator import CaseInput

# Which claims each "model" proposes (drives the consensus vote).
MODEL_FINDINGS = {
    "model-a": ["evil.exe is a malicious implant"],
    "model-b": ["evil.exe is a malicious implant"],
    "model-c": ["other.exe is mildly suspicious"],
}


class FakeChatClient:
    """Deterministic stand-in: returns scripted court output per role/model."""

    def __init__(self):
        self._last: list[str] = []

    def health(self) -> bool:
        return True

    def complete_json(self, system, user, schema, schema_name="response", model=None):
        usage = {"prompt_tokens": 0, "completion_tokens": 0}
        if schema_name == "prosecutor":
            self._last = MODEL_FINDINGS.get(model, [])
            return {"findings": [{"claim": c, "detail": "", "artifact_refs": [], "mitre": []}
                                 for c in self._last]}, usage
        if schema_name == "defender":
            return {"verdicts": []}, usage
        if schema_name == "arbiter":
            return {"dispositions": [
                {"claim": c, "detail": "", "artifact_refs": [], "mitre": [],
                 "proposed_tier": "INFERRED", "need_more_evidence": False, "follow_up": ""}
                for c in self._last
            ]}, usage
        return {}, usage


@pytest.fixture
def jury(tmp_path, monkeypatch):
    monkeypatch.setattr("evidencegene.court.orchestrator.ChatClient", FakeChatClient)
    store = ArtifactStore(tmp_path / "art.sqlite3", tmp_path / "audit.jsonl")
    serializer = FindingSerializer(store, tmp_path / "findings.jsonl")
    # evil.exe present in two sources -> can reach CONFIRMED; other.exe in one source.
    store.record("vol_pslist", "memory:t", {}, [{"ImageFileName": "evil.exe", "PID": 1337}])
    store.record("disk_file_timeline", "disk:t", {}, [{"name": "/tmp/evil.exe"}])
    store.record("vol_pslist", "memory:t", {}, [{"ImageFileName": "other.exe", "PID": 9}])
    court = JuryCourt(store, serializer, models=["model-a", "model-b", "model-c"])
    return court


def test_consensus_promotes_only_majority_entity(jury):
    result = jury.investigate(CaseInput())
    assert result.jury_size == 3
    assert result.votes.get("evil.exe") == 2
    assert result.votes.get("other.exe") == 1
    # only evil.exe reaches the 2-vote threshold and gets published
    claims = [f.claim for f in result.published]
    assert any("evil.exe" in c for c in claims)
    assert not any("other.exe" in c for c in claims)


def test_consensus_finding_is_confirmed_and_carries_votes(jury):
    result = jury.investigate(CaseInput())
    evil = next(f for f in result.published if "evil.exe" in f.claim)
    assert evil.tier == Tier.CONFIRMED
    assert evil.jury_votes == 2
    assert evil.jury_size == 3
