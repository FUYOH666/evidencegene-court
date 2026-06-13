"""Tests for the kill-chain timeline and HTML report — deterministic, no LLM."""

import pytest

from evidencegene.analysis import ablate
from evidencegene.artifacts.store import ArtifactStore
from evidencegene.attestation import Finding, FindingSerializer, Tier
from evidencegene.report.render import render_html
from evidencegene.report.timeline import build_timeline


@pytest.fixture
def populated(tmp_path):
    store = ArtifactStore(tmp_path / "art.sqlite3", tmp_path / "audit.jsonl")
    serializer = FindingSerializer(store, tmp_path / "findings.jsonl")
    store.record("vol_pslist", "memory:t", {}, [{"ImageFileName": "evil.exe", "PID": 1337}])
    store.record("disk_file_timeline", "disk:t", {}, [{"name": "/tmp/evil.exe"}])
    from evidencegene.court.binding import bind_claim

    bound = bind_claim(store, "evil.exe beaconed on 2026-01-01T03:56:37")
    serializer.publish(
        Finding(
            claim="evil.exe beaconed on 2026-01-01T03:56:37",
            artifact_refs=bound.refs,
            proposed_tier=Tier.CONFIRMED,
            mitre=["T1071.001"],
        )
    )
    return store, serializer, tmp_path


def test_timeline_orders_and_maps_tactic(populated):
    _, serializer, _ = populated
    events = build_timeline(serializer.published())
    assert events
    assert events[0].tactic == "command-and-control"
    assert events[0].timestamp == "2026-01-01T03:56:37"


def test_render_html_contains_all_sections(populated):
    store, serializer, tmp_path = populated
    findings = serializer.published()
    html_text = render_html(
        store, findings, ablation=ablate(store, findings),
        audit_path=tmp_path / "audit.jsonl",
    )
    assert "EvidenceGene Court" in html_text
    assert "kill-chain timeline" in html_text
    assert "Counterfactual ablation" in html_text
    assert "Audit root hash" in html_text
    assert "CONFIRMED" in html_text
