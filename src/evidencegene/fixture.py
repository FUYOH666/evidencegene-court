"""Generate a tiny synthetic two-source case for fast, offline, token-free runs.

The fixture seeds the artifact store with memory + disk artifacts that include a
planted implant (``evil.exe``) corroborated across both sources, then publishes
one CONFIRMED finding. Every downstream module (redteam, ablation, report) can
then run in milliseconds without 2 GB evidence images or an LLM.
"""

import logging

from evidencegene.artifacts.store import ArtifactStore
from evidencegene.attestation import Finding, FindingSerializer, Tier
from evidencegene.config import settings
from evidencegene.court.binding import bind_claim

logger = logging.getLogger(__name__)


def build() -> tuple[ArtifactStore, FindingSerializer]:
    """Create (or overwrite) the synthetic fixture. Returns (store, serializer)."""
    fdir = settings.fixture_dir
    fdir.mkdir(parents=True, exist_ok=True)
    db = fdir / "artifacts.sqlite3"
    audit = fdir / "audit_chain.jsonl"
    findings = fdir / "findings.jsonl"
    for p in (db, audit, findings):
        p.unlink(missing_ok=True)

    store = ArtifactStore(db, audit)
    serializer = FindingSerializer(store, findings)

    # Memory source: process list (planted implant + benign processes).
    store.record(
        "vol_pslist",
        "memory:test",
        {"image": "synthetic.mem"},
        [
            {"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2026-01-01T00:00:00"},
            {"PID": 880, "PPID": 4, "ImageFileName": "svchost.exe",
             "CreateTime": "2026-01-01T00:01:00"},
            {"PID": 1337, "PPID": 1, "ImageFileName": "evil.exe",
             "CreateTime": "2026-01-01T03:56:37"},
        ],
    )
    # Memory source: network scan (implant beaconing to external C2).
    store.record(
        "vol_netscan",
        "memory:test",
        {"image": "synthetic.mem"},
        [
            {"LocalAddr": "10.0.0.5", "ForeignAddr": "13.37.13.37", "ForeignPort": 443,
             "State": "ESTABLISHED", "Owner": "evil.exe", "PID": 1337, "Proto": "TCPv4"},
        ],
    )
    # Disk source: file timeline confirms the implant exists on disk.
    store.record(
        "disk_file_timeline",
        "disk:test",
        {"image": "synthetic.E01", "offset": 2048},
        [
            {"name": "/Windows/Temp/evil.exe", "size": "7168",
             "mtime": "2026-01-01T03:56:30", "crtime": "2026-01-01T03:56:30"},
        ],
    )

    # Publish one finding; binding computes CONFIRMED across the two sources.
    bound = bind_claim(store, "evil.exe is a malicious implant beaconing to 13.37.13.37")
    serializer.publish(
        Finding(
            claim="evil.exe (PID 1337) is a malicious implant beaconing to 13.37.13.37",
            detail="Present in memory process/network artifacts and on disk in Windows Temp.",
            artifact_refs=bound.refs,
            proposed_tier=Tier.CONFIRMED,
            mitre=["T1071.001"],
            agent="arbiter",
        )
    )
    logger.info("fixture built at %s", fdir)
    return store, serializer


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s evidencegene %(name)s %(message)s",
    )
    store, serializer = build()
    ok, entries = store.verify_chain()
    print(
        f"fixture: {settings.fixture_dir}  (audit chain {'VALID' if ok else 'BROKEN'}, "
        f"{entries} entries, {len(serializer.published())} findings)"
    )


if __name__ == "__main__":
    main()
