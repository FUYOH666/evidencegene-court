"""CLI: health check and full court investigation."""

import argparse
import logging
import shutil
import sys

from evidencegene.artifacts.store import ArtifactStore
from evidencegene.attestation import FindingSerializer
from evidencegene.config import settings
from evidencegene.court.llm import ChatClient
from evidencegene.court.orchestrator import CaseInput, Court

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s evidencegene %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


def _store_and_serializer() -> tuple[ArtifactStore, FindingSerializer]:
    store = ArtifactStore(settings.artifact_db, settings.audit_log)
    serializer = FindingSerializer(store, settings.findings_log)
    return store, serializer


def cmd_health(_: argparse.Namespace) -> int:
    ok = True
    llm = ChatClient()
    llm_ok = llm.health()
    print(f"LLM endpoint ({settings.llm_base_url}): {'OK' if llm_ok else 'UNREACHABLE'}")
    ok &= llm_ok
    for tool in (settings.vol_cmd, settings.mmls_cmd, settings.fls_cmd):
        found = shutil.which(tool) is not None
        print(f"tool {tool}: {'found' if found else 'MISSING'}")
    store, _ = _store_and_serializer()
    chain_ok, entries = store.verify_chain()
    print(f"audit chain: {'valid' if chain_ok else 'BROKEN'} ({entries} entries)")
    return 0 if ok else 1


def cmd_investigate(args: argparse.Namespace) -> int:
    store, serializer = _store_and_serializer()
    court = Court(store, serializer)
    case = CaseInput(
        memory_image=args.memory,
        memory_source=args.source,
        disk_image=args.disk,
        disk_source=args.disk_source,
        disk_offset=args.disk_offset,
    )
    result = court.investigate(case)

    print(f"\n=== Investigation complete ({result.iterations} court iterations) ===")
    print(f"artifacts collected: {len(result.artifacts)}")
    print(f"findings published:  {len(result.published)}")
    print(f"findings rejected:   {len(result.rejected)}")
    for f in result.published:
        print(f"  [{f.tier}] {f.claim}  (refs={f.artifact_refs}, sources={f.sources})")
    for r in result.rejected:
        print(f"  [REJECTED] {r['claim']}  reason: {r['reason']}")

    chain_ok, entries = store.verify_chain()
    print(f"\naudit chain: {'VALID' if chain_ok else 'BROKEN'} ({entries} entries)")
    return 0


def cmd_verify(_: argparse.Namespace) -> int:
    store, _ = _store_and_serializer()
    ok, entries = store.verify_chain()
    print(f"audit chain: {'VALID' if ok else 'BROKEN'} ({entries} entries)")
    return 0 if ok else 1


def main() -> None:
    parser = argparse.ArgumentParser(prog="egc-court", description="EvidenceGene Court")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("health", help="check LLM endpoint, tools, audit chain").set_defaults(
        func=cmd_health
    )
    sub.add_parser("verify", help="replay and verify the audit chain").set_defaults(
        func=cmd_verify
    )

    inv = sub.add_parser("investigate", help="run a full court investigation")
    inv.add_argument("--memory", help="path to memory image")
    inv.add_argument("--source", default="memory:host", help="memory evidence source id")
    inv.add_argument("--disk", help="path to disk image (E01/raw)")
    inv.add_argument("--disk-source", default="disk:host", help="disk evidence source id")
    inv.add_argument("--disk-offset", type=int, default=0, help="partition sector offset")
    inv.set_defaults(func=cmd_investigate)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
