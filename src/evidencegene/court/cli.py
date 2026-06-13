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


def cmd_fixture(_: argparse.Namespace) -> int:
    from evidencegene.fixture import build

    store, serializer = build()
    ok, entries = store.verify_chain()
    print(
        f"fixture: {settings.fixture_dir}  (audit chain {'VALID' if ok else 'BROKEN'}, "
        f"{entries} entries, {len(serializer.published())} findings)"
    )
    return 0 if ok else 1


def cmd_ablate(_: argparse.Namespace) -> int:
    from evidencegene.analysis import ablate

    store, serializer = _store_and_serializer()
    published = serializer.published()
    rows = ablate(store, published)
    confirmed = [f for f in published if str(f.tier) == "CONFIRMED"]
    print(f"\n=== Counterfactual ablation: {len(confirmed)} CONFIRMED finding(s) ===")
    if not rows:
        print("  (no CONFIRMED findings to ablate)")
    for r in rows:
        mark = "COLLAPSED" if r.collapsed else "HELD"
        print(
            f"  [{mark}] remove {r.removed_source}: {r.original_tier} -> "
            f"{r.resulting_tier}  ::  {r.claim[:60]}"
        )
    all_collapse = all(r.collapsed for r in rows) if rows else True
    print(
        "\nResult: every CONFIRMED finding depends on cross-source corroboration."
        if all_collapse
        else "\nResult: some CONFIRMED findings survived ablation (single-source over-grant?)."
    )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from pathlib import Path

    from evidencegene.analysis import ablate
    from evidencegene.report.render import render_html, write_report

    store, serializer = _store_and_serializer()
    findings = serializer.published()
    ablation = ablate(store, findings)
    html_text = render_html(
        store, findings, ablation=ablation, audit_path=Path(settings.audit_log)
    )
    write_report(html_text, Path(args.html))
    print(f"report written: {args.html} ({len(findings)} findings)")
    if settings.enable_pdf:
        print(f"pdf (if WeasyPrint installed): {Path(args.html).with_suffix('.pdf')}")
    return 0


def cmd_jury(args: argparse.Namespace) -> int:
    from evidencegene.court.jury import JuryCourt, jury_models

    models = [m.strip() for m in args.models.split(",") if m.strip()] if args.models else None
    store, serializer = _store_and_serializer()
    court = JuryCourt(store, serializer, models=models)
    case = CaseInput(
        memory_image=args.memory,
        memory_source=args.source,
        disk_image=args.disk,
        disk_source=args.disk_source,
        disk_offset=args.disk_offset,
    )
    result = court.investigate(case)
    used = models or jury_models()
    print(f"\n=== Jury verdict ({result.jury_size} jurors: {', '.join(used)}) ===")
    print("Votes per entity:")
    for ent, votes in sorted(result.votes.items(), key=lambda kv: -kv[1]):
        print(f"  {votes}/{result.jury_size}  {ent}")
    print(f"\nConsensus findings (>= {settings.jury_min_votes} votes): {len(result.published)}")
    for f in result.published:
        print(f"  [{f.tier}] ({f.jury_votes}/{f.jury_size}) {f.claim[:70]}")
    return 0


def cmd_redteam(args: argparse.Namespace) -> int:
    from pathlib import Path

    from evidencegene.redteam import InjectionHarness
    from evidencegene.redteam.report import write_report

    db = Path(settings.work_dir) / "redteam.sqlite3"
    audit = Path(settings.work_dir) / "redteam_audit.jsonl"
    findings = Path(settings.work_dir) / "redteam_findings.jsonl"
    for p in (db, audit, findings):
        p.unlink(missing_ok=True)
    store = ArtifactStore(db, audit)
    serializer = FindingSerializer(store, findings)

    results = InjectionHarness(store, serializer).run_all()
    defended = sum(1 for r in results if r.defended)
    print(f"\n=== Red-team scorecard: {defended}/{len(results)} defended ===")
    for r in results:
        mark = "DEFENDED" if r.defended else "BYPASSED"
        print(f"  [{mark}] {r.payload_id} {r.name} ({r.atlas_id}) — {r.detail}")
    chain_ok, entries = store.verify_chain()
    print(f"audit chain: {'VALID' if chain_ok else 'BROKEN'} ({entries} entries)")
    if args.report:
        write_report(results, Path(args.report))
        print(f"report written: {args.report}")
    return 0 if defended == len(results) else 1


def main() -> None:
    parser = argparse.ArgumentParser(prog="egc-court", description="EvidenceGene Court")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("health", help="check LLM endpoint, tools, audit chain").set_defaults(
        func=cmd_health
    )
    sub.add_parser("verify", help="replay and verify the audit chain").set_defaults(
        func=cmd_verify
    )
    sub.add_parser("fixture", help="generate the synthetic mini-fixture").set_defaults(
        func=cmd_fixture
    )

    sub.add_parser(
        "ablate", help="counterfactual ablation: remove a source, watch CONFIRMED collapse"
    ).set_defaults(func=cmd_ablate)

    rp = sub.add_parser("report", help="render a self-contained HTML incident report")
    rp.add_argument(
        "--html", default="docs/submission/report.html", help="output HTML path"
    )
    rp.set_defaults(func=cmd_report)

    jr = sub.add_parser("jury", help="run the court across multiple models (consensus)")
    jr.add_argument("--memory", help="path to memory image")
    jr.add_argument("--source", default="memory:host", help="memory evidence source id")
    jr.add_argument("--disk", help="path to disk image (E01/raw)")
    jr.add_argument("--disk-source", default="disk:host", help="disk evidence source id")
    jr.add_argument("--disk-offset", type=int, default=0, help="partition sector offset")
    jr.add_argument("--models", default="", help="CSV of model ids (default: EGC_JURY_MODELS)")
    jr.set_defaults(func=cmd_jury)

    rt = sub.add_parser("redteam", help="run the injection harness against the defender")
    rt.add_argument(
        "--report",
        default="docs/REDTEAM_REPORT.md",
        help="path to write the markdown scorecard (default: docs/REDTEAM_REPORT.md)",
    )
    rt.set_defaults(func=cmd_redteam)

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
