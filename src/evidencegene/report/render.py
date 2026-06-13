"""Render a self-contained HTML incident report (no external dependencies).

Sections: summary, findings by tier, ATT&CK kill-chain timeline, red-team
scorecard, ablation table, jury votes, and the audit-chain status with its root
hash. Optionally exports PDF via WeasyPrint when settings.enable_pdf is set.
"""

import html
import json
from pathlib import Path

from evidencegene.artifacts.store import ArtifactStore
from evidencegene.config import settings
from evidencegene.report.timeline import build_timeline

_CSS = """
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:980px;margin:2rem auto;
padding:0 1rem;color:#1b1f24;line-height:1.5}
h1{border-bottom:3px solid #7c3aed;padding-bottom:.3rem}
h2{margin-top:2rem;border-bottom:1px solid #d0d7de;padding-bottom:.2rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0}
th,td{border:1px solid #d0d7de;padding:.4rem .6rem;text-align:left;font-size:.92rem}
th{background:#f6f8fa}
.tier-CONFIRMED{color:#1a7f37;font-weight:700}
.tier-INFERRED{color:#9a6700;font-weight:700}
.tier-ABSTAIN{color:#57606a;font-weight:700}
.ok{color:#1a7f37;font-weight:700}.bad{color:#cf222e;font-weight:700}
code{background:#f6f8fa;padding:.1rem .3rem;border-radius:4px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85rem}
"""


def _esc(text) -> str:
    return html.escape(str(text))


def _root_hash(audit_path: Path) -> str:
    if not audit_path.exists():
        return ""
    last = ""
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            last = line
    return json.loads(last)["hash"] if last else ""


def render_html(
    store: ArtifactStore,
    findings: list,
    redteam: list | None = None,
    ablation: list | None = None,
    jury_votes: dict | None = None,
    audit_path: Path | None = None,
) -> str:
    redteam = redteam or []
    ablation = ablation or []
    jury_votes = jury_votes or {}
    chain_ok, entries = store.verify_chain()
    root = _root_hash(audit_path) if audit_path else ""

    by_tier = {"CONFIRMED": [], "INFERRED": [], "ABSTAIN": []}
    for f in findings:
        by_tier.setdefault(str(f.tier), []).append(f)

    parts: list[str] = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>EvidenceGene Court — Incident Report</title>",
        f"<style>{_CSS}</style></head><body>",
        "<h1>EvidenceGene Court — Incident Report</h1>",
        "<p>Autonomous adversarial DFIR. Every finding is bound to evidence and "
        "traceable to a tool execution in a SHA-256 audit chain.</p>",
    ]

    # Summary
    parts.append("<h2>Summary</h2><ul>")
    parts.append(f"<li>Findings published: <b>{len(findings)}</b> "
                 f"(CONFIRMED {len(by_tier['CONFIRMED'])}, INFERRED {len(by_tier['INFERRED'])}, "
                 f"ABSTAIN {len(by_tier['ABSTAIN'])})</li>")
    status = "<span class='ok'>VALID</span>" if chain_ok else "<span class='bad'>BROKEN</span>"
    parts.append(f"<li>Audit chain: {status} ({entries} entries)</li>")
    if root:
        parts.append(f"<li>Audit root hash: <span class='mono'>{_esc(root)}</span></li>")
    if redteam:
        d = sum(1 for r in redteam if r.defended)
        parts.append(f"<li>Red-team: <b>{d}/{len(redteam)}</b> attacks defended</li>")
    parts.append("</ul>")

    # Findings
    parts.append("<h2>Findings</h2><table><tr><th>Tier</th><th>Claim</th>"
                 "<th>Sources</th><th>MITRE</th><th>Artifact refs</th></tr>")
    for f in findings:
        votes = f" ({f.jury_votes}/{f.jury_size})" if getattr(f, "jury_size", 0) else ""
        parts.append(
            f"<tr><td class='tier-{_esc(f.tier)}'>{_esc(f.tier)}{votes}</td>"
            f"<td>{_esc(f.claim)}</td><td>{_esc(', '.join(f.sources))}</td>"
            f"<td>{_esc(', '.join(f.mitre))}</td>"
            f"<td class='mono'>{_esc(', '.join(f.artifact_refs))}</td></tr>"
        )
    parts.append("</table>")

    # Kill-chain timeline
    parts.append("<h2>ATT&CK kill-chain timeline</h2><table>"
                 "<tr><th>#</th><th>Tactic</th><th>Technique</th><th>Timestamp</th>"
                 "<th>Tier</th><th>Claim</th></tr>")
    for i, e in enumerate(build_timeline(findings), 1):
        parts.append(
            f"<tr><td>{i}</td><td>{_esc(e.tactic)}</td><td>{_esc(e.technique)}</td>"
            f"<td class='mono'>{_esc(e.timestamp)}</td>"
            f"<td class='tier-{_esc(e.tier)}'>{_esc(e.tier)}</td><td>{_esc(e.claim)}</td></tr>"
        )
    parts.append("</table>")

    # Red-team scorecard
    if redteam:
        parts.append("<h2>Red-team scorecard (GTG-1002 mirror)</h2><table>"
                     "<tr><th>Result</th><th>Attack</th><th>ATLAS</th><th>Outcome</th></tr>")
        for r in redteam:
            cls = "ok" if r.defended else "bad"
            mark = "DEFENDED" if r.defended else "BYPASSED"
            parts.append(
                f"<tr><td class='{cls}'>{mark}</td><td>{_esc(r.name)}</td>"
                f"<td class='mono'>{_esc(r.atlas_id)}</td><td>{_esc(r.detail)}</td></tr>"
            )
        parts.append("</table>")

    # Ablation
    if ablation:
        parts.append("<h2>Counterfactual ablation</h2><table>"
                     "<tr><th>Removed source</th><th>Tier change</th><th>Claim</th></tr>")
        for a in ablation:
            arrow = f"{a.original_tier} &rarr; {a.resulting_tier}"
            mark = "COLLAPSED" if a.collapsed else "HELD"
            parts.append(
                f"<tr><td>{_esc(a.removed_source)}</td>"
                f"<td><b>{mark}</b> ({arrow})</td><td>{_esc(a.claim)}</td></tr>"
            )
        parts.append("</table>")

    # Jury
    if jury_votes:
        parts.append("<h2>Jury votes</h2><table><tr><th>Entity</th><th>Votes</th></tr>")
        for ent, v in sorted(jury_votes.items(), key=lambda kv: -kv[1]):
            parts.append(f"<tr><td class='mono'>{_esc(ent)}</td><td>{_esc(v)}</td></tr>")
        parts.append("</table>")

    parts.append("</body></html>")
    return "".join(parts)


def write_report(html_text: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_text, encoding="utf-8")
    if settings.enable_pdf:
        try:
            from weasyprint import HTML

            HTML(string=html_text).write_pdf(str(path.with_suffix(".pdf")))
        except Exception:  # noqa: BLE001 - PDF is optional, never fail the report
            pass
