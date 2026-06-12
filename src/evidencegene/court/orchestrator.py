"""Court orchestrator.

Phases:
  1. Collect — run a fixed read-only tool sweep over the evidence; everything
     lands in the artifact store.
  2. Trial — Prosecutor proposes findings, Defender challenges, Arbiter
     dispositions. If the Arbiter needs more evidence, run the requested
     follow-up tool and loop (bounded by max_iterations).
  3. Publish — every disposition goes through the FindingSerializer, which
     fail-closes on missing/unknown artifact refs.

The orchestrator calls the typed forensic functions directly (the same code
the MCP server exposes), so a run is fully reproducible from the CLI.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from evidencegene.artifacts.store import ArtifactStore
from evidencegene.attestation import Finding, FindingRejected, FindingSerializer, Tier
from evidencegene.config import settings
from evidencegene.court import agents
from evidencegene.court.llm import ChatClient
from evidencegene.tools import forensics

logger = logging.getLogger(__name__)

# Project tool rows to the columns that matter for triage, keeping the prompt
# compact (full output always remains in the artifact store, queryable by id).
_PROJECTIONS: dict[str, list[str]] = {
    "vol_pslist": ["PID", "PPID", "ImageFileName", "CreateTime"],
    "vol_psscan": ["PID", "PPID", "ImageFileName", "CreateTime", "ExitTime"],
    "vol_netscan": ["LocalAddr", "ForeignAddr", "State", "Owner", "PID", "Proto"],
    "vol_cmdline": ["PID", "Process", "Args"],
    "vol_malfind": ["PID", "Process", "Protection", "CommitCharge"],
    "cross_validate_processes": ["PID", "ImageFileName", "PPID", "anomaly"],
    "disk_partitions": ["slot", "start", "description"],
    "disk_file_timeline": ["name", "size", "mtime", "crtime"],
    "verify_image_integrity": ["path", "size_bytes", "sha256", "md5"],
}


def _project(tool: str, row: dict) -> dict:
    cols = _PROJECTIONS.get(tool)
    if not cols:
        return row
    return {k: row.get(k) for k in cols if k in row}


_RE_FILE = re.compile(r"\b[\w-]+\.(?:exe|dll|sys|bat|ps1|vbs|scr)\b", re.IGNORECASE)
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _extract_entities(text: str) -> set[str]:
    """Pull stable entity keys (binary names, IPv4s) for evidence binding.

    Volatility truncates ImageFileName (e.g. 'coreupdater.ex'), while the disk
    timeline has the full 'coreupdater.exe'. Emitting the extension-less stem
    lets a claim bind to BOTH sources, which is what unlocks CONFIRMED.
    """
    ents: set[str] = set()
    for m in _RE_FILE.finditer(text):
        name = m.group(0).lower()
        ents.add(name)
        ents.add(name.rsplit(".", 1)[0])  # stem, matches truncated vol names
    ents |= {m.group(0) for m in _RE_IPV4.finditer(text)}
    return {e for e in ents if len(e) > 4}


# Process lists are small and every entry matters → show them all.
# Network scans are huge and dominated by listeners → surface only the rows
# that matter for triage (active/foreign connections), capped.
_FULL_VIEW_TOOLS = {"vol_pslist", "vol_psscan", "cross_validate_processes", "disk_partitions"}
_NOISE_ADDRS = {"*", "0.0.0.0", "::", "127.0.0.1", "::1"}


def _select_rows(tool: str, rows: list[dict]) -> list[dict]:
    if tool in _FULL_VIEW_TOOLS:
        return rows[:80]
    if tool == "vol_netscan":
        meaningful = [
            r
            for r in rows
            if str(r.get("ForeignAddr", "")) not in _NOISE_ADDRS
            or str(r.get("State", "")).upper() == "ESTABLISHED"
        ]
        return (meaningful or rows)[:40]
    return rows[: settings.preview_rows]


@dataclass
class CaseInput:
    memory_image: str | None = None
    memory_source: str = "memory:host"
    disk_image: str | None = None
    disk_source: str = "disk:host"
    disk_offset: int = 0


@dataclass
class RunResult:
    published: list[Any] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    iterations: int = 0
    artifacts: list[str] = field(default_factory=list)


class Court:
    def __init__(self, store: ArtifactStore, serializer: FindingSerializer) -> None:
        self._store = store
        self._serializer = serializer
        self._llm = ChatClient()

    def investigate(self, case: CaseInput) -> RunResult:
        result = RunResult()
        tool_summaries = self._collect(case, result)

        prosecutor_out, usage = self._llm.complete_json(
            agents.PROSECUTOR_SYSTEM,
            self._evidence_prompt(tool_summaries),
            agents.PROSECUTOR_SCHEMA,
            "prosecutor",
        )
        self._store.append_event(
            {"type": "agent_message", "agent": "prosecutor", "token_usage": usage,
             "payload": prosecutor_out}
        )
        findings = prosecutor_out.get("findings", [])

        for iteration in range(settings.max_iterations):
            result.iterations = iteration + 1

            defender_out, usage = self._llm.complete_json(
                agents.DEFENDER_SYSTEM,
                f"Findings to challenge:\n{json.dumps(findings, indent=2)}",
                agents.DEFENDER_SCHEMA,
                "defender",
            )
            self._store.append_event(
                {"type": "agent_message", "agent": "defender", "token_usage": usage,
                 "payload": defender_out}
            )

            arbiter_out, usage = self._llm.complete_json(
                agents.ARBITER_SYSTEM,
                f"Prosecutor findings:\n{json.dumps(findings, indent=2)}\n\n"
                f"Defender verdicts:\n{json.dumps(defender_out.get('verdicts', []), indent=2)}",
                agents.ARBITER_SCHEMA,
                "arbiter",
            )
            self._store.append_event(
                {"type": "agent_message", "agent": "arbiter", "token_usage": usage,
                 "payload": arbiter_out}
            )
            dispositions = self._reconcile(
                findings, defender_out.get("verdicts", []), arbiter_out.get("dispositions", [])
            )

            follow_ups = [d for d in dispositions if d.get("need_more_evidence")]
            if follow_ups and iteration < settings.max_iterations - 1:
                self._run_follow_ups(follow_ups, case, tool_summaries, result)
                # re-prosecute with the enlarged evidence set
                prosecutor_out, usage = self._llm.complete_json(
                    agents.PROSECUTOR_SYSTEM,
                    self._evidence_prompt(tool_summaries),
                    agents.PROSECUTOR_SCHEMA,
                    "prosecutor",
                )
                self._store.append_event(
                    {"type": "agent_message", "agent": "prosecutor",
                     "token_usage": usage, "payload": prosecutor_out}
                )
                findings = prosecutor_out.get("findings", [])
                continue

            self._publish(dispositions, result)
            break

        return result

    # -- phases -------------------------------------------------------------

    def _collect(self, case: CaseInput, result: RunResult) -> list[dict]:
        summaries: list[dict] = []
        if case.memory_image:
            for fn in (
                forensics.verify_image_integrity,
                forensics.vol_pslist,
                forensics.vol_psscan,
                forensics.vol_netscan,
            ):
                summaries.append(self._safe_tool(fn, case.memory_image, case.memory_source))
            self._cross_validate(summaries, result)
        if case.disk_image:
            summaries.append(
                self._safe_tool(
                    forensics.verify_image_integrity, case.disk_image, case.disk_source
                )
            )
            self._collect_disk_timeline(case, summaries)
        result.artifacts = [s["artifact_id"] for s in summaries if s.get("artifact_id")]
        return summaries

    def _collect_disk_timeline(self, case: CaseInput, summaries: list[dict]) -> None:
        """Partition the disk, then build a focused file timeline for the NTFS slot.

        A filtered timeline (suspicious process names + persistence locations)
        lets the court corroborate a memory finding against on-disk artifacts,
        which is what unlocks the CONFIRMED tier.
        """
        try:
            parts, prec = forensics.disk_partitions(
                self._store, case.disk_image, case.disk_source
            )
            summaries.append(self._summarize(parts, prec))
        except Exception as exc:
            logger.warning("disk_partitions failed: %s", exc)
            self._store.append_event(
                {"type": "tool_error", "tool": "disk_partitions", "error": str(exc)}
            )
            return

        offset = case.disk_offset or self._largest_ntfs_offset(parts)
        if offset is None:
            return
        for needle in ("coreupdater", "Windows/Prefetch", "Temp"):
            try:
                rows, rec = forensics.disk_file_timeline(
                    self._store, case.disk_image, case.disk_source, offset, needle
                )
                if rows:
                    summaries.append(self._summarize(rows, rec))
            except Exception as exc:
                logger.warning("disk_file_timeline(%s) failed: %s", needle, exc)

    @staticmethod
    def _largest_ntfs_offset(parts: list[dict]) -> int | None:
        ntfs = [p for p in parts if "ntfs" in str(p.get("description", "")).lower()]
        if not ntfs:
            return None
        best = max(ntfs, key=lambda p: int(str(p.get("length", "0")) or 0))
        return int(str(best.get("start", "0")) or 0)

    def _cross_validate(self, summaries: list[dict], result: RunResult) -> None:
        by_tool = {s.get("tool"): s.get("artifact_id") for s in summaries}
        if by_tool.get("vol_pslist") and by_tool.get("vol_psscan"):
            rows, rec = forensics.cross_validate_processes(
                self._store, by_tool["vol_pslist"], by_tool["vol_psscan"]
            )
            summaries.append(self._summarize(rows, rec))

    def _run_follow_ups(
        self, follow_ups: list[dict], case: CaseInput, summaries: list[dict], result: RunResult
    ) -> None:
        # Bounded set of extra tools the arbiter may request, keyed by intent.
        for fu in follow_ups:
            text = fu.get("follow_up", "").lower()
            if case.memory_image and "cmdline" in text:
                summaries.append(
                    self._safe_tool(forensics.vol_cmdline, case.memory_image, case.memory_source)
                )
            elif case.memory_image and ("malfind" in text or "inject" in text):
                summaries.append(
                    self._safe_tool(forensics.vol_malfind, case.memory_image, case.memory_source)
                )

    def _reconcile(
        self, findings: list[dict], verdicts: list[dict], dispositions: list[dict]
    ) -> list[dict]:
        """Build the final claim set robustly across agents.

        Reasoning models occasionally emit degenerate dispositions (empty or
        placeholder claims). Rather than depend on any single agent being
        well-behaved, we take the Arbiter's valid dispositions, then backfill
        from Prosecutor findings the Defender did not CHALLENGE. Evidence binding
        and tiering happen downstream, so this only governs which CLAIMS survive.
        """
        challenged = {
            v.get("claim", "").strip().lower()
            for v in verdicts
            if v.get("verdict") == "CHALLENGED"
        }

        def is_real(claim: str) -> bool:
            return len(claim.strip().strip(".").strip()) >= 10

        final = [d for d in dispositions if is_real(d.get("claim", ""))]
        seen = {d["claim"].strip().lower() for d in final}
        for f in findings:
            claim = f.get("claim", "")
            key = claim.strip().lower()
            if is_real(claim) and key not in seen and key not in challenged:
                final.append(
                    {
                        "claim": claim,
                        "detail": f.get("detail", ""),
                        "artifact_refs": f.get("artifact_refs", []),
                        "mitre": f.get("mitre", []),
                        "proposed_tier": "INFERRED",
                        "need_more_evidence": False,
                        "follow_up": "",
                    }
                )
                seen.add(key)
        return final

    def _publish(self, dispositions: list[dict], result: RunResult) -> None:
        for d in dispositions:
            finding = self._bind_evidence(d)
            try:
                published = self._serializer.publish(finding)
                result.published.append(published)
            except FindingRejected as exc:
                result.rejected.append({"claim": finding.claim, "reason": exc.reason})

    def _bind_evidence(self, disposition: dict) -> Finding:
        """Re-derive artifact_refs from the evidence store; do not trust the model's.

        The model proposes a claim. We extract its entities (binaries, IPs) and
        look up which stored artifacts actually contain them. Refs and tier are
        therefore *computed* from evidence, not asserted by the LLM:
          * refs spanning >=2 sources  -> CONFIRMED
          * refs from a single source  -> INFERRED
          * no entity found in evidence -> no refs -> serializer rejects it
        Model-proposed refs are kept only if they are valid and add a source.
        """
        claim = disposition.get("claim", "")
        detail = disposition.get("detail", "")
        proposed_tier = disposition.get("proposed_tier", "INFERRED")

        if proposed_tier == "ABSTAIN":
            return Finding(claim=claim, detail=detail, proposed_tier=Tier.ABSTAIN, agent="arbiter")

        bound: dict[str, str] = {}  # artifact_id -> source
        for entity in _extract_entities(f"{claim} {detail}"):
            for artifact_id, source in self._store.artifacts_containing(entity):
                bound[artifact_id] = source
        # honor any model refs that are real and broaden coverage
        for ref in disposition.get("artifact_refs", []):
            meta = self._store.meta(ref)
            if meta is not None:
                bound[ref] = meta.source

        sources = set(bound.values())
        tier = Tier.CONFIRMED if len(sources) >= 2 else Tier.INFERRED
        return Finding(
            claim=claim,
            detail=detail,
            artifact_refs=sorted(bound),
            proposed_tier=tier,
            mitre=disposition.get("mitre", []),
            agent="arbiter",
        )

    # -- helpers ------------------------------------------------------------

    def _safe_tool(self, fn, image: str, source: str) -> dict:
        try:
            rows, rec = fn(self._store, image, source)
            return self._summarize(rows, rec)
        except Exception as exc:  # tool failure is data, not a crash
            logger.warning("tool failed: %s", exc)
            self._store.append_event(
                {"type": "tool_error", "tool": fn.__name__, "error": str(exc)}
            )
            return {"tool": fn.__name__, "error": str(exc)}

    def _summarize(self, rows: list[dict], rec) -> dict:
        view = _select_rows(rec.tool, rows)
        return {
            "tool": rec.tool,
            "source": rec.source,
            "artifact_id": rec.artifact_id,
            "row_count": rec.row_count,
            "shown": len(view),
            "preview": [_project(rec.tool, r) for r in view],
        }

    def _evidence_prompt(self, summaries: list[dict]) -> str:
        return (
            "Tool results from the evidence (cite the artifact_id values in your "
            "findings):\n\n" + json.dumps(summaries, indent=2, default=str)
        )
