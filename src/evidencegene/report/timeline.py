"""Order findings into a MITRE ATT&CK kill-chain timeline.

Findings are sorted by ATT&CK tactic order (inferred from their technique IDs),
then by any timestamp parsed from the claim/detail text. Pure logic, no LLM.
"""

import re
from dataclasses import dataclass

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Minimal ATT&CK technique -> tactic map for the techniques we commonly emit.
# Extend as new techniques appear; unknown techniques sort to the end.
_TECHNIQUE_TACTIC = {
    "T1071": "command-and-control",
    "T1071.001": "command-and-control",
    "T1059": "execution",
    "T1543": "persistence",
    "T1547": "persistence",
    "T1055": "defense-evasion",
    "T1003": "credential-access",
    "T1021": "lateral-movement",
    "T1041": "exfiltration",
    "T1190": "initial-access",
    "T1078": "initial-access",
}

_RE_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


@dataclass
class TimelineEvent:
    order: int
    tactic: str
    technique: str
    timestamp: str
    tier: str
    claim: str


def _tactic_for(mitre: list[str]) -> tuple[int, str, str]:
    for tech in mitre:
        tactic = _TECHNIQUE_TACTIC.get(tech) or _TECHNIQUE_TACTIC.get(tech.split(".")[0])
        if tactic:
            return TACTIC_ORDER.index(tactic), tactic, tech
    return len(TACTIC_ORDER), "unmapped", (mitre[0] if mitre else "")


def _first_timestamp(text: str) -> str:
    m = _RE_TS.search(text)
    return m.group(0) if m else ""


def build_timeline(published_findings) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for f in published_findings:
        order, tactic, technique = _tactic_for(getattr(f, "mitre", []) or [])
        ts = _first_timestamp(f"{f.claim} {getattr(f, 'detail', '')}")
        events.append(
            TimelineEvent(
                order=order,
                tactic=tactic,
                technique=technique,
                timestamp=ts,
                tier=str(f.tier),
                claim=f.claim,
            )
        )
    events.sort(key=lambda e: (e.order, e.timestamp or "9999", e.claim))
    return events
