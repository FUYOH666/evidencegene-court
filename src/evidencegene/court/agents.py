"""Court roles: Prosecutor, Defender, Arbiter.

The adversarial structure is the self-correction mechanism: the Prosecutor
must convince a hostile Defender before the Arbiter publishes anything.
Agents only ever see bounded tool previews and artifact metadata — never
raw evidence dumps.
"""

PROSECUTOR_SYSTEM = """You are the PROSECUTOR in a digital forensics court.
Your job: find evidence of compromise in the tool results provided.
Rules (enforced by the system, not negotiable):
- Every claim MUST cite artifact_id values that appear in the tool results.
- Never invent PIDs, IPs, filenames, or timestamps. If the data does not show it, do not claim it.
- Prefer claims corroborated across BOTH memory and disk sources.
- Map claims to MITRE ATT&CK technique IDs only where you are certain.
Respond strictly in the requested JSON format."""

DEFENDER_SYSTEM = """You are the DEFENDER in a digital forensics court.
Your job: challenge each of the Prosecutor's findings with benign explanations.
For every finding decide one verdict:
- SUPPORTED: cited artifacts genuinely support the claim; no benign explanation fits.
- CHALLENGED: a plausible benign explanation exists, OR the cited artifacts do
  not actually show what is claimed (e.g. invented PID, wrong source).
Common benign explanations: psscan shows terminated-but-cached processes, signed
system binaries, admin tooling, expected service network listeners.
Respond strictly in the requested JSON format."""

ARBITER_SYSTEM = """You are the ARBITER in a digital forensics court.
You receive the Prosecutor's findings and the Defender's verdicts.

FIRST, correlate across evidence sources. If two or more findings concern the
SAME entity (same process name, PID, file, or IP) but are backed by artifacts
from DIFFERENT sources (e.g. one from memory:* and one from disk:*), MERGE them
into a SINGLE disposition whose artifact_refs include ALL of those artifact ids.
A claim corroborated by both memory and disk is the strongest evidence you can
produce — state it as one finding.

THEN, for each disposition:
- If supported and its artifact_refs span two different evidence sources
  (memory and disk), set proposed_tier CONFIRMED.
- If supported by a single source, set proposed_tier INFERRED.
- If the Defender CHALLENGED it: either request a specific follow-up tool call
  (set need_more_evidence true and describe the action), or, if unresolved,
  set proposed_tier ABSTAIN and state the open question.
- Never publish a claim without artifact_refs. Drop unsupported claims entirely.
Respond strictly in the requested JSON format."""


PROSECUTOR_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "claim": {"type": "string"},
                    "detail": {"type": "string"},
                    "artifact_refs": {"type": "array", "items": {"type": "string"}},
                    "mitre": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["claim", "detail", "artifact_refs", "mitre"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["findings"],
    "additionalProperties": False,
}

DEFENDER_SCHEMA = {
    "type": "object",
    "properties": {
        "verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "claim": {"type": "string"},
                    "verdict": {"type": "string", "enum": ["SUPPORTED", "CHALLENGED"]},
                    "benign_explanation": {"type": "string"},
                },
                "required": ["claim", "verdict", "benign_explanation"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["verdicts"],
    "additionalProperties": False,
}

ARBITER_SCHEMA = {
    "type": "object",
    "properties": {
        "dispositions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "claim": {"type": "string"},
                    "detail": {"type": "string"},
                    "artifact_refs": {"type": "array", "items": {"type": "string"}},
                    "mitre": {"type": "array", "items": {"type": "string"}},
                    "proposed_tier": {
                        "type": "string",
                        "enum": ["CONFIRMED", "INFERRED", "ABSTAIN"],
                    },
                    "need_more_evidence": {"type": "boolean"},
                    "follow_up": {"type": "string"},
                },
                "required": [
                    "claim",
                    "detail",
                    "artifact_refs",
                    "mitre",
                    "proposed_tier",
                    "need_more_evidence",
                    "follow_up",
                ],
                "additionalProperties": False,
            },
        }
    },
    "required": ["dispositions"],
    "additionalProperties": False,
}
