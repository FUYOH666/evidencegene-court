"""Append-only artifact store with a SHA-256 hash-chained audit log.

Every forensic tool execution is recorded here. Findings may only cite
``artifact_id`` values that exist in this store — the FindingSerializer
rejects anything else at the API boundary. Tampering with the audit log
breaks chain verification.
"""

import hashlib
import json
import logging
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ArtifactRecord:
    artifact_id: str
    tool: str
    source: str  # evidence source identity, e.g. "memory:dc01" / "disk:dc01"
    created_at: str
    row_count: int
    payload_sha256: str


class ArtifactStore:
    """SQLite-backed artifact store + JSONL audit chain. Thread-safe, append-only."""

    def __init__(self, db_path: Path, audit_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._audit_path = audit_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS artifacts (
                artifact_id TEXT PRIMARY KEY,
                tool TEXT NOT NULL,
                source TEXT NOT NULL,
                args_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                row_count INTEGER NOT NULL,
                payload_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    # -- write path ---------------------------------------------------------

    def record(
        self,
        tool: str,
        source: str,
        args: dict[str, Any],
        rows: list[dict[str, Any]],
        token_usage: dict[str, int] | None = None,
    ) -> ArtifactRecord:
        """Persist a tool execution result and append it to the audit chain."""
        artifact_id = f"art-{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(UTC).isoformat()
        payload_json = _canonical(rows)
        payload_sha = _sha256(payload_json)
        with self._lock:
            self._conn.execute(
                "INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?)",
                (
                    artifact_id,
                    tool,
                    source,
                    _canonical(args),
                    created_at,
                    len(rows),
                    payload_sha,
                    payload_json,
                ),
            )
            self._conn.commit()
            self._append_audit(
                {
                    "type": "tool_execution",
                    "artifact_id": artifact_id,
                    "tool": tool,
                    "source": source,
                    "args": args,
                    "row_count": len(rows),
                    "payload_sha256": payload_sha,
                    "created_at": created_at,
                    "token_usage": token_usage or {},
                }
            )
        logger.info("artifact recorded", extra={"artifact_id": artifact_id, "tool": tool})
        return ArtifactRecord(artifact_id, tool, source, created_at, len(rows), payload_sha)

    def append_event(self, event: dict[str, Any]) -> None:
        """Append a non-tool event (agent message, verdict, rejection) to the chain."""
        with self._lock:
            self._append_audit(event)

    def _append_audit(self, body: dict[str, Any]) -> None:
        prev_hash = self._last_hash()
        seq = self._next_seq()
        entry = {
            "seq": seq,
            "ts": datetime.now(UTC).isoformat(),
            **body,
            "prev_hash": prev_hash,
        }
        entry["hash"] = _sha256(_canonical(entry))
        with self._audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")

    def _last_hash(self) -> str:
        if not self._audit_path.exists():
            return GENESIS_HASH
        last = None
        with self._audit_path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        return json.loads(last)["hash"] if last else GENESIS_HASH

    def _next_seq(self) -> int:
        if not self._audit_path.exists():
            return 0
        with self._audit_path.open(encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())

    # -- read path ----------------------------------------------------------

    def exists(self, artifact_id: str) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM artifacts WHERE artifact_id = ?", (artifact_id,)
        )
        return cur.fetchone() is not None

    def meta(self, artifact_id: str) -> ArtifactRecord | None:
        cur = self._conn.execute(
            "SELECT artifact_id, tool, source, created_at, row_count, payload_sha256 "
            "FROM artifacts WHERE artifact_id = ?",
            (artifact_id,),
        )
        row = cur.fetchone()
        return ArtifactRecord(*row) if row else None

    def rows(self, artifact_id: str, offset: int = 0, limit: int = 50) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT payload_json FROM artifacts WHERE artifact_id = ?", (artifact_id,)
        )
        row = cur.fetchone()
        if row is None:
            raise KeyError(f"unknown artifact: {artifact_id}")
        return json.loads(row[0])[offset : offset + limit]

    def search_rows(self, artifact_id: str, needle: str, limit: int = 50) -> list[dict[str, Any]]:
        needle_lower = needle.lower()
        matches = [
            r
            for r in self.rows(artifact_id, 0, 1_000_000)
            if needle_lower in _canonical(r).lower()
        ]
        return matches[:limit]

    def artifacts_containing(self, needle: str) -> list[tuple[str, str]]:
        """Return (artifact_id, source) for every artifact whose payload contains needle.

        This is how findings are *bound* to evidence: a claim about an entity is
        only publishable if that entity literally appears in stored tool output.
        """
        needle_lower = needle.lower()
        cur = self._conn.execute("SELECT artifact_id, source, payload_json FROM artifacts")
        out = []
        for artifact_id, source, payload in cur.fetchall():
            if needle_lower in payload.lower():
                out.append((artifact_id, source))
        return out

    # -- integrity ----------------------------------------------------------

    def verify_chain(self) -> tuple[bool, int]:
        """Replay the audit chain. Returns (ok, entries_checked)."""
        if not self._audit_path.exists():
            return True, 0
        prev = GENESIS_HASH
        count = 0
        with self._audit_path.open(encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                claimed = entry.pop("hash")
                if entry.get("prev_hash") != prev:
                    return False, count
                if _sha256(_canonical(entry)) != claimed:
                    return False, count
                prev = claimed
                count += 1
        return True, count
