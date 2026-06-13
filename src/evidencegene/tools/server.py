"""sift-gene-mcp — typed, read-only MCP server over SIFT forensic tools.

Security boundary (architectural, not prompt-based):
  * no shell tool exists — the model cannot run arbitrary commands;
  * no write/delete tool exists — evidence spoliation is impossible on wire;
  * every tool records its full output as an artifact and returns only a
    bounded preview + ``artifact_id``, preventing context-window floods;
  * findings must cite those artifact ids (enforced by FindingSerializer).
"""

import logging

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from evidencegene.artifacts.store import ArtifactStore
from evidencegene.config import settings
from evidencegene.tools import forensics

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s evidencegene %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

mcp = FastMCP("sift-gene-mcp")

_STORE: ArtifactStore | None = None


def store() -> ArtifactStore:
    """Lazily create the artifact store so importing this module is side-effect-free.

    Introspecting the tool surface (e.g. the red-team spoliation check) must not
    create files; the store is only built when a tool actually runs.
    """
    global _STORE
    if _STORE is None:
        _STORE = ArtifactStore(settings.artifact_db, settings.audit_log)
    return _STORE


class ToolResult(BaseModel):
    """Bounded view of a tool execution. Full rows live in the artifact store."""

    artifact_id: str = Field(description="Cite this id in findings (artifact_refs)")
    tool: str
    source: str
    row_count: int
    payload_sha256: str
    preview: list[dict] = Field(description="First rows only; query the rest via artifact_query")


def _result(rows: list[dict], rec) -> ToolResult:
    return ToolResult(
        artifact_id=rec.artifact_id,
        tool=rec.tool,
        source=rec.source,
        row_count=rec.row_count,
        payload_sha256=rec.payload_sha256,
        preview=rows[: settings.preview_rows],
    )


@mcp.tool()
def verify_image_integrity(image_path: str, source: str) -> ToolResult:
    """Hash an evidence image (sha256/md5) for chain-of-custody. Run this first."""
    rows, rec = forensics.verify_image_integrity(store(), image_path, source)
    return _result(rows, rec)


@mcp.tool()
def vol_pslist(image_path: str, source: str) -> ToolResult:
    """Volatility3 windows.pslist — processes from the active process list."""
    rows, rec = forensics.vol_pslist(store(), image_path, source)
    return _result(rows, rec)


@mcp.tool()
def vol_psscan(image_path: str, source: str) -> ToolResult:
    """Volatility3 windows.psscan — pool-scanned processes (finds hidden/terminated)."""
    rows, rec = forensics.vol_psscan(store(), image_path, source)
    return _result(rows, rec)


@mcp.tool()
def vol_netscan(image_path: str, source: str) -> ToolResult:
    """Volatility3 windows.netscan — network connections and listeners from memory."""
    rows, rec = forensics.vol_netscan(store(), image_path, source)
    return _result(rows, rec)


@mcp.tool()
def vol_cmdline(image_path: str, source: str) -> ToolResult:
    """Volatility3 windows.cmdline — process command lines from memory."""
    rows, rec = forensics.vol_cmdline(store(), image_path, source)
    return _result(rows, rec)


@mcp.tool()
def vol_malfind(image_path: str, source: str) -> ToolResult:
    """Volatility3 windows.malfind — injected/suspicious executable memory regions."""
    rows, rec = forensics.vol_malfind(store(), image_path, source)
    return _result(rows, rec)


@mcp.tool()
def disk_partitions(image_path: str, source: str) -> ToolResult:
    """Sleuth Kit mmls — partition table of a disk image (E01/raw)."""
    rows, rec = forensics.disk_partitions(store(), image_path, source)
    return _result(rows, rec)


@mcp.tool()
def disk_file_timeline(
    image_path: str, source: str, sector_offset: int, path_filter: str = ""
) -> ToolResult:
    """Sleuth Kit fls — recursive file timeline from a partition (MACB timestamps).

    Use path_filter (substring) to focus, e.g. 'Windows/Prefetch' or 'Users'.
    """
    rows, rec = forensics.disk_file_timeline(
        store(), image_path, source, sector_offset, path_filter
    )
    return _result(rows, rec)


@mcp.tool()
def cross_validate_processes(pslist_artifact: str, psscan_artifact: str) -> ToolResult:
    """Compare pslist vs psscan artifacts; returns ghost processes (hidden candidates)."""
    rows, rec = forensics.cross_validate_processes(store(), pslist_artifact, psscan_artifact)
    return _result(rows, rec)


@mcp.tool()
def artifact_query(
    artifact_id: str, offset: int = 0, limit: int = 50, search: str = ""
) -> list[dict]:
    """Page through or search the full rows of a previously recorded artifact."""
    if search:
        return store().search_rows(artifact_id, search, limit)
    return store().rows(artifact_id, offset, limit)


@mcp.tool()
def verify_audit_chain() -> dict:
    """Replay the SHA-256 audit chain; proves the investigation log is untampered."""
    ok, count = store().verify_chain()
    return {"chain_valid": ok, "entries": count}


def main() -> None:
    logger.info("starting sift-gene-mcp (stdio)")
    mcp.run()


if __name__ == "__main__":
    main()
