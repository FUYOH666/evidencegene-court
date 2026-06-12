"""Typed forensic tool wrappers.

Each function: runs one read-only CLI, parses output into structured rows,
records the full result as an artifact, and returns (rows, ArtifactRecord).
The MCP layer returns only a summary + artifact_id to the model — full
data never floods the context window.
"""

import csv
import hashlib
import io
import json
import logging
from pathlib import Path
from typing import Any

from evidencegene.artifacts.store import ArtifactRecord, ArtifactStore
from evidencegene.config import settings
from evidencegene.tools.runner import run

logger = logging.getLogger(__name__)


# -- chain of custody ---------------------------------------------------------


def verify_image_integrity(
    store: ArtifactStore, image_path: str, source: str
) -> tuple[list[dict[str, Any]], ArtifactRecord]:
    path = Path(image_path)
    if not path.is_file():
        raise FileNotFoundError(image_path)
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024 * 8), b""):
            sha256.update(chunk)
            md5.update(chunk)
    rows = [
        {
            "path": str(path),
            "size_bytes": path.stat().st_size,
            "sha256": sha256.hexdigest(),
            "md5": md5.hexdigest(),
        }
    ]
    rec = store.record("verify_image_integrity", source, {"image_path": image_path}, rows)
    return rows, rec


# -- volatility 3 (memory) ----------------------------------------------------


def _vol(plugin: str, image_path: str, extra: list[str] | None = None) -> list[dict[str, Any]]:
    argv = [settings.vol_cmd, "-q", "-r", "json", "-f", image_path, plugin, *(extra or [])]
    out = run(argv)
    # vol -r json prints a JSON array (possibly after warnings on stderr)
    start = out.find("[")
    if start == -1:
        raise ValueError(f"no JSON output from volatility plugin {plugin}")
    return json.loads(out[start:])


def vol_pslist(
    store: ArtifactStore, image_path: str, source: str
) -> tuple[list[dict[str, Any]], ArtifactRecord]:
    rows = _vol("windows.pslist.PsList", image_path)
    rec = store.record("vol_pslist", source, {"image_path": image_path}, rows)
    return rows, rec


def vol_psscan(
    store: ArtifactStore, image_path: str, source: str
) -> tuple[list[dict[str, Any]], ArtifactRecord]:
    rows = _vol("windows.psscan.PsScan", image_path)
    rec = store.record("vol_psscan", source, {"image_path": image_path}, rows)
    return rows, rec


def vol_netscan(
    store: ArtifactStore, image_path: str, source: str
) -> tuple[list[dict[str, Any]], ArtifactRecord]:
    rows = _vol("windows.netscan.NetScan", image_path)
    rec = store.record("vol_netscan", source, {"image_path": image_path}, rows)
    return rows, rec


def vol_cmdline(
    store: ArtifactStore, image_path: str, source: str
) -> tuple[list[dict[str, Any]], ArtifactRecord]:
    rows = _vol("windows.cmdline.CmdLine", image_path)
    rec = store.record("vol_cmdline", source, {"image_path": image_path}, rows)
    return rows, rec


def vol_malfind(
    store: ArtifactStore, image_path: str, source: str
) -> tuple[list[dict[str, Any]], ArtifactRecord]:
    rows = _vol("windows.malfind.Malfind", image_path)
    # drop raw hexdumps — keep metadata only, full row text stays in artifact
    slim = [{k: v for k, v in r.items() if k not in ("Hexdump", "Disasm")} for r in rows]
    rec = store.record("vol_malfind", source, {"image_path": image_path}, slim)
    return slim, rec


# -- sleuth kit (disk) --------------------------------------------------------


def disk_partitions(
    store: ArtifactStore, image_path: str, source: str
) -> tuple[list[dict[str, Any]], ArtifactRecord]:
    out = run([settings.mmls_cmd, image_path])
    rows: list[dict[str, Any]] = []
    for line in out.splitlines():
        parts = line.split(None, 5)
        if len(parts) == 6 and parts[0].rstrip(":").isdigit():
            rows.append(
                {
                    "slot": parts[0].rstrip(":"),
                    "start": parts[2],
                    "end": parts[3],
                    "length": parts[4],
                    "description": parts[5],
                }
            )
    rec = store.record("disk_partitions", source, {"image_path": image_path}, rows)
    return rows, rec


def disk_file_timeline(
    store: ArtifactStore,
    image_path: str,
    source: str,
    sector_offset: int,
    path_filter: str = "",
    max_rows: int = 5000,
) -> tuple[list[dict[str, Any]], ArtifactRecord]:
    """Bodyfile-style timeline of filesystem entries via fls -m."""
    out = run(
        [settings.fls_cmd, "-r", "-m", "/", "-o", str(sector_offset), image_path]
    )
    reader = csv.reader(io.StringIO(out), delimiter="|")
    rows = []
    for parts in reader:
        if len(parts) < 8:
            continue
        name = parts[1]
        if path_filter and path_filter.lower() not in name.lower():
            continue
        rows.append(
            {
                "name": name,
                "inode": parts[2],
                "mode": parts[3],
                "size": parts[6],
                "atime": parts[7] if len(parts) > 7 else "",
                "mtime": parts[8] if len(parts) > 8 else "",
                "ctime": parts[9] if len(parts) > 9 else "",
                "crtime": parts[10] if len(parts) > 10 else "",
            }
        )
        if len(rows) >= max_rows:
            break
    rec = store.record(
        "disk_file_timeline",
        source,
        {"image_path": image_path, "offset": sector_offset, "filter": path_filter},
        rows,
    )
    return rows, rec


# -- cross-source validation --------------------------------------------------


def cross_validate_processes(
    store: ArtifactStore, pslist_artifact: str, psscan_artifact: str
) -> tuple[list[dict[str, Any]], ArtifactRecord]:
    """Ghost-process detector: PIDs present in psscan but absent from pslist."""
    pslist = store.rows(pslist_artifact, 0, 1_000_000)
    psscan = store.rows(psscan_artifact, 0, 1_000_000)
    listed = {r.get("PID") for r in pslist}
    rows = [
        {
            "PID": r.get("PID"),
            "ImageFileName": r.get("ImageFileName"),
            "PPID": r.get("PPID"),
            "CreateTime": r.get("CreateTime"),
            "anomaly": "present_in_psscan_missing_from_pslist",
        }
        for r in psscan
        if r.get("PID") not in listed
    ]
    rec = store.record(
        "cross_validate_processes",
        "derived:memory",
        {"pslist_artifact": pslist_artifact, "psscan_artifact": psscan_artifact},
        rows,
    )
    return rows, rec
