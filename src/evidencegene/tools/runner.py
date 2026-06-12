"""Subprocess runner for forensic CLIs.

Read-only invariant: this module only ever *reads* evidence. No wrapper
accepts a free-form command string — argv lists are built by typed
functions, so shell injection and destructive commands are impossible
by construction.
"""

import logging
import subprocess

from evidencegene.config import settings

logger = logging.getLogger(__name__)


class ToolExecutionError(Exception):
    pass


def run(argv: list[str], timeout: float | None = None) -> str:
    timeout = timeout or settings.tool_timeout
    logger.info("exec", extra={"argv": argv})
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolExecutionError(f"tool not installed: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolExecutionError(f"tool timed out after {timeout}s: {argv[0]}") from exc
    if proc.returncode != 0 and not proc.stdout.strip():
        raise ToolExecutionError(
            f"{argv[0]} exited {proc.returncode}: {proc.stderr.strip()[:500]}"
        )
    return proc.stdout
