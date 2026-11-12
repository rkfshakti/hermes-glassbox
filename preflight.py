"""Preflight for file tools: turn a hidden kernel denial into a clear message.

The Seatbelt kernel is the boundary. This hook is only a usability layer: some file
tools wrap reads in ``2>/dev/null`` and then report an empty file, which makes a
denied read look like a successful empty read. For the path-shaped tools we can do
better: resolve the requested path, compare it with the same policy the environment
uses, and return Hermes' documented ``block`` directive with an actionable message.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Mapping

from .policy import SandboxPolicy, build_policy

logger = logging.getLogger(__name__)

_FILE_TOOLS = frozenset({"read_file", "write_file", "patch", "search_files"})
_WRITE_TOOLS = frozenset({"write_file", "patch"})


def _resolve(path: str, *, base: Path) -> Path | None:
    try:
        candidate = Path(os.path.expanduser(path))
        if not candidate.is_absolute():
            candidate = base / candidate
        return Path(os.path.realpath(str(candidate)))
    except (OSError, ValueError):
        return None


def _under(path: Path, roots: tuple[Path, ...] | Path) -> bool:
    if isinstance(roots, Path):
        roots = (roots,)
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def is_blocked(path: Path, policy: SandboxPolicy, *, write: bool) -> bool:
    """True when *path* falls outside the same roots the Seatbelt profile allows."""
    if _under(path, policy.denied):
        return True
    if write:
        return not _under(path, policy.write_paths)
    if _under(path, policy.read_paths):
        return False
    # The profile keeps the system readable, but hides every user home and
    # external volume unless the workspace/allow-list re-allows a subtree.
    if not policy.allow_home and _under(path, policy.home):
        return True
    return _under(path, (Path("/Users"), Path("/Volumes"), Path("/Users/Shared")))


def _action_for(tool_name: str, args: Mapping[str, Any], policy: SandboxPolicy) -> dict[str, str] | None:
    if tool_name not in _FILE_TOOLS:
        return None
    raw = args.get("path") or args.get("file") or args.get("directory") or args.get("root")
    if not isinstance(raw, str) or not raw.strip():
        return None
    base = Path(os.getcwd())
    path = _resolve(raw, base=base)
    if path is None:
        return None
    write = tool_name in _WRITE_TOOLS
    if not is_blocked(path, policy, write=write):
        return None
    setting = "write_paths" if write else "read_paths"
    return {
        "action": "block",
        "message": (
            f"Glassbox blocked {tool_name} on {path}: it is outside the sandbox's "
            f"{'writable' if write else 'readable'} roots. The kernel would refuse it, "
            f"and this preflight prevents a masked error. If the access is legitimate, "
            f"ask the user to add the path with: hermes config set "
            f"plugins.entries.glassbox.settings.{setting} '[\"{path}\"]'. "
            f"Use glassbox_policy to inspect the current policy."
        ),
    }


def pre_tool_call(tool_name: str = "", args: dict | None = None,
                  task_id: str = "", session_id: str = "", **_: Any):
    """Hermes ``pre_tool_call`` hook; never raises and never approves anything."""
    try:
        from .cli import active_backend, data_dir, settings
        from .provider import resolve_workspace

        backend = active_backend()
        if backend != "glassbox":
            logger.debug("Glassbox preflight skipped: backend=%r tool=%s", backend, tool_name)
            return None
        workspace = resolve_workspace(os.getcwd())
        if workspace is None:
            # The environment will use a random empty scratch workspace; a policy
            # built from ~ would disagree with the kernel. Let the kernel decide.
            logger.debug("Glassbox preflight skipped: cwd is not a safe workspace")
            return None
        policy = build_policy(
            workspace,
            settings(),
            scratch=data_dir() / "preflight-scratch",
        )
        action = _action_for(tool_name, args or {}, policy)
        if action is not None:
            logger.info("Glassbox preflight blocked %s: %s", tool_name, args)
        return action
    except Exception:
        # A preflight bug must not block tool calls; the kernel still contains them.
        logger.debug("Glassbox preflight failed", exc_info=True)
        return None
