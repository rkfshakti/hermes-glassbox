"""Glassbox — a contained, auditable terminal backend for macOS.

Registers a Hermes terminal-environment provider (``terminal.backend: glassbox``),
three inspection tools, a ``/glassbox`` slash command, ``hermes glassbox``, and a
bundled skill. The security boundary is macOS Seatbelt: every terminal and file-tool
command runs under a generated ``sandbox-exec`` profile. The plugin also records what
the kernel refused so a blocked command is explainable instead of mysterious.

Imports are deliberately lazy: this file stays importable without a Hermes install so
the policy/audit unit tests can run standalone and a broken optional dependency cannot
take down plugin discovery.
"""

from __future__ import annotations

import logging
import os
import shlex
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_PLUGIN_DIR = Path(__file__).parent
_SKILL = _PLUGIN_DIR / "skills" / "glassbox" / "SKILL.md"


def _prune_stale_sandboxes(root: Path, max_age_hours: float = 24.0) -> None:
    """Remove sandbox directories a crashed session left behind."""
    cutoff = time.time() - max_age_hours * 3600
    try:
        children = list((root / "sandboxes").iterdir())
    except OSError:
        return
    for child in children:
        try:
            if child.is_dir() and child.stat().st_mtime < cutoff:
                import shutil

                shutil.rmtree(child, ignore_errors=True)
        except OSError:
            continue


def _slash(raw_args: str, **kwargs) -> str:
    """Handle ``/glassbox [status|verify|report|profile]`` inside a session."""
    from .audit import AuditLog, render_text
    from .cli import data_dir as _data_dir, settings as read_settings
    from .policy import build_policy
    from .verify import checks_ok, run_checks

    try:
        parts = shlex.split(raw_args or "")
    except ValueError:
        parts = (raw_args or "").split()
    sub = (parts[0] if parts else "status").lower()
    data = _data_dir()
    if sub == "status":
        backend = ""
        try:
            from hermes_cli.config import load_config_readonly

            backend = str((((load_config_readonly() or {}).get("terminal") or {}).get("backend") or ""))
        except Exception:
            pass
        audit = AuditLog(data, enabled=True)
        entries = audit.read(limit=0)
        blocked = sum(1 for entry in entries if entry.get("denied_paths") or entry.get("network_denied"))
        return (
            "Glassbox\n"
            f"  platform: macOS Seatbelt ({'/usr/bin/sandbox-exec'})\n"
            f"  backend: {backend or '(unset)'}\n"
            f"  audit: {len(entries)} commands, {blocked} blocked\n"
            f"  data: {data}"
        )
    if sub == "verify":
        checks = run_checks(data_dir=data, settings=read_settings())
        lines = ["Glassbox containment self-test"]
        for item in checks:
            lines.append(f"  {'✓' if item.get('ok') else '✗'} {item['name']}: {item.get('detail', '')}")
        lines.append("PASS" if checks_ok(checks) else "FAIL")
        return "\n".join(lines)
    if sub == "report":
        entries = AuditLog(data, enabled=True).read(limit=0)
        return render_text(entries, limit=20)
    if sub == "profile":
        cwd = parts[1] if len(parts) > 1 else os.getcwd()
        return build_policy(cwd, read_settings(), scratch=data / "policy-preview").render()
    return "usage: /glassbox [status|verify|report|profile [cwd]]"


def register(ctx) -> None:
    """Wire the provider, tools, commands and skill into Hermes."""
    from . import handlers, schemas
    from .cli import (
        data_dir as _default_data_dir,
        glassbox_command,
        register_cli,
        settings as read_settings,
    )
    from .provider import GlassboxProvider
    from .preflight import pre_tool_call

    data = Path(_default_data_dir())
    _prune_stale_sandboxes(data)

    provider = GlassboxProvider(settings=read_settings, data_dir=data)
    ctx.register_terminal_environment_provider(provider)
    ctx.register_hook("pre_tool_call", pre_tool_call)

    def _report_tool(args, **kwargs):
        # The audit's session id is the terminal task id, not the chat session id;
        # filtering by the chat id would hide every entry. Only filter when the
        # caller explicitly asks for a session.
        return handlers.report(args, data_dir=data, session_id="")

    def _policy_tool(args, **kwargs):
        return handlers.policy(args, data_dir=data, settings=read_settings())

    def _verify_tool(args, **kwargs):
        return handlers.verify(args, data_dir=data, settings=read_settings())

    ctx.register_tool(
        name="glassbox_report",
        toolset="glassbox",
        schema=schemas.GLASSBOX_REPORT,
        handler=_report_tool,
        emoji="🛡️",
    )
    ctx.register_tool(
        name="glassbox_policy",
        toolset="glassbox",
        schema=schemas.GLASSBOX_POLICY,
        handler=_policy_tool,
        emoji="📜",
    )
    ctx.register_tool(
        name="glassbox_verify",
        toolset="glassbox",
        schema=schemas.GLASSBOX_VERIFY,
        handler=_verify_tool,
        emoji="✅",
    )

    ctx.register_command(
        "glassbox",
        handler=_slash,
        description="Inspect the Glassbox sandbox, audit log and containment self-test.",
        args_hint="status|verify|report|profile",
    )
    ctx.register_cli_command(
        name="glassbox",
        help="Contained, auditable macOS terminal backend",
        setup_fn=register_cli,
        handler_fn=glassbox_command,
        description=(
            "Inspect and verify the Glassbox terminal backend: status, containment "
            "self-test, audit report (text or HTML), generated Seatbelt profile, and demo."
        ),
    )

    try:
        if _SKILL.exists():
            ctx.register_skill("glassbox", _SKILL)
    except Exception:
        logger.debug("Glassbox skill registration failed", exc_info=True)
