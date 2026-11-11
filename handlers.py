"""Tool implementations for Glassbox."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from .audit import AuditLog, summarize
from .policy import build_policy
from .verify import checks_ok, run_checks


def _dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _clamp(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def _active_backend() -> str:
    try:
        from hermes_cli.config import load_config_readonly

        config = load_config_readonly() or {}
        return str(((config.get("terminal") or {}).get("backend") or "")).strip()
    except Exception:
        return ""


def report(args: Mapping[str, Any], *, data_dir: Path, session_id: str = "") -> str:
    limit = _clamp(args.get("limit"), 50, 1, 500)
    requested_session = str(args.get("session_id") or session_id or "").strip()
    include_commands = bool(args.get("include_commands", True))
    audit = AuditLog(data_dir, enabled=True)
    entries = audit.read(limit=0)
    summary = summarize(entries, session_id=requested_session)
    recent = [e for e in entries if not requested_session or e.get("session_id") == requested_session][-limit:]
    if not include_commands:
        for entry in recent:
            entry.pop("command", None)
            entry.pop("excerpt", None)
    payload = {
        "ok": True,
        "audit_path": str(audit.path),
        "summary": summary,
        "recent": recent,
    }
    if not entries:
        payload["message"] = "No Glassbox commands have been recorded yet."
    return _dumps(payload)


def policy(args: Mapping[str, Any], *, data_dir: Path, settings: Mapping[str, Any]) -> str:
    cwd = str(args.get("cwd") or os.getcwd())
    scratch = Path(data_dir) / "policy-preview"
    built = build_policy(cwd, settings, scratch=scratch)
    return _dumps({
        "ok": True,
        "active_backend": _active_backend(),
        "policy": built.as_dict(),
        "profile": built.render(),
    })


def verify(args: Mapping[str, Any], *, data_dir: Path, settings: Mapping[str, Any]) -> str:
    checks = run_checks(data_dir=Path(data_dir), settings=dict(settings or {}))
    return _dumps({
        "ok": checks_ok(checks),
        "checks": checks,
        "note": "A pass means the kernel refused the canary and the network while allowing workspace work.",
    })
