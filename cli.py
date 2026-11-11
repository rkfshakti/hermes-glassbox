"""``hermes glassbox`` CLI: status, verify, report, profile, demo, clear."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Mapping

from .audit import AuditLog, render_html, render_text, summarize
from .policy import build_policy
from .provider import GlassboxEnvironment, SANDBOX_EXEC
from .verify import checks_ok, run_checks

_ANSI = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _ANSI else text


def _ok(text: str) -> str:
    return _c("32", text)


def _bad(text: str) -> str:
    return _c("31", text)


def _dim(text: str) -> str:
    return _c("2", text)


def _bold(text: str) -> str:
    return _c("1", text)


def data_dir() -> Path:
    """The profile-scoped plugin data directory."""
    try:
        from plugins.plugin_storage import plugin_data_dir

        return Path(plugin_data_dir("glassbox"))
    except Exception:
        return Path.home() / ".hermes" / "plugin-data" / "glassbox"


def settings() -> dict[str, Any]:
    """Read this plugin's settings without requiring the plugin to be active."""
    try:
        from hermes_cli.config import load_config_readonly

        config = load_config_readonly() or {}
        entries = (config.get("plugins") or {}).get("entries") or {}
        return dict((entries.get("glassbox") or {}).get("settings") or {})
    except Exception:
        return {}


def active_backend() -> str:
    try:
        from hermes_cli.config import load_config_readonly

        config = load_config_readonly() or {}
        return str(((config.get("terminal") or {}).get("backend") or "")).strip()
    except Exception:
        return ""


def enabled() -> bool:
    try:
        from hermes_cli.config import load_config_readonly

        config = load_config_readonly() or {}
        enabled_list = (config.get("plugins") or {}).get("enabled") or []
        return any(str(item).split("/")[-1] == "glassbox" for item in enabled_list)
    except Exception:
        return False


def _last_line(text: str, limit: int = 160) -> str:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    if not lines:
        return "no output"
    return lines[-1][:limit]


def _status_payload() -> dict[str, Any]:
    audit = AuditLog(data_dir(), enabled=True)
    entries = audit.read(limit=0)
    summary = summarize(entries)
    return {
        "platform": sys.platform,
        "sandbox_exec": SANDBOX_EXEC,
        "sandbox_exec_present": Path(SANDBOX_EXEC).exists(),
        "active_backend": active_backend(),
        "plugin_enabled": enabled(),
        "data_dir": str(data_dir()),
        "audit_path": str(audit.path),
        "commands": summary["total_commands"],
        "blocked_commands": summary["blocked_commands"],
        "network_blocked": summary["network_blocked"],
    }


def _cmd_status(args: argparse.Namespace) -> int:
    payload = _status_payload()
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2))
        return 0
    ready = payload["platform"] == "darwin" and payload["sandbox_exec_present"]
    print(_bold("Glassbox"))
    print("────────")
    print(f"  Platform       {payload['platform']}")
    print(f"  Seatbelt       {SANDBOX_EXEC} {'✓' if payload['sandbox_exec_present'] else '✗'}")
    print(f"  Plugin         {'enabled' if payload['plugin_enabled'] else 'not enabled'}")
    backend = payload["active_backend"] or "(unset)"
    marker = "✓" if backend == "glassbox" else "•"
    print(f"  Backend        {marker} {backend}")
    print(f"  Audit          {payload['commands']} commands, {payload['blocked_commands']} blocked")
    print(f"  Data           {payload['data_dir']}")
    if not ready:
        print()
        print(_bad("Glassbox is macOS-only and needs /usr/bin/sandbox-exec."))
        return 1
    if backend != "glassbox":
        print()
        print(_dim("Activate it with: hermes config set terminal.backend glassbox"))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    checks = run_checks(data_dir=data_dir(), settings=settings())
    ok = checks_ok(checks)
    if getattr(args, "json", False):
        print(json.dumps({"ok": ok, "checks": checks}, indent=2))
        return 0 if ok else 1
    print(_bold("Glassbox containment self-test"))
    print("────────────────────────────────")
    for item in checks:
        mark = _ok("✓") if item.get("ok") else _bad("✗")
        skipped = " (skipped)" if item.get("skipped") else ""
        print(f"  {mark} {item['name']:<24}{skipped}  {_dim(str(item.get('detail', ''))[:110])}")
    print()
    if ok:
        print(_ok("All checks passed: the sandbox is containing commands."))
        return 0
    print(_bad("One or more checks failed. Run `hermes glassbox status` and inspect the profile."))
    return 1


def _cmd_report(args: argparse.Namespace) -> int:
    audit = AuditLog(data_dir(), enabled=True)
    entries = audit.read(limit=0)
    session = str(getattr(args, "session", "") or "")
    if getattr(args, "json", False):
        selected = [e for e in entries if not session or e.get("session_id") == session]
        print(json.dumps({"summary": summarize(selected), "entries": selected[-args.limit:]}, indent=2))
        return 0
    if not entries:
        print("No Glassbox audit entries yet. Commands appear here once the backend is active.")
        return 0
    print(render_text(entries, session_id=session, limit=args.limit))
    if getattr(args, "html", None) is not None:
        content = render_html(entries, session_id=session)
        target = getattr(args, "html", None)
        if target in (None, ""):
            stamp = time.strftime("%Y%m%d-%H%M%S")
            target_path = data_dir() / "reports" / f"glassbox-{stamp}.html"
        else:
            target_path = Path(str(target)).expanduser()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(content, encoding="utf-8")
        print()
        print(f"HTML report: {target_path}")
        if getattr(args, "open", False):
            subprocess.run(["open", str(target_path)], check=False)
    return 0


def _cmd_profile(args: argparse.Namespace) -> int:
    built = build_policy(args.cwd or os.getcwd(), settings(), scratch=data_dir() / "policy-preview")
    if getattr(args, "json", False):
        print(json.dumps(built.as_dict(), indent=2))
        return 0
    print(built.render())
    return 0


def _cmd_clear(args: argparse.Namespace) -> int:
    if not getattr(args, "yes", False):
        answer = input("Delete all Glassbox audit entries for this profile? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("Cancelled.")
            return 1
    count = AuditLog(data_dir(), enabled=True).clear()
    print(f"Removed {count} audit entr{'y' if count == 1 else 'ies'}.")
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    data = data_dir()
    workspace = Path(tempfile.mkdtemp(prefix="glassbox-demo-"))
    home = Path.home()
    canary = home / f".glassbox-demo-{uuid.uuid4().hex[:8]}"
    write_target = home / f".glassbox-demo-write-{uuid.uuid4().hex[:8]}"
    canary.write_text("demo-secret", encoding="utf-8")
    env = GlassboxEnvironment(
        workspace=workspace,
        timeout=20,
        task_id=f"glassbox-demo-{uuid.uuid4().hex[:8]}",
        settings={
            "network": False,
            "allow_home": False,
            "workspace_writable": True,
            "audit": True,
            "deny_paths": [],
        },
        data_dir=data,
    )
    script = [
        ("write inside the workspace", "printf 'hello from the glass box\\n' > notes.txt", True),
        ("read it back", "cat notes.txt", True),
        ("read a file from home", f"cat {canary}", False),
        ("write outside the workspace", f"printf nope > {write_target}", False),
        ("reach the network", "curl -sS --max-time 2 https://example.com -o /dev/null", False),
        ("spawn a child that tries the same read", f"bash -c 'cat {canary}'", False),
    ]
    results: list[dict[str, Any]] = []
    if not getattr(args, "json", False):
        print(_bold("Glassbox demo"))
        print(f"workspace  {workspace}")
        print(f"home       {home} (hidden)")
        print()
    try:
        for label, command, should_pass in script:
            result = env.execute(command)
            exit_code = result.get("returncode")
            output = (result.get("output") or "").strip()
            passed = exit_code == 0
            expected = passed if should_pass else not passed
            results.append({
                "label": label,
                "command": command,
                "exit_code": exit_code,
                "expected": should_pass,
                "blocked": not passed,
                "ok": expected,
                "output": _last_line(output),
            })
            if not getattr(args, "json", False):
                if should_pass:
                    mark = _ok("✓") if expected else _bad("✗")
                else:
                    mark = _bad("⛔") if expected else _bad("✗")
                detail = _last_line(output, 90) if output else ("exit 0" if passed else f"exit {exit_code}")
                print(f"  {mark} {label:<44} {_dim(detail)}")
        if not getattr(args, "json", False):
            summary = summarize(env.audit.read(limit=0), session_id=env.task_id)
            print()
            print(_ok(f"{summary['total_commands']} commands ran; {summary['blocked_commands']} were blocked as expected."))
            print(_dim("Report: hermes glassbox report --html"))
    finally:
        try:
            env.cleanup()
        except Exception:
            pass
        for path in (canary, write_target):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        import shutil

        shutil.rmtree(workspace, ignore_errors=True)
    if getattr(args, "json", False):
        print(json.dumps({"ok": all(r["ok"] for r in results), "results": results}, indent=2))
        return 0 if all(r["ok"] for r in results) else 1
    return 0 if all(r["ok"] for r in results) else 1


def register_cli(subparser: argparse.ArgumentParser) -> None:
    """Build the ``hermes glassbox`` argparse tree."""
    subs = subparser.add_subparsers(dest="glassbox_command")
    p = {
        "status": subs.add_parser("status", help="Show backend, plugin and audit status"),
        "verify": subs.add_parser("verify", help="Run the containment self-test"),
        "report": subs.add_parser("report", help="Show the audit log or write an HTML report"),
        "profile": subs.add_parser("profile", help="Print the generated Seatbelt profile"),
        "demo": subs.add_parser("demo", help="Run a short allowed/blocked demonstration"),
        "clear": subs.add_parser("clear", help="Delete this profile's audit log"),
    }
    p["status"].add_argument("--json", action="store_true")
    p["verify"].add_argument("--json", action="store_true")
    p["report"].add_argument("--limit", type=int, default=20, help="Recent commands to show (default 20)")
    p["report"].add_argument("--session", default="", help="Filter by session id")
    p["report"].add_argument("--json", action="store_true")
    p["report"].add_argument("--html", nargs="?", const="", default=None,
                             help="Write a self-contained HTML report (optional path)")
    p["report"].add_argument("--open", action="store_true", help="Open the HTML report after writing it")
    p["profile"].add_argument("--cwd", default="", help="Directory to build the profile for")
    p["profile"].add_argument("--json", action="store_true")
    p["demo"].add_argument("--json", action="store_true")
    p["clear"].add_argument("--yes", "-y", action="store_true")
    subparser.set_defaults(func=glassbox_command)


_DISPATCH = {
    "status": _cmd_status,
    "verify": _cmd_verify,
    "report": _cmd_report,
    "profile": _cmd_profile,
    "demo": _cmd_demo,
    "clear": _cmd_clear,
}


def glassbox_command(args: argparse.Namespace) -> int:
    sub = getattr(args, "glassbox_command", None)
    if not sub:
        print("usage: hermes glassbox {status,verify,report,profile,demo,clear}")
        return 2
    handler = _DISPATCH.get(sub)
    if handler is None:
        print(f"unknown subcommand: {sub}")
        return 2
    return int(handler(args) or 0)
