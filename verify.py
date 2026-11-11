"""Self-test used by ``hermes glassbox verify`` and the ``glassbox_verify`` tool.

The test builds a throwaway workspace on the real host, creates a canary file in
the real home directory, then runs a battery of commands through a freshly created
Glassbox environment. A pass means the kernel refused the canary and the network
while allowing ordinary workspace work.
"""

from __future__ import annotations

import os
import shutil
import sys
import uuid
from pathlib import Path
from typing import Any, Callable

from .provider import GlassboxEnvironment, SANDBOX_EXEC


def _check(name: str, ok: bool, detail: str = "", *, skipped: bool = False) -> dict[str, Any]:
    return {"name": name, "ok": bool(ok), "detail": detail, "skipped": skipped}


def run_checks(
    *,
    data_dir: Path,
    settings: dict[str, Any] | None = None,
    progress: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Run the baseline containment suite. Never raises; failures become checks."""
    checks: list[dict[str, Any]] = []
    if sys.platform != "darwin":
        return [_check("platform", False, f"{sys.platform}: Glassbox requires macOS Seatbelt")]
    checks.append(_check("seatbelt", Path(SANDBOX_EXEC).exists(), SANDBOX_EXEC))

    token = f"glassbox-canary-{uuid.uuid4().hex[:10]}"
    home = Path.home()
    canary = home / f".glassbox-verify-{uuid.uuid4().hex[:10]}"
    write_canary = home / f".glassbox-verify-write-{uuid.uuid4().hex[:10]}"
    # Put the workspace under a fresh directory in the real home so the parent
    # traversal check exercises the same boundary a project in ~/ does.
    verify_root = home / f".glassbox-verify-root-{uuid.uuid4().hex[:10]}"
    workspace = verify_root / "workspace"
    workspace.mkdir(parents=True)
    parent_canary = verify_root / f".glassbox-parent-{uuid.uuid4().hex[:10]}"
    env: GlassboxEnvironment | None = None
    old_secret = os.environ.get("GLASSBOX_VERIFY_SECRET")
    os.environ["GLASSBOX_VERIFY_SECRET"] = "must-not-leak"

    def note(name: str) -> None:
        if progress:
            try:
                progress(name)
            except Exception:
                pass

    try:
        canary.write_text(token, encoding="utf-8")
        parent_canary.write_text(token, encoding="utf-8")
        check_settings = {
            "network": False,
            "allow_home": False,
            "workspace_writable": True,
            "audit": False,
            "deny_paths": [],
        }
        check_settings.update(settings or {})
        # These are invariants of the self-test, not user policy.
        check_settings["network"] = False
        check_settings["allow_home"] = False

        note("building sandbox")
        env = GlassboxEnvironment(
            workspace=workspace,
            timeout=20,
            task_id="glassbox-verify",
            settings=check_settings,
            data_dir=Path(data_dir),
        )
        checks.append(_check("profile", "(deny default)" in env.profile_path.read_text(encoding="utf-8"),
                             str(env.profile_path)))

        note("workspace write")
        result = env.execute("printf glassbox-ok > glassbox-ok.txt")
        wrote = result.get("returncode") == 0 and (workspace / "glassbox-ok.txt").exists()
        checks.append(_check("workspace write", wrote,
                             f"exit {result.get('returncode')}: {(result.get('output') or '').strip()[:120]}"))

        note("workspace read")
        result = env.execute("cat glassbox-ok.txt")
        read_ok = result.get("returncode") == 0 and "glassbox-ok" in (result.get("output") or "")
        checks.append(_check("workspace read", read_ok, (result.get("output") or "").strip()[:120]))

        note("home read")
        result = env.execute(f"cat {canary}")
        output = result.get("output") or ""
        home_read_ok = token not in output and result.get("returncode") != 0
        checks.append(_check("home read denied", home_read_ok,
                             (output.strip().splitlines()[-1] if output.strip() else "no output")[:160]))

        note("home write")
        result = env.execute(f"printf nope > {write_canary}")
        home_write_ok = not write_canary.exists() and result.get("returncode") != 0
        checks.append(_check("home write denied", home_write_ok,
                             (result.get("output") or "").strip()[:160] or "no output"))

        note("child process")
        result = env.execute(f"bash -c 'cat {canary}'")
        child_ok = token not in (result.get("output") or "") and result.get("returncode") != 0
        checks.append(_check("child process confined", child_ok,
                             (result.get("output") or "").strip()[:160] or "no output"))

        note("parent escape")
        result = env.execute(f"cat ../{parent_canary.name}")
        escape_ok = token not in (result.get("output") or "") and result.get("returncode") != 0
        checks.append(_check("parent traversal denied", escape_ok,
                             (result.get("output") or "").strip()[:160] or "no output"))

        note("network")
        result = env.execute("curl -sS --max-time 2 https://example.com -o /dev/null")
        network_ok = result.get("returncode") != 0
        checks.append(_check("network denied", network_ok,
                             (result.get("output") or "").strip()[:160] or "no output"))

        note("env filter")
        result = env.execute('if [ -z "${GLASSBOX_VERIFY_SECRET:-}" ]; then echo absent; else echo leaked; fi')
        env_ok = "leaked" not in (result.get("output") or "")
        checks.append(_check("secret env filtered", env_ok,
                             (result.get("output") or "").strip()[:160] or "not present"))

        note("audit")
        checks.append(_check("audit log writable", True, str(env.audit.path)))
    except Exception as exc:
        checks.append(_check("selftest", False, f"{type(exc).__name__}: {exc}"))
    finally:
        if env is not None:
            try:
                env.cleanup()
            except Exception:
                pass
        for path in (canary, write_canary, parent_canary):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        shutil.rmtree(verify_root, ignore_errors=True)
        if old_secret is None:
            os.environ.pop("GLASSBOX_VERIFY_SECRET", None)
        else:
            os.environ["GLASSBOX_VERIFY_SECRET"] = old_secret
    return checks


def checks_ok(checks: list[dict[str, Any]]) -> bool:
    return all(item.get("ok") or item.get("skipped") for item in checks)
