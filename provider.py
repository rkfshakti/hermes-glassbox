"""The Glassbox terminal backend: a macOS Seatbelt environment for Hermes.

Hermes talks to a terminal backend through a small duck-typed object. We subclass
``BaseEnvironment`` to inherit its process/timeout/CWD plumbing, but spawn every
command under ``sandbox-exec`` with a generated profile and a filtered environment.
"""

from __future__ import annotations

import functools
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping

from agent.terminal_env_provider import TerminalEnvironmentProvider
from tools.environments.base import BaseEnvironment

from .audit import AuditLog, extract_denied_paths
from .policy import (
    SECRET_ENV_MARKERS,
    SandboxPolicy,
    build_policy,
    prepare_scratch,
    safe_child_env,
)

logger = logging.getLogger(__name__)

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
BASH = "/bin/bash"
_BACKEND_LABEL = "glassbox"

# A launch directory at a system root would turn the whole root into the writable
# workspace. Fall back to the user's home; the secret-store deny list still applies.
_UNSAFE_WORKSPACES = frozenset({
    Path("/"), Path("/Users"), Path("/Volumes"), Path("/System"), Path("/Library"),
    Path("/Applications"), Path("/private"), Path("/usr"), Path("/bin"), Path("/sbin"),
    Path("/etc"), Path("/var"),
})


def _looks_secret(name: str) -> bool:
    upper = name.upper()
    return any(marker in upper for marker in SECRET_ENV_MARKERS)


@functools.lru_cache(maxsize=1)
def _host_git_identity() -> dict[str, str]:
    """Read the user's Git identity once, without reading credential files.

    The sandbox hides ``~/.gitconfig`` (it may live beside credentials), so commits
    would otherwise fail with "Author identity unknown". Two local ``git config``
    calls fix that without copying the file into the sandbox.
    """
    identity: dict[str, str] = {}
    try:
        for key, env_name in (("user.name", "GIT_AUTHOR_NAME"), ("user.email", "GIT_AUTHOR_EMAIL")):
            proc = subprocess.run(
                ["git", "config", "--global", "--get", key],
                capture_output=True, text=True, timeout=1.5, check=False,
            )
            value = (proc.stdout or "").strip()
            if proc.returncode == 0 and value:
                identity[env_name] = value
    except Exception:
        pass
    if "GIT_AUTHOR_NAME" in identity:
        identity["GIT_COMMITTER_NAME"] = identity["GIT_AUTHOR_NAME"]
    if "GIT_AUTHOR_EMAIL" in identity:
        identity["GIT_COMMITTER_EMAIL"] = identity["GIT_AUTHOR_EMAIL"]
    return identity


class GlassboxEnvironment(BaseEnvironment):
    """Run commands in a generated macOS Seatbelt profile."""

    # File tools must go through execute() so read_file/write_file/patch/search
    # see exactly the sandbox the shell sees.
    uses_host_filesystem = False
    is_local = False
    _passwordless_sudo_probe_supported = False

    def __init__(
        self,
        *,
        workspace: Path,
        timeout: int,
        task_id: str,
        settings: Mapping[str, Any] | None,
        data_dir: Path,
    ):
        self.workspace = Path(workspace)
        self.task_id = task_id or "default"
        self.data_dir = Path(data_dir)
        self._settings = dict(settings or {})
        self._closed = False

        run_id = uuid.uuid4().hex[:12]
        self.run_dir = self.data_dir / "sandboxes" / run_id
        self.sandbox_home = self.run_dir / "home"
        self.sandbox_tmp = self.run_dir / "tmp"
        prepare_scratch(self.run_dir)

        self.policy = build_policy(
            self.workspace,
            self._settings,
            scratch=self.run_dir,
        )
        self.profile_path = self.run_dir / "profile.sb"
        self.profile_path.write_text(self.policy.render(), encoding="utf-8")
        try:
            os.chmod(self.profile_path, 0o600)
        except OSError:
            pass

        self.audit = AuditLog(
            self.data_dir,
            enabled=bool(self._settings.get("audit", True)),
        )

        extra_env = dict(_host_git_identity())
        extra_env["GLASSBOX_PROFILE"] = str(self.profile_path)
        self._sandbox_env = safe_child_env(
            os.environ,
            home=Path.home(),
            scratch=self.run_dir,
            workspace=self.workspace,
            extra=extra_env,
        )

        # BaseEnvironment only snapshots when a subclass asks it to. A login shell
        # would read the deliberately hidden home directory, so use plain bash -c.
        super().__init__(cwd=str(self.workspace), timeout=timeout, env=self._sandbox_env, persist_env=True)
        self._snapshot_ready = False
        self._prefer_nonlogin = True

    # --- Session plumbing -------------------------------------------------
    def get_temp_dir(self) -> str:
        return str(self.sandbox_tmp)

    # --- Process execution ------------------------------------------------
    def _run_bash(self, cmd_string: str, *, login: bool = False, timeout: int = 120,
                  stdin_data: str | None = None) -> subprocess.Popen:
        if not Path(SANDBOX_EXEC).exists():
            raise RuntimeError("sandbox-exec is missing (macOS 10.x+ is required)")
        args = [SANDBOX_EXEC, "-f", str(self.profile_path), BASH, "-c", cmd_string]
        proc = subprocess.Popen(
            args,
            text=True,
            env=self._sandbox_env,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            cwd=self.cwd,
            start_new_session=True,
        )
        if stdin_data is not None:
            def _write() -> None:
                try:
                    assert proc.stdin is not None
                    proc.stdin.write(stdin_data)
                    proc.stdin.close()
                except Exception:
                    pass

            thread = threading.Thread(target=_write, daemon=True)
            thread.start()
            proc._hermes_stdin_thread = thread  # type: ignore[attr-defined]
        return proc

    def _kill_process(self, proc) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except OSError:
            try:
                proc.terminate()
            except OSError:
                pass

    def _force_kill_process(self, proc) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            try:
                proc.kill()
            except OSError:
                pass

    def execute(self, command: str, cwd: str = "", **kwargs) -> dict:
        # Hermes defaults a non-local backend to /root when no default_cwd is
        # advertised. /root does not exist on macOS, so every command would fail
        # with `cd: /root: No such file or directory`. Clamp the known placeholders
        # to the real workspace; a genuine `cd /tmp` is left alone so the sandbox
        # can deny it and the audit can explain why.
        if not cwd or cwd in {"/root", "~"} or not os.path.isdir(os.path.expanduser(cwd)):
            cwd = str(self.workspace)
        started = time.monotonic()
        try:
            result = super().execute(command, cwd=cwd, **kwargs)
        except Exception as exc:  # a sandbox startup failure must be a tool result
            logger.warning("Glassbox command failed to start: %s", exc, exc_info=True)
            result = {"output": f"Glassbox could not start the sandbox: {exc}", "returncode": 1}
        # A file tool may wrap a read in a shell construct that masks the kernel's
        # EPERM (for example `cat path || true`). The output still names the denied
        # path, so promote it to a hard failure instead of letting the model see an
        # empty file and assume the read succeeded.
        denied = extract_denied_paths(result.get("output", ""))
        if denied and result.get("returncode") == 0:
            result["returncode"] = 1
            result["glassbox_denied"] = denied
            result["output"] = (
                f"Glassbox blocked this command: {', '.join(denied)}\n"
                f"{result.get('output', '')}"
            )
        try:
            self.audit.record(
                command=command,
                cwd=cwd or self.cwd,
                exit_code=result.get("returncode"),
                duration_ms=int((time.monotonic() - started) * 1000),
                task_id=self.task_id,
                session_id=self.task_id,
                output=result.get("output", ""),
                network_enabled=self.policy.network,
                profile=str(self.profile_path),
            )
        except Exception:
            logger.debug("Glassbox audit write failed", exc_info=True)
        return result

    def cleanup(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            shutil.rmtree(self.run_dir, ignore_errors=True)
        except Exception:
            pass

    # --- Introspection ----------------------------------------------------
    def policy_dict(self) -> dict[str, Any]:
        return {
            **self.policy.as_dict(),
            "profile_path": str(self.profile_path),
            "audit_path": str(self.audit.path),
            "sandbox_exec": SANDBOX_EXEC,
        }


class GlassboxProvider(TerminalEnvironmentProvider):
    """Register Glassbox as ``terminal.backend: glassbox``."""

    name = "glassbox"
    display_name = "Glassbox (macOS Seatbelt)"
    is_remote = False
    is_container = False
    skip_container_guards = False
    cache_path_base = None

    def __init__(self, *, settings: Callable[[], Mapping[str, Any]], data_dir: Path):
        self._settings = settings
        self._data_dir = Path(data_dir)

    @property
    def description(self) -> str:
        return (
            "Run every terminal and file-tool command inside a macOS Seatbelt sandbox: "
            "read-only system, a writable workspace, the user's home hidden, and network "
            "off by default. Blocked attempts are recorded in a local audit log."
        )

    @property
    def env_description(self) -> str:
        return "a macOS Seatbelt sandbox (system read-only; home and network confined)"

    @property
    def default_cwd(self) -> str | None:
        """Start in the directory Hermes was launched from, not ``/root``.

        Hermes reads this on every command, so keep it cheap and fall back to None
        if the process cwd has been deleted.
        """
        try:
            cwd = os.getcwd()
        except OSError:
            return None
        return cwd if os.path.isdir(cwd) else None

    @property
    def strip_env_keys(self) -> frozenset[str]:
        return frozenset(name for name in os.environ if _looks_secret(name))

    def _settings_dict(self) -> dict[str, Any]:
        try:
            value = self._settings()
            return dict(value) if isinstance(value, Mapping) else {}
        except Exception:
            return {}

    def is_available(self) -> bool:
        return sys.platform == "darwin" and Path(SANDBOX_EXEC).exists()

    def check_requirements(self, config: dict[str, Any]) -> bool:
        return self.is_available()

    def probe(self) -> tuple[str, str]:
        if sys.platform != "darwin":
            return ("unavailable", "Glassbox is macOS-only (Seatbelt).")
        if not Path(SANDBOX_EXEC).exists():
            return ("unavailable", "/usr/bin/sandbox-exec is missing on this macOS.")
        return ("ready", "Seatbelt is available; select terminal.backend: glassbox.")

    def setup_instructions(self) -> list[str]:
        return [
            "Enable the plugin: hermes plugins enable glassbox",
            "Select the backend: hermes config set terminal.backend glassbox",
            "Verify containment: hermes glassbox verify",
        ]

    def doctor_checks(self) -> list[tuple[bool, str, str]]:
        platform_ok = sys.platform == "darwin"
        binary_ok = Path(SANDBOX_EXEC).exists()
        return [
            (platform_ok, "Glassbox platform", "macOS" if platform_ok else f"{sys.platform} (unsupported)"),
            (binary_ok, "Seatbelt binary", SANDBOX_EXEC if binary_ok else "missing"),
            (self.is_available(), "Glassbox backend", "ready" if self.is_available() else "unavailable"),
        ]

    def create_environment(
        self,
        *,
        cwd: str,
        timeout: int,
        task_id: str = "default",
        image: str | None = None,
        container_config: dict[str, Any] | None = None,
        **kwargs: Any,
    ):
        workspace = Path(os.path.expanduser(cwd or os.getcwd()))
        if not workspace.is_absolute():
            workspace = Path.cwd() / workspace
        workspace = Path(os.path.realpath(str(workspace)))
        if not workspace.is_dir() or workspace in _UNSAFE_WORKSPACES:
            workspace = Path(os.path.realpath(str(Path.home())))
        return GlassboxEnvironment(
            workspace=workspace,
            timeout=timeout,
            task_id=task_id,
            settings=self._settings_dict(),
            data_dir=self._data_dir,
        )
