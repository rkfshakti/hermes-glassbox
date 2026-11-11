"""Sandbox policy and macOS Seatbelt profile rendering.

The policy has one job: turn a workspace and a handful of user settings into a
``sandbox-exec`` profile that is strict by default, keeps the system readable, lets
the agent write only inside the workspace (and a private scratch area), hides the
rest of the user's home, and denies network access unless explicitly enabled.

Seatbelt profiles are S-expressions. Rules are evaluated with deny taking priority,
so a ``(deny file-read* ...)`` for the home directory can be followed by an
``(allow file-read* ...)`` for the workspace itself.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

# Tools that can ask another process to do work outside the sandbox (Apple Events,
# LaunchServices, the keychain, launchd). They are blocked by default; a user who
# needs one can add a write/read path, but process-exec stays closed.
_BLOCKED_EXECUTABLES = (
    "/usr/bin/osascript",
    "/usr/bin/open",
    "/usr/bin/security",
    "/bin/launchctl",
    "/usr/bin/launchctl",
)

# Denied even when ``allow_home`` is on. These are credential stores and agent
# homes, not project files.
_DEFAULT_SECRET_PATHS = (
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.kube",
    "~/.docker",
    "~/.netrc",
    "~/.npmrc",
    "~/.pypirc",
    "~/.config",
    "~/.codex",
    "~/.claude",
    "~/.gemini",
    "~/.hermes",
    "~/.local/share/keyrings",
    "~/Library/Keychains",
    "~/Library/Cookies",
    "~/Library/Messages",
    "~/Library/Mail",
    "~/Library/Safari",
    "~/Library/Application Support/Google/Chrome",
    "~/Library/Application Support/Firefox",
    "~/Library/Application Support/Slack",
    "~/Library/Application Support/Discord",
)

# Environment variables that must never reach a sandboxed command. The environment
# builder uses an allowlist, but this list is also exported for the provider's
# ``strip_env_keys`` so Hermes' own secret stripping agrees with ours.
SECRET_ENV_MARKERS = (
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "AUTH",
    "COOKIE",
    "SESSION",
    "PRIVATE",
)

# Env vars a shell genuinely needs. Everything else is dropped, including provider
# credentials Hermes may have inherited.
_SAFE_ENV_NAMES = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "TERM",
    "TZ",
    "USER",
    "LOGNAME",
    "SHELL",
    "COLORTERM",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
)


def _expand(path: str | os.PathLike[str]) -> Path:
    """Expand ``~`` and make the path absolute without requiring it to exist."""
    p = Path(os.path.expanduser(str(path)))
    if not p.is_absolute():
        p = Path.cwd() / p
    # realpath resolves symlinks; a symlinked workspace must be allowed at its real
    # location or writes through the link can miss the rule.
    return Path(os.path.realpath(str(p)))


def _dedupe(paths: Iterable[Path]) -> tuple[Path, ...]:
    seen: set[str] = set()
    out: list[Path] = []
    for p in paths:
        key = str(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return tuple(out)


def _seatbelt_string(value: str | os.PathLike[str]) -> str:
    """Quote a value for a Seatbelt profile string literal."""
    text = str(value)
    if "\x00" in text or "\n" in text:
        raise ValueError("Seatbelt paths cannot contain NUL or newline characters")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _as_path_list(value: Any) -> list[Path]:
    if value is None:
        return []
    if isinstance(value, (str, os.PathLike)):
        raw = [value]
    elif isinstance(value, (list, tuple, set)):
        raw = list(value)
    else:
        return []
    return [_expand(item) for item in raw if str(item).strip()]


@dataclass(frozen=True)
class SandboxPolicy:
    """One immutable policy, rendered into a Seatbelt profile."""

    workspace: Path
    scratch: Path
    home: Path
    allowed_read: tuple[Path, ...] = field(default_factory=tuple)
    allowed_write: tuple[Path, ...] = field(default_factory=tuple)
    denied: tuple[Path, ...] = field(default_factory=tuple)
    network: bool = False
    allow_home: bool = False
    workspace_writable: bool = True

    @property
    def read_paths(self) -> tuple[Path, ...]:
        paths = [self.workspace, self.scratch, *self.allowed_read]
        if self.allow_home:
            paths.append(self.home)
        return _dedupe(paths)

    @property
    def write_paths(self) -> tuple[Path, ...]:
        paths = [self.scratch, *self.allowed_write]
        if self.workspace_writable:
            paths.append(self.workspace)
        return _dedupe(paths)

    def as_dict(self) -> dict[str, Any]:
        return {
            "workspace": str(self.workspace),
            "scratch": str(self.scratch),
            "home_hidden": not self.allow_home,
            "network": self.network,
            "workspace_writable": self.workspace_writable,
            "read_paths": [str(p) for p in self.read_paths],
            "write_paths": [str(p) for p in self.write_paths],
            "denied_paths": [str(p) for p in self.denied],
        }

    def render(self) -> str:
        """Render the macOS Seatbelt profile.

        Ordering matters. Seatbelt resolves overlapping rules with the most recent
        matching rule winning, so a broad home deny is followed by a narrow allow
        for the workspace/scratch, and explicit secret denies are emitted after any
        allow that could contain them. Deny paths that are ancestors of the scratch
        root (for example ``~/.hermes``) are emitted before the scratch allow so the
        agent can still write its private temp/home area.
        """
        read_paths = self.read_paths
        write_paths = self.write_paths
        inner_denied = [
            p for p in self.denied
            if any(_is_relative_to(p, root) for root in (*read_paths, *write_paths))
        ]
        ancestor_denied = [
            p for p in self.denied
            if any(_is_relative_to(root, p) for root in (*read_paths, *write_paths))
        ]
        other_denied = [p for p in self.denied if p not in inner_denied and p not in ancestor_denied]

        lines = [
            "(version 1)",
            "(deny default)",
            # Process creation and the normal sandbox housekeeping services.
            "(allow process*)",
            "(allow signal)",
            "(allow sysctl-read)",
            "(allow mach-lookup)",
            "(allow ipc-posix-shm)",
            # Metadata is needed to stat paths the process may not read; denying it
            # breaks almost every CLI tool with confusing ENOENT instead of EPERM.
            "(allow file-read-metadata)",
            # The system is readable. The home directory is carved back out below.
            '(allow file-read* (subpath "/"))',
            # Hide every user home and external volume. The workspace and scratch
            # root are re-allowed after these broad denies.
            '(deny file-read* (subpath "/Users") (subpath "/Volumes") '
            '(subpath "/Users/Shared") (subpath "/private/var/root"))',
        ]

        # Ancestor denies (e.g. ~/.hermes around the scratch root) go before the
        # narrow allows so scratch remains usable; all other explicit denies go
        # here too, and any that live inside an allowed path are repeated last.
        for path in _dedupe(Path(p) for p in (*ancestor_denied, *other_denied)):
            lines.append(f"(deny file-read* (subpath {_seatbelt_string(path)}))")
            lines.append(f"(deny file-write* (subpath {_seatbelt_string(path)}))")

        for path in read_paths:
            lines.append(f"(allow file-read* (subpath {_seatbelt_string(path)}))")

        lines.append(
            '(allow file-write* (literal "/dev/null") (literal "/dev/stdout") '
            '(literal "/dev/stderr") (literal "/dev/tty") (literal "/dev/dtracehelper"))'
        )
        for path in write_paths:
            lines.append(f"(allow file-write* (subpath {_seatbelt_string(path)}))")

        # Explicit denials inside an allowed root win over that root's allow.
        for path in _dedupe(Path(p) for p in inner_denied):
            lines.append(f"(deny file-read* (subpath {_seatbelt_string(path)}))")
            lines.append(f"(deny file-write* (subpath {_seatbelt_string(path)}))")

        # Keep the common IPC escape hatches closed. A model-authored command could
        # otherwise ask Finder or System Events to read a file on its behalf.
        for executable in _BLOCKED_EXECUTABLES:
            lines.append(f"(deny process-exec (literal {_seatbelt_string(executable)}))")
        for service in ("com.apple.appleevent", "com.apple.coreservices.appleevents"):
            lines.append(f"(deny mach-lookup (global-name {_seatbelt_string(service)}))")

        if self.network:
            lines.append("(allow network*)")

        return "\n".join(lines) + "\n"


def build_policy(
    workspace: str | os.PathLike[str],
    settings: Mapping[str, Any] | None = None,
    *,
    scratch: str | os.PathLike[str] | None = None,
) -> SandboxPolicy:
    """Build a policy from plugin settings.

    Unknown or malformed settings fall back to the safe default rather than raising:
    a bad config must not leave the agent running unconfined.
    """
    cfg = dict(settings or {})
    ws = _expand(workspace)
    home = _expand("~")
    scratch_path = _expand(scratch) if scratch else _expand(home / ".hermes-glassbox-scratch")

    denied: list[Path] = [_expand(p) for p in _DEFAULT_SECRET_PATHS]
    denied.extend(_as_path_list(cfg.get("deny_paths")))
    # Do not drop a deny just because it surrounds the workspace: the renderer
    # orders ancestor denies before the narrow workspace allow and repeats any
    # deny inside the workspace after it, so both "~/.hermes" around scratch and
    # "~/.ssh" inside a home workspace stay closed.
    denied = list(_dedupe(denied))

    allow_home = bool(cfg.get("allow_home", False))
    network = bool(cfg.get("network", False))
    workspace_writable = bool(cfg.get("workspace_writable", True))

    allowed_read: list[Path] = _as_path_list(cfg.get("read_paths"))
    allowed_write: list[Path] = _as_path_list(cfg.get("write_paths"))

    return SandboxPolicy(
        workspace=ws,
        scratch=scratch_path,
        home=home,
        allowed_read=_dedupe(allowed_read),
        allowed_write=_dedupe(allowed_write),
        denied=_dedupe(denied),
        network=network,
        allow_home=allow_home,
        workspace_writable=workspace_writable,
    )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def safe_child_env(
    base: Mapping[str, str] | None = None,
    *,
    home: Path,
    scratch: Path,
    workspace: Path,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the small, allowlisted environment a sandboxed command receives.

    This deliberately does not copy ``os.environ`` wholesale: provider keys, GitHub
    tokens and SSH agent sockets must not be reachable from a model-authored shell.
    """
    source = dict(base if base is not None else os.environ)
    env: dict[str, str] = {}
    for name in _SAFE_ENV_NAMES:
        value = source.get(name)
        if value:
            env[name] = value

    # Keep only PATH entries that are readable in the sandbox. Home-relative tool
    # directories are re-added only when the user opted into reading home.
    path_entries = [p for p in env.get("PATH", "").split(os.pathsep) if p]
    keep: list[str] = []
    for entry in path_entries:
        expanded = _expand(entry)
        if _is_relative_to(expanded, home) and not _is_relative_to(expanded, workspace):
            continue
        keep.append(str(expanded))
    for fallback in ("/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin",
                     "/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        if fallback not in keep and Path(fallback).is_dir():
            keep.append(fallback)
    env["PATH"] = os.pathsep.join(str(p) for p in _dedupe(Path(p) for p in keep))

    env["HOME"] = str(home)
    env["TMPDIR"] = str(scratch / "tmp")
    env["TMP"] = env["TMPDIR"]
    env["TEMP"] = env["TMPDIR"]
    env["PWD"] = str(workspace)
    env["SHELL"] = "/bin/bash"
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_CONFIG_SYSTEM"] = "/dev/null"
    env["GIT_PAGER"] = "cat"
    env["PAGER"] = "cat"
    env["GLASSBOX"] = "1"
    env["GLASSBOX_WORKSPACE"] = str(workspace)
    # Package managers get private caches under the scratch root.
    env["XDG_CACHE_HOME"] = str(scratch / ".cache")
    env["XDG_CONFIG_HOME"] = str(scratch / ".config")
    env["XDG_DATA_HOME"] = str(scratch / ".local" / "share")
    env["PIP_CACHE_DIR"] = str(scratch / ".cache" / "pip")
    env["UV_CACHE_DIR"] = str(scratch / ".cache" / "uv")
    env["npm_config_cache"] = str(scratch / ".npm")
    if extra:
        for name, value in extra.items():
            if name and value is not None and _is_safe_env_name(str(name)):
                env[str(name)] = str(value)
    return env


def _is_safe_env_name(name: str) -> bool:
    if not name.replace("_", "").isalnum() or name[0].isdigit():
        return False
    # Git identity values are not credentials; the generic AUTH marker would
    # otherwise reject GIT_AUTHOR_NAME/GIT_COMMITTER_NAME.
    if name.startswith(("GIT_AUTHOR_", "GIT_COMMITTER_", "GLASSBOX_")):
        return True
    upper = name.upper()
    return not any(marker in upper for marker in SECRET_ENV_MARKERS)


def prepare_scratch(scratch: Path) -> None:
    """Create the private home/scratch layout a sandboxed shell expects."""
    for relative in (
        "tmp",
        "home",
        ".cache/pip",
        ".cache/uv",
        ".config",
        ".local/share",
        ".npm",
    ):
        (scratch / relative).mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(scratch, 0o700)
        os.chmod(scratch / "tmp", 0o700)
    except OSError:
        pass
