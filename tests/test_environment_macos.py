from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").exists(),
    reason="Glassbox requires macOS Seatbelt",
)

agent = pytest.importorskip("agent.terminal_env_provider")
from glassbox.provider import GlassboxEnvironment  # noqa: E402


def _environment(tmp_path, **settings):
    workspace = tmp_path / "project"
    workspace.mkdir()
    data = tmp_path / "data"
    data.mkdir()
    return GlassboxEnvironment(
        workspace=workspace,
        timeout=20,
        task_id="test-session",
        settings={"audit": True, **settings},
        data_dir=data,
    )


def test_workspace_write_and_read(tmp_path):
    env = _environment(tmp_path)
    try:
        result = env.execute("printf hello > hello.txt")
        assert result["returncode"] == 0, result
        assert (env.workspace / "hello.txt").read_text() == "hello"
        result = env.execute("cat hello.txt")
        assert result["returncode"] == 0
        assert "hello" in result["output"]
    finally:
        env.cleanup()


def test_home_is_denied_and_audited(tmp_path):
    env = _environment(tmp_path)
    canary = Path.home() / ".glassbox-test-canary"
    canary.write_text("do-not-read", encoding="utf-8")
    try:
        result = env.execute(f"cat {canary}")
        assert result["returncode"] != 0
        assert "do-not-read" not in result["output"]
        entries = env.audit.read()
        assert any(str(canary) in entry.get("denied_paths", []) for entry in entries)
    finally:
        canary.unlink(missing_ok=True)
        env.cleanup()


def test_network_denied(tmp_path):
    if not shutil.which("curl"):
        pytest.skip("curl not installed")
    env = _environment(tmp_path)
    try:
        result = env.execute("curl -sS --max-time 2 https://example.com -o /dev/null")
        assert result["returncode"] != 0
    finally:
        env.cleanup()


def test_secret_environment_is_filtered(tmp_path):
    os.environ["GLASSBOX_TEST_SECRET"] = "must-not-leak"
    try:
        env = _environment(tmp_path)
        try:
            result = env.execute('if [ -z "${GLASSBOX_TEST_SECRET:-}" ]; then echo absent; else echo leaked; fi')
            assert "leaked" not in result["output"]
        finally:
            env.cleanup()
    finally:
        os.environ.pop("GLASSBOX_TEST_SECRET", None)
