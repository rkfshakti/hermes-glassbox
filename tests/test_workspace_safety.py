from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

pytest.importorskip("agent.terminal_env_provider")

from glassbox.handlers import policy as policy_tool  # noqa: E402
from glassbox.provider import (  # noqa: E402
    GlassboxEnvironment,
    GlassboxProvider,
    _is_unsafe_workspace,
    resolve_workspace,
)


def test_home_and_ancestors_are_unsafe():
    home = Path(os.path.realpath(Path.home()))
    assert _is_unsafe_workspace(home)
    assert _is_unsafe_workspace(home.parent)
    assert _is_unsafe_workspace("/")
    assert resolve_workspace(home) is None


def test_project_under_home_is_safe():
    project = Path.home() / f".glassbox-workspace-test-{os.getpid()}"
    project.mkdir()
    try:
        assert not _is_unsafe_workspace(project)
        assert resolve_workspace(project) == Path(os.path.realpath(project))
    finally:
        project.rmdir()


def test_environment_falls_back_to_empty_workspace(tmp_path):
    env = GlassboxEnvironment(
        workspace=Path.home(),
        timeout=5,
        task_id="test",
        settings={"audit": False},
        data_dir=tmp_path,
    )
    try:
        assert env.workspace_fallback is True
        assert env.workspace != Path(os.path.realpath(Path.home()))
        assert env.workspace.is_dir()
        assert env.workspace.is_relative_to(env.run_dir)
    finally:
        env.cleanup()


def test_provider_preserves_a_real_project_directory(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    provider = GlassboxProvider(settings=lambda: {"audit": False}, data_dir=tmp_path / "data")
    env = provider.create_environment(cwd=str(project), timeout=5, task_id="test")
    try:
        assert env.workspace_fallback is False
        assert env.workspace == Path(os.path.realpath(project))
    finally:
        env.cleanup()


def test_provider_falls_back_when_launched_from_home(tmp_path):
    provider = GlassboxProvider(settings=lambda: {"audit": False}, data_dir=tmp_path / "data")
    env = provider.create_environment(cwd=str(Path.home()), timeout=5, task_id="test")
    try:
        assert env.workspace_fallback is True
        assert env.workspace.is_relative_to(env.run_dir)
    finally:
        env.cleanup()


def test_policy_tool_reports_home_fallback(tmp_path):
    payload = json.loads(policy_tool({"cwd": str(Path.home())}, data_dir=tmp_path, settings={}))
    assert payload["workspace_fallback"] is True
    assert payload["policy"]["workspace"].endswith("policy-preview")
