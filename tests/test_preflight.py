from __future__ import annotations

from pathlib import Path

from glassbox.policy import build_policy
from glassbox.preflight import _action_for, is_blocked


def _policy(tmp_path, **settings):
    workspace = tmp_path / "project"
    workspace.mkdir()
    return build_policy(workspace, settings, scratch=tmp_path / "scratch")


def test_reads_of_system_paths_are_allowed(tmp_path):
    policy = _policy(tmp_path)
    assert not is_blocked(Path("/usr/bin/python3"), policy, write=False)
    assert not is_blocked(Path("/opt/homebrew/bin/rg"), policy, write=False)


def test_home_and_ssh_are_blocked(tmp_path):
    policy = _policy(tmp_path)
    assert is_blocked(Path.home() / ".ssh" / "id_rsa", policy, write=False)
    assert is_blocked(Path.home() / "Documents" / "notes.txt", policy, write=False)
    assert is_blocked(Path.home() / ".ssh" / "id_rsa", policy, write=True)


def test_shell_startup_and_launch_agents_are_always_blocked(tmp_path):
    policy = _policy(tmp_path, allow_home=True)
    for path in (
        Path.home() / ".zshrc",
        Path.home() / ".bashrc",
        Path.home() / ".profile",
        Path.home() / "Library" / "LaunchAgents" / "com.example.plist",
    ):
        assert is_blocked(path, policy, write=True), path
        assert is_blocked(path, policy, write=False), path


def test_workspace_is_readable_and_writable(tmp_path):
    policy = _policy(tmp_path)
    file = policy.workspace / "notes.txt"
    assert not is_blocked(file, policy, write=False)
    assert not is_blocked(file, policy, write=True)


def test_write_outside_the_workspace_is_blocked(tmp_path):
    policy = _policy(tmp_path)
    assert is_blocked(Path("/private/tmp/elsewhere.txt"), policy, write=True)
    assert not is_blocked(Path("/private/tmp/elsewhere.txt"), policy, write=False)


def test_allow_home_opens_reads_but_not_secrets(tmp_path):
    policy = _policy(tmp_path, allow_home=True)
    assert not is_blocked(Path.home() / "Documents" / "notes.txt", policy, write=False)
    assert is_blocked(Path.home() / ".ssh" / "id_rsa", policy, write=False)


def test_action_for_returns_an_actionable_block(tmp_path):
    policy = _policy(tmp_path)
    action = _action_for("read_file", {"path": "~/.ssh/id_rsa"}, policy)
    assert action is not None
    assert action["action"] == "block"
    assert "read_paths" in action["message"]
    assert _action_for("read_file", {"path": str(policy.workspace / "ok.txt")}, policy) is None
    assert _action_for("terminal", {"command": "pwd"}, policy) is None
