from __future__ import annotations

import os
from pathlib import Path

from glassbox.policy import build_policy, prepare_scratch, safe_child_env


def test_default_policy_hides_home_and_network(tmp_path):
    workspace = tmp_path / "project"
    workspace.mkdir()
    scratch = tmp_path / "scratch"
    policy = build_policy(workspace, {}, scratch=scratch)
    profile = policy.render()

    assert "(deny default)" in profile
    assert "(allow network*)" not in profile
    assert f'(allow file-read* (subpath "{workspace}"))' in profile
    assert f'(allow file-write* (subpath "{workspace}"))' in profile
    assert '(deny file-read* (subpath "/Users")' in profile
    assert str(Path.home() / ".ssh") in profile
    assert str(Path.home() / ".hermes") in profile
    for name in (".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile"):
        path = Path.home() / name
        assert f'(deny file-write* (subpath "{path}"))' in profile
    assert f'(deny file-write* (subpath "{Path.home() / "Library/LaunchAgents"}"))' in profile
    assert '(deny mach-lookup (global-name "com.apple.coreservices.launchservicesd"))' in profile
    assert '(deny mach-lookup (global-name-prefix "com.apple.lsd."))' in profile


def test_network_and_home_are_opt_in(tmp_path):
    workspace = tmp_path / "project"
    workspace.mkdir()
    policy = build_policy(workspace, {"network": True, "allow_home": True}, scratch=tmp_path / "scratch")
    profile = policy.render()
    assert "(allow network*)" in profile
    assert f'(allow file-read* (subpath "{Path.home()}"))' in profile
    # Even with allow_home, the secret stores remain denied.
    assert f'(deny file-read* (subpath "{Path.home() / ".ssh"}"))' in profile


def test_deny_inside_workspace_is_emitted_after_the_allow(tmp_path):
    workspace = tmp_path / "project"
    workspace.mkdir()
    secret = workspace / ".env"
    policy = build_policy(workspace, {"deny_paths": [str(secret)]}, scratch=tmp_path / "scratch")
    profile = policy.render()
    allow_at = profile.index(f'(allow file-read* (subpath "{workspace}"))')
    deny_at = profile.index(f'(deny file-read* (subpath "{secret}"))')
    assert deny_at > allow_at


def test_scratch_inside_denied_hermes_is_reallowed(tmp_path):
    workspace = tmp_path / "project"
    workspace.mkdir()
    scratch = Path.home() / ".hermes" / "plugin-data" / "glassbox" / "sandboxes" / "test"
    policy = build_policy(workspace, {}, scratch=scratch)
    profile = policy.render()
    # ~/.hermes is denied broadly, then the scratch root is re-allowed after it.
    deny_at = profile.index(f'(deny file-read* (subpath "{Path.home() / ".hermes"}"))')
    allow_at = profile.index(f'(allow file-read* (subpath "{scratch}"))')
    assert allow_at > deny_at


def test_safe_child_env_drops_credentials_and_sets_private_home(tmp_path):
    scratch = tmp_path / "scratch"
    prepare_scratch(scratch)
    env = safe_child_env(
        {
            "PATH": "/usr/bin:/bin",
            "HOME": str(Path.home()),
            "OPENAI_API_KEY": "sk-secret",
            "ANTHROPIC_API_KEY": "sk-secret",
            "SSH_AUTH_SOCK": "/tmp/agent.sock",
            "LANG": "en_US.UTF-8",
        },
        home=scratch / "home",
        scratch=scratch,
        workspace=tmp_path / "project",
        extra={"GIT_AUTHOR_NAME": "Test", "GLASSBOX_TEST": "1"},
    )
    assert "OPENAI_API_KEY" not in env
    assert "ANTHROPIC_API_KEY" not in env
    assert "SSH_AUTH_SOCK" not in env
    assert env["HOME"] == str(scratch / "home")
    assert env["TMPDIR"] == str(scratch / "tmp")
    assert env["LANG"] == "en_US.UTF-8"
    assert env["GIT_AUTHOR_NAME"] == "Test"
    assert env["GLASSBOX_TEST"] == "1"
    assert env["PATH"].startswith("/usr/bin")


def test_prepare_scratch_is_private(tmp_path):
    scratch = tmp_path / "scratch"
    prepare_scratch(scratch)
    assert (scratch / "home").is_dir()
    assert (scratch / "tmp").is_dir()
    assert oct(os.stat(scratch).st_mode & 0o777) == "0o700"
