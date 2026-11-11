from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").exists(),
    reason="Glassbox requires macOS Seatbelt",
)

pytest.importorskip("agent.terminal_env_provider")
from glassbox.verify import checks_ok, run_checks  # noqa: E402


def test_self_test_passes(tmp_path):
    checks = run_checks(data_dir=tmp_path, settings={})
    failed = [item for item in checks if not item.get("ok") and not item.get("skipped")]
    assert not failed, failed
    assert checks_ok(checks)
