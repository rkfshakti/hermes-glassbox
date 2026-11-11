from __future__ import annotations

from glassbox.audit import (
    AuditLog,
    extract_denied_paths,
    network_denied,
    render_html,
    render_text,
    summarize,
)


def test_extract_denied_paths():
    output = (
        "cat: /Users/me/.ssh/id_rsa: Operation not permitted\n"
        "'/Users/me/.aws/credentials': Operation not permitted\n"
        "curl: (6) Could not resolve host\n"
    )
    assert extract_denied_paths(output) == [
        "/Users/me/.ssh/id_rsa",
        "/Users/me/.aws/credentials",
    ]


def test_network_denied_is_a_signal_not_a_guess_when_network_is_on():
    assert network_denied("curl: (6) Could not resolve host", "curl https://x", network_enabled=False)
    assert not network_denied("curl: (6) Could not resolve host", "curl https://x", network_enabled=True)
    assert not network_denied("ls: no such file", "ls nope", network_enabled=False)


def test_audit_round_trip_and_summary(tmp_path):
    audit = AuditLog(tmp_path)
    audit.record(
        command="cat ~/.ssh/id_rsa",
        cwd=str(tmp_path),
        exit_code=1,
        duration_ms=12,
        task_id="s1",
        session_id="s1",
        output="cat: /Users/me/.ssh/id_rsa: Operation not permitted",
    )
    audit.record(
        command="printf ok > notes.txt",
        cwd=str(tmp_path),
        exit_code=0,
        duration_ms=4,
        task_id="s1",
        session_id="s1",
    )
    entries = audit.read()
    assert len(entries) == 2
    summary = summarize(entries)
    assert summary["total_commands"] == 2
    assert summary["blocked_commands"] == 1
    assert summary["blocked_paths"][0]["path"] == "/Users/me/.ssh/id_rsa"
    assert "Glassbox audit" in render_text(entries)
    assert "Glassbox" in render_html(entries)
    assert audit.clear() == 2
    assert audit.read() == []


def test_audit_disabled_writes_nothing(tmp_path):
    audit = AuditLog(tmp_path, enabled=False)
    assert audit.record(command="true", cwd=str(tmp_path), exit_code=0, duration_ms=1) is None
    assert not audit.path.exists()
