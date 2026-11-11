"""Append-only audit log for Glassbox.

Every sandboxed command is recorded as one JSON line: what ran, where, the exit
status, and any paths the kernel refused to read or write. The log is local, capped,
and readable with ``hermes glassbox report`` or the ``glassbox_report`` tool.

The audit is intentionally best-effort: a full disk or a concurrent writer must never
break the command the user is running.
"""

from __future__ import annotations

import html
import json
import os
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

_MAX_COMMAND_CHARS = 2000
_MAX_EXCERPT_CHARS = 400
_MAX_LOG_BYTES = 4 * 1024 * 1024
_LOCK = threading.Lock()

# Paths in Seatbelt's "Operation not permitted" message. macOS prints the path
# followed by a colon; paths with spaces are uncommon in the credential locations
# this plugin is meant to surface, so keep the expression conservative.
_DENIED_PATH_RE = re.compile(r"((?:/|~/)[^\s:'\"<>]+): Operation not permitted")
_DENIED_QUOTED_RE = re.compile(r"['\"]([^'\"]+)['\"]: Operation not permitted")
_DENIED_PY_RE = re.compile(r"Operation not permitted: ['\"]([^'\"]+)['\"]")
_NETWORK_HINTS = re.compile(
    r"(?i)\b(curl|wget|http|https|socket|connect|ssh|scp|rsync|git\s+push|"
    r"pip\s+install|npm\s+install|brew\s+install|network)\b"
)
_NETWORK_ERRORS = re.compile(
    r"(?i)(operation not permitted|could not resolve|nodename nor servname|"
    r"network is unreachable|connection refused|failed to connect)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _truncate(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def extract_denied_paths(output: str) -> list[str]:
    """Pull paths out of kernel denial messages, preserving order and deduping."""
    found: list[str] = []
    for pattern in (_DENIED_PATH_RE, _DENIED_QUOTED_RE, _DENIED_PY_RE):
        for match in pattern.finditer(output or ""):
            path = match.group(1).strip()
            if path and path not in found:
                found.append(path)
    return found


def network_denied(output: str, command: str, *, network_enabled: bool) -> bool:
    """Best-effort signal that a command failed because the network was walled off."""
    if network_enabled:
        return False
    return bool(_NETWORK_HINTS.search(command or "") and _NETWORK_ERRORS.search(output or ""))


class AuditLog:
    """A tiny JSONL log with a cross-process write lock."""

    def __init__(self, data_dir: str | os.PathLike[str], *, enabled: bool = True):
        self.dir = Path(data_dir)
        self.path = self.dir / "audit.jsonl"
        self.rotated_path = self.dir / "audit.1.jsonl"
        self.lock_path = self.dir / "audit.lock"
        self.enabled = enabled
        if enabled:
            self.dir.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialize appends across threads and, where available, processes."""
        with _LOCK:
            handle = None
            try:
                self.lock_path.parent.mkdir(parents=True, exist_ok=True)
                handle = open(self.lock_path, "a+", encoding="utf-8")
                try:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                except Exception:
                    pass
                yield
            finally:
                if handle is not None:
                    try:
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                    except Exception:
                        pass
                    handle.close()

    def _rotate_if_needed(self) -> None:
        try:
            if self.path.exists() and self.path.stat().st_size > _MAX_LOG_BYTES:
                self.rotated_path.unlink(missing_ok=True)
                self.path.rename(self.rotated_path)
        except OSError:
            pass

    def record(
        self,
        *,
        command: str,
        cwd: str,
        exit_code: int | None,
        duration_ms: int,
        task_id: str = "",
        session_id: str = "",
        output: str = "",
        network_enabled: bool = False,
        profile: str = "",
    ) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        denied = extract_denied_paths(output)
        entry = {
            "ts": time.time(),
            "iso": utc_now(),
            "task_id": task_id or "",
            "session_id": session_id or "",
            "cwd": cwd or "",
            "command": _truncate(command or "", _MAX_COMMAND_CHARS),
            "exit_code": exit_code,
            "duration_ms": max(0, int(duration_ms)),
            "denied_paths": denied,
            "network_denied": network_denied(output, command or "", network_enabled=network_enabled),
            "profile": profile or "",
        }
        if denied or entry["network_denied"]:
            entry["excerpt"] = _truncate((output or "").strip(), _MAX_EXCERPT_CHARS)
        try:
            line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
            with self._locked():
                self._rotate_if_needed()
                with open(self.path, "a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
        except Exception:
            return entry
        return entry

    def read(self, limit: int = 200) -> list[dict[str, Any]]:
        """Return the newest *limit* valid entries, oldest first."""
        entries: list[dict[str, Any]] = []
        for path in (self.rotated_path, self.path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                        except ValueError:
                            continue
                        if isinstance(item, dict):
                            entries.append(item)
            except OSError:
                continue
        if limit > 0:
            entries = entries[-limit:]
        return entries

    def clear(self) -> int:
        """Delete this profile's audit history; returns how many entries were removed."""
        removed = len(self.read(limit=0))
        try:
            with self._locked():
                self.path.unlink(missing_ok=True)
                self.rotated_path.unlink(missing_ok=True)
        except OSError:
            pass
        return removed


def _blocked_key(entry: dict[str, Any]) -> list[str]:
    paths = [str(p) for p in entry.get("denied_paths") or [] if p]
    if entry.get("network_denied"):
        paths.append("network")
    return paths


def summarize(entries: Iterable[dict[str, Any]], *, session_id: str = "") -> dict[str, Any]:
    """Aggregate a list of audit entries into the shape the tools and CLI return."""
    selected = [e for e in entries if not session_id or e.get("session_id") == session_id]
    total = len(selected)
    blocked_entries = [e for e in selected if _blocked_key(e)]
    counts: dict[str, dict[str, Any]] = {}
    for entry in blocked_entries:
        for key in _blocked_key(entry):
            bucket = counts.setdefault(key, {"path": key, "count": 0, "last_command": "", "last_seen": ""})
            bucket["count"] += 1
            bucket["last_command"] = entry.get("command", "")
            bucket["last_seen"] = entry.get("iso", "")
    blocked = sorted(counts.values(), key=lambda item: (-item["count"], item["path"]))
    return {
        "total_commands": total,
        "blocked_commands": len(blocked_entries),
        "blocked_paths": blocked,
        "network_blocked": sum(1 for e in selected if e.get("network_denied")),
        "sessions": sorted({e.get("session_id") for e in selected if e.get("session_id")}),
        "first": selected[0].get("iso", "") if selected else "",
        "last": selected[-1].get("iso", "") if selected else "",
    }


def _fmt_time(value: str) -> str:
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return value or "—"


def render_text(entries: list[dict[str, Any]], *, session_id: str = "", limit: int = 20) -> str:
    """Human-readable report used by the CLI and slash command."""
    summary = summarize(entries, session_id=session_id)
    lines = [
        "Glassbox audit",
        "──────────────",
        f"Commands:  {summary['total_commands']}",
        f"Blocked:   {summary['blocked_commands']}",
        f"Window:    {_fmt_time(summary['first'])} → {_fmt_time(summary['last'])}",
    ]
    if summary["blocked_paths"]:
        lines += ["", "Blocked attempts"]
        for item in summary["blocked_paths"][:limit]:
            count = f" ×{item['count']}" if item["count"] > 1 else ""
            lines.append(f"  ⛔ {item['path']}{count}")
            if item.get("last_command"):
                lines.append(f"     last: {_truncate(item['last_command'], 110)}")
    else:
        lines += ["", "No blocked access recorded. ✓"]

    recent = [e for e in entries if not session_id or e.get("session_id") == session_id][-limit:]
    if recent:
        lines += ["", f"Last {len(recent)} commands"]
        for entry in reversed(recent):
            status = "⛔" if _blocked_key(entry) else "✓"
            command = _truncate((entry.get("command") or "").replace("\n", " "), 96)
            lines.append(f"  {status} [{entry.get('exit_code', '?')}] {command}")
    return "\n".join(lines)


def render_html(entries: list[dict[str, Any]], *, session_id: str = "") -> str:
    """Self-contained dark report, built without a template dependency."""
    summary = summarize(entries, session_id=session_id)
    selected = [e for e in entries if not session_id or e.get("session_id") == session_id]
    selected = selected[-200:]
    rows: list[str] = []
    for entry in reversed(selected):
        blocked = _blocked_key(entry)
        status = "blocked" if blocked else "allowed"
        badge = "⛔" if blocked else "✓"
        command = html.escape(_truncate((entry.get("command") or "").replace("\n", " "), 220))
        paths = ", ".join(html.escape(str(p)) for p in blocked) or "—"
        rows.append(
            "<tr>"
            f'<td class="status {status}">{badge}</td>'
            f"<td><code>{command}</code></td>"
            f"<td>{html.escape(paths)}</td>"
            f'<td class="num">{entry.get("exit_code", "?")}</td>'
            f'<td class="num">{entry.get("duration_ms", 0)} ms</td>'
            f"<td>{html.escape(_fmt_time(entry.get('iso', '')))}</td>"
            "</tr>"
        )
    blocked_cards = "".join(
        f'<div class="card"><div class="big">{item["count"]}×</div>'
        f'<div class="path">{html.escape(item["path"])}</div>'
        f'<div class="muted">{html.escape(_truncate(item.get("last_command", ""), 150))}</div></div>'
        for item in summary["blocked_paths"][:12]
    ) or '<div class="empty">No blocked access recorded.</div>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Glassbox report</title>
<style>
:root {{ color-scheme: dark; --bg:#0b0f14; --panel:#111821; --line:#233041; --text:#e6edf3;
        --muted:#8b98a9; --green:#3fb950; --red:#f85149; --amber:#d29922; --blue:#58a6ff; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:radial-gradient(circle at 20% -10%,#17263a 0,var(--bg) 45%);
        color:var(--text); font:14px/1.5 -apple-system,BlinkMacSystemFont,"SF Mono",Menlo,monospace; }}
main {{ max-width:1100px; margin:0 auto; padding:48px 24px 80px; }}
h1 {{ font-size:30px; letter-spacing:-.03em; margin:0 0 4px; }}
h1 span {{ color:var(--blue); }}
.sub {{ color:var(--muted); margin-bottom:32px; }}
.stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:24px 0 32px; }}
.stat,.card {{ background:linear-gradient(180deg,#141c26,#10161e); border:1px solid var(--line);
               border-radius:12px; padding:16px; }}
.stat .n {{ font-size:30px; font-weight:700; letter-spacing:-.04em; }}
.stat .l {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(240px,1fr)); gap:12px; }}
.card .big {{ color:var(--red); font-size:22px; font-weight:700; }}
.card .path {{ margin:4px 0; word-break:break-all; }}
.muted {{ color:var(--muted); font-size:12px; }}
.empty {{ color:var(--green); background:var(--panel); border:1px solid var(--line);
          border-radius:12px; padding:20px; }}
table {{ width:100%; border-collapse:collapse; margin-top:28px; background:var(--panel);
         border:1px solid var(--line); border-radius:12px; overflow:hidden; }}
th {{ text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.08em;
      color:var(--muted); padding:12px 14px; border-bottom:1px solid var(--line); }}
td {{ padding:11px 14px; border-bottom:1px solid #1a2431; vertical-align:top; }}
tr:last-child td {{ border-bottom:0; }}
code {{ font:12px/1.45 "SF Mono",Menlo,monospace; color:#c9d1d9; word-break:break-word; }}
.status {{ font-size:16px; }}
.status.blocked {{ color:var(--red); }}
.status.allowed {{ color:var(--green); }}
.num {{ color:var(--muted); text-align:right; white-space:nowrap; }}
footer {{ color:var(--muted); margin-top:28px; font-size:12px; }}
@media (max-width:720px) {{ .stats {{ grid-template-columns:repeat(2,1fr); }} main {{ padding:24px 14px; }} }}
</style></head><body><main>
<h1>Hermes <span>Glassbox</span></h1>
<div class="sub">Containment audit · generated {html.escape(utc_now())}</div>
<div class="stats">
  <div class="stat"><div class="n">{summary['total_commands']}</div><div class="l">Commands</div></div>
  <div class="stat"><div class="n" style="color:var(--red)">{summary['blocked_commands']}</div><div class="l">Blocked</div></div>
  <div class="stat"><div class="n" style="color:var(--amber)">{summary['network_blocked']}</div><div class="l">Network blocks</div></div>
  <div class="stat"><div class="n" style="color:var(--blue)">{len(summary['sessions'])}</div><div class="l">Sessions</div></div>
</div>
<h2>Blocked attempts</h2>
<div class="cards">{blocked_cards}</div>
<h2 style="margin-top:36px">Timeline</h2>
<table><thead><tr><th></th><th>Command</th><th>Blocked path</th><th>Exit</th><th>Duration</th><th>When</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="6" class="muted">No audit entries yet.</td></tr>'}</tbody></table>
<footer>Glassbox is a macOS Seatbelt sandbox. Denials are kernel-enforced; the audit is local and never leaves this machine.</footer>
</main></body></html>"""
