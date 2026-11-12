---
name: glassbox
description: Explain and operate the Glassbox macOS sandbox backend — what is allowed, why a command hit "Operation not permitted", how to read the containment audit, and how to request a policy change. Use when the user asks about sandboxing, blocked file or network access, or the safety of running a command on this Mac.
version: 1.1.0
metadata:
  hermes:
    tags: [security, sandbox, macos, seatbelt, audit]
---

# Glassbox

Glassbox is a Hermes terminal backend for macOS. When `terminal.backend` is `glassbox`,
every terminal, `execute_code`, `read_file`, `write_file`, `patch` and `search_files`
operation runs under a generated **Seatbelt** profile.

## The policy in one breath

- **Readable:** macOS system paths, the current workspace, and the private scratch area.
- **Writable:** the workspace (unless `workspace_writable` is off) and the scratch area.
- **Hidden:** the rest of the user's home — including `~/.ssh`, `~/.aws`, `~/.hermes`,
  keychains, mail, messages and browser profiles.
- **Network:** off by default.
- **IPC escape hatches:** `osascript`, `open`, `security` and `launchctl` are blocked,
  and Apple Events are denied.

## When a command fails with "Operation not permitted"

That is the kernel refusing the operation, not a bug in the command. Do not retry the
same path or try to copy the file somewhere else to get around it.

1. Call `glassbox_policy` for the working directory to see what is allowed.
2. Call `glassbox_report` to see the blocked path and the command that requested it.
3. Tell the user plainly what was blocked and why.
4. If the access is legitimate, ask the user to add an explicit allowance:
   `hermes config set plugins.entries.glassbox.settings.read_paths '["~/path"]'`
   (or `write_paths`). Do not edit the generated profile.
5. Changing `network`, `allow_home` or the path lists takes effect on the next command.

## Verifying the sandbox

Run `glassbox_verify` (or `hermes glassbox verify`). It checks workspace read/write,
home read/write denial, child-process confinement, parent traversal, network denial,
and secret-environment filtering. A pass means the kernel refused the canaries while
ordinary workspace work succeeded.

## Reading the audit

`glassbox_report` returns a summary and recent entries: command, cwd, exit code,
duration, blocked paths, and whether the network was suspected. The text report is
`hermes glassbox report`; the visual timeline is `hermes glassbox report --html --open`.
The audit is local, capped at 4 MB, and never transmitted.

## Limits to state honestly

- This is a Seatbelt sandbox, not a virtual machine. It does not defend against a
  kernel exploit, and a process the user deliberately launches outside the sandbox is
  outside the boundary.
- Commands run as the same UNIX user, with the same files the user can read *inside*
  the allowed roots. The sandbox removes access outside them; it is not a separate UID.
- Package installs that need the network require `network: true` (or a local mirror).
- Git commits work: the plugin copies the user's Git author name/email as environment
  variables, but `~/.gitconfig` itself stays hidden.
- Privilege escalation (`su`, password prompts in a shell) does not work inside the
  sandbox; that is intentional.
