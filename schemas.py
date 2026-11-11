"""Tool schemas — the descriptions the model reads."""

GLASSBOX_REPORT = {
    "name": "glassbox_report",
    "description": (
        "Show what the Glassbox sandbox recorded: commands run, exit codes, and any "
        "filesystem or network access the kernel blocked. Use this when the user asks "
        "what the agent tried to read or write, why a command failed with 'Operation "
        "not permitted', or what happened in a sandboxed session. The audit is local "
        "to this machine."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "How many recent commands to include (1-500, default 50).",
            },
            "session_id": {
                "type": "string",
                "description": "Only show entries for this session id. Omit for the current session.",
            },
            "include_commands": {
                "type": "boolean",
                "description": "Include command text in the recent entries (default true).",
            },
        },
        "required": [],
    },
}

GLASSBOX_POLICY = {
    "name": "glassbox_policy",
    "description": (
        "Explain the active Glassbox containment policy for a directory: the workspace, "
        "which paths are readable and writable, whether the home directory is hidden, "
        "whether network access is allowed, and the exact macOS Seatbelt profile. Use "
        "this before running a command that may need access outside the workspace."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "cwd": {
                "type": "string",
                "description": "Directory to build the policy for. Defaults to the current working directory.",
            },
        },
        "required": [],
    },
}

GLASSBOX_VERIFY = {
    "name": "glassbox_verify",
    "description": (
        "Run Glassbox's containment self-test: workspace read/write, home read/write "
        "denial, child-process confinement, parent traversal, network denial, and "
        "secret-environment filtering. Returns a pass/fail check list. Use this after "
        "installing or changing the backend, or when the user asks whether the sandbox "
        "is actually working."
    ),
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
    },
}
