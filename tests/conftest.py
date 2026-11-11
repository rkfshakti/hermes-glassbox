"""Make the plugin directory importable as a normal package in tests.

Hermes loads directory plugins under a synthetic package name, so production code uses
relative imports. Tests need the same modules without Hermes' loader; a namespace module
with ``__path__`` gives us ``glassbox.policy`` and friends without executing ``__init__``
(which imports Hermes).
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if "glassbox" not in sys.modules:
    package = types.ModuleType("glassbox")
    package.__path__ = [str(ROOT)]
    sys.modules["glassbox"] = package
