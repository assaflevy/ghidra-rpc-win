"""Ghidra launchers for ghidra-rpc.

Provides context initialization for both headless and GUI modes.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from ghidra_rpc.session import Session


def _validate_ghidra_install() -> str:
    """Validate GHIDRA_INSTALL_DIR is set and points to a valid Ghidra installation."""
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not ghidra_dir:
        raise RuntimeError(
            "GHIDRA_INSTALL_DIR environment variable is not set.\n"
            "Set it to your Ghidra installation directory, e.g.:\n"
            "  export GHIDRA_INSTALL_DIR=/opt/ghidra_11.3\n"
            "See docs/install.md for details."
        )
    ghidra_path = Path(ghidra_dir)
    if not ghidra_path.is_dir():
        raise RuntimeError(
            f"GHIDRA_INSTALL_DIR points to a non-existent directory: {ghidra_dir}"
        )
    return ghidra_dir


def create_headless_context(session: Session):
    """Initialize PyGhidra in headless mode and return a HeadlessContext."""
    _validate_ghidra_install()

    import pyghidra
    pyghidra.start()

    from ghidra_rpc.server.context import HeadlessContext
    return HeadlessContext(session)


def create_gui_context(session: Session):
    """Initialize PyGhidra in GUI mode and return a GuiContext.

    Adapts the pattern from pyghidra-mcp's GuiPyGhidraMcpLauncher:
    - Re-exec into framework Python on macOS if needed
    - Launch Ghidra GUI in a background thread
    - Wait for the project to become active
    """
    _validate_ghidra_install()

    # macOS framework Python re-exec
    _ensure_macos_framework_python()

    import pyghidra
    from pyghidra.launcher import PyGhidraLauncher

    from ghidra_rpc.server._gui_launcher import GuiRpcLauncher
    from ghidra_rpc.server.context import GuiContext

    launcher = GuiRpcLauncher(session.project_gpr)
    launcher.start()

    ctx = GuiContext(session, launcher)
    return ctx


# macOS framework Python handling (copied from pyghidra-mcp)
_REEXEC_ENV = "GHIDRA_RPC_REEXEC"


def _framework_python_path() -> Path:
    return Path(sys.base_exec_prefix) / "Resources/Python.app/Contents/MacOS/Python"


def _ensure_macos_framework_python() -> None:
    """Re-exec into framework Python before JVM startup when GUI mode needs it."""
    if sys.platform != "darwin":
        return
    if os.environ.get(_REEXEC_ENV):
        return
    framework_python = _framework_python_path()
    if not framework_python.exists():
        return
    if Path(sys.executable).resolve() == framework_python.resolve():
        return
    env = os.environ.copy()
    env[_REEXEC_ENV] = "1"
    os.execve(
        str(framework_python),
        [sys.executable, "-m", "ghidra_rpc.daemon", *sys.argv[1:]],
        env,
    )
