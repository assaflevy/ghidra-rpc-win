"""Cross-platform RPC transport helpers.

Unix domain sockets are ideal on Linux/macOS, but Windows support is uneven in
Python and unavailable in some CI/user environments.  On Windows we use a
localhost TCP listener and persist the chosen port in a small endpoint file so
the rest of the code can continue to pass around a deterministic ``Path``.
"""

from __future__ import annotations

import hashlib
import os
import socket
import tempfile
from pathlib import Path
from typing import Callable


IS_WINDOWS = os.name == "nt"
HOST = "127.0.0.1"


def endpoint_path_for_project(gpr: Path) -> Path:
    """Return the deterministic endpoint path for a project."""
    digest = hashlib.sha256(str(gpr.resolve()).encode()).hexdigest()[:8]
    if IS_WINDOWS:
        return Path(tempfile.gettempdir()) / f"ghidra-rpc-{digest}.port"
    return Path(f"/tmp/ghidra-rpc-{digest}.sock")


def discover_endpoint_paths() -> list[Path]:
    """Find unregistered endpoint files created by running daemons."""
    if IS_WINDOWS:
        return sorted(Path(tempfile.gettempdir()).glob("ghidra-rpc-*.port"))
    return sorted(Path("/tmp").glob("ghidra-rpc-*.sock"))


def connect(endpoint_path: Path, timeout: float) -> socket.socket:
    """Connect to an endpoint file and return a configured socket."""
    if not endpoint_path.exists():
        raise FileNotFoundError(str(endpoint_path))

    if IS_WINDOWS:
        try:
            port = int(endpoint_path.read_text().strip())
        except (OSError, ValueError) as exc:
            raise ConnectionRefusedError(
                f"Invalid ghidra-rpc endpoint file: {endpoint_path}"
            ) from exc
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((HOST, port))
        return sock

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(str(endpoint_path))
    return sock


def create_server(endpoint_path: Path) -> tuple[socket.socket, Callable[[], None]]:
    """Create a listening server socket and a cleanup callback.

    On Windows the endpoint file is written only after ``listen`` succeeds, so
    clients never see a port file before the server is actually reachable.
    """
    if endpoint_path.exists():
        endpoint_path.unlink()
    endpoint_path.parent.mkdir(parents=True, exist_ok=True)

    if IS_WINDOWS:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, 0))
        server_sock.listen(5)
        endpoint_path.write_text(str(server_sock.getsockname()[1]))
    else:
        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(str(endpoint_path))
        server_sock.listen(5)

    def cleanup() -> None:
        server_sock.close()
        if endpoint_path.exists():
            endpoint_path.unlink()

    return server_sock, cleanup
