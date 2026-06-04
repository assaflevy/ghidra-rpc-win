"""Tests for tool handlers (requires Ghidra — these are integration tests).

These tests require GHIDRA_INSTALL_DIR to be set and a running JVM.
Mark as skip if Ghidra is not available.
"""

import pytest

# These tests are integration tests that need Ghidra
pytestmark = pytest.mark.skipif(
    True,  # Skip by default — run manually with Ghidra available
    reason="Requires GHIDRA_INSTALL_DIR and Ghidra installation",
)


class TestToolsIntegration:
    """Integration tests for tool handlers with a real Ghidra instance."""
    pass
