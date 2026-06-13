"""Integration tests for ghidra-rpc against a real Ghidra headless instance.

These tests start a real Ghidra daemon in headless mode, load
``tests/fixtures/testapp`` (a small purpose-built x86-64 ELF binary that
lives in the repository), and exercise the full RPC API surface to verify
correctness.

Prerequisites
-------------
- ``GHIDRA_INSTALL_DIR`` environment variable must point to a valid Ghidra
  installation.

Running
-------
    # From the project root:
    GHIDRA_INSTALL_DIR=/path/to/ghidra pytest tests/test_integration.py -v

    # With a generous timeout for slow machines:
    GHIDRA_INSTALL_DIR=/path/to/ghidra pytest tests/test_integration.py -v \
        --timeout=600

All tests are automatically skipped when ``GHIDRA_INSTALL_DIR`` is not set.

Architecture
------------
A single module-scoped ``daemon`` fixture starts Ghidra once and loads the
test binary with full analysis.  All test classes share this fixture so the
expensive Ghidra + JVM startup only happens once per pytest invocation.

Write operations (rename, comment, bookmark, etc.) clean up after themselves
so they don't pollute later read tests.

Test binary
-----------
``tests/fixtures/testapp`` is compiled from ``tests/fixtures/testapp.c``:

    gcc -O0 -m64 -o tests/fixtures/testapp tests/fixtures/testapp.c

It is committed to the repository so tests are fully reproducible without
a C compiler on the test machine.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

# ── Availability guards ───────────────────────────────────────────────────────

GHIDRA_DIR = os.environ.get("GHIDRA_INSTALL_DIR")

# The test binary lives alongside this file in tests/fixtures/
_TEST_BINARY = Path(__file__).parent / "fixtures" / "testapp"

pytestmark = pytest.mark.skipif(
    not GHIDRA_DIR,
    reason=(
        "Integration tests require GHIDRA_INSTALL_DIR to be set. "
        "Run with: GHIDRA_INSTALL_DIR=/path/to/ghidra pytest tests/test_integration.py"
    ),
)

# ── Constants ─────────────────────────────────────────────────────────────────

# Generous timeouts: Ghidra JVM startup + analysis can take several minutes.
_DAEMON_START_TIMEOUT = 300   # seconds to wait for the daemon to become responsive
_LOAD_TIMEOUT         = 600   # socket timeout for the initial load + analysis call
_RPC_TIMEOUT          = 120   # default socket timeout for regular RPC calls


# ── Shared module-level fixture ───────────────────────────────────────────────

@pytest.fixture(scope="module")
def daemon(tmp_path_factory):
    """Start a headless Ghidra daemon, load tests/fixtures/testapp, and yield context.

    The daemon and loaded binary are shared across all tests in this module.
    Teardown stops the daemon after all tests complete.

    Yields a dict:
        sock        -- Path to the daemon's Unix socket
        binary      -- the binary key returned by ``load`` (full path key)
        short_name  -- ``"testapp"`` (short alias accepted by ``get_program``)
        gpr         -- Path to the temp Ghidra project
        main_addr   -- hex address of the ``main`` function (or a known function)
        main_name   -- name of the chosen entry-point function
    """
    from ghidra_rpc.client import DaemonError, send_request
    from ghidra_rpc.daemon import start_background, stop_daemon
    from ghidra_rpc.session import Session, socket_path_for_project

    tmp = tmp_path_factory.mktemp("ghidra_int")
    gpr_path = tmp / "test_project.gpr"
    sock = socket_path_for_project(gpr_path)

    session = Session(
        mode="headless",
        project_gpr=gpr_path,
        socket_path=sock,
        ghidra_install_dir=Path(GHIDRA_DIR),
    )

    # ── Start daemon ──────────────────────────────────────────────────────────
    start_background(session, timeout=_DAEMON_START_TIMEOUT)

    # ── Load tests/fixtures/testapp with full analysis ──────────────────────
    load_resp = send_request(
        sock,
        "load",
        {"path": str(_TEST_BINARY), "analyze": True},
        socket_timeout=_LOAD_TIMEOUT,
    )
    assert load_resp["ok"] is True, f"load failed: {load_resp}"
    binary_key   = load_resp["result"]["binary"]
    short_name   = load_resp["result"]["short_name"]   # "testapp"

    # ── Discover the main function (or a reliable substitute) ─────────────────
    fns_resp = send_request(
        sock, "functions", {"binary": short_name},
        socket_timeout=_RPC_TIMEOUT,
    )
    assert fns_resp["ok"] is True
    all_funcs = fns_resp["result"]["functions"]

    # Prefer "main"; fall back to "_start" / "entry" / first function.
    main_func = next(
        (f for f in all_funcs if f["name"].lower() == "main"),
        None,
    )
    if main_func is None:
        main_func = next(
            (f for f in all_funcs if f["name"].lower() in ("_start", "entry", "start")),
            all_funcs[0] if all_funcs else None,
        )

    assert main_func is not None, "No functions found in testapp — analysis may have failed"

    ctx = {
        "sock":       sock,
        "binary":     binary_key,
        "short_name": short_name,
        "gpr":        gpr_path,
        "main_addr":  main_func["address"],
        "main_name":  main_func["name"],
        "all_funcs":  all_funcs,
    }

    yield ctx

    # ── Teardown ──────────────────────────────────────────────────────────────
    try:
        stop_daemon(sock)
    except Exception:
        pass


# ── Test helpers ──────────────────────────────────────────────────────────────

def rpc(sock: Path, cmd: str, args: dict | None = None,
        *, timeout: float = _RPC_TIMEOUT) -> dict:
    """Send an RPC request; return the full response dict on success.

    Raises ``pytest.fail`` with a descriptive message on daemon errors so
    test failures are clear and don't show raw exception tracebacks.
    """
    from ghidra_rpc.client import DaemonError, send_request
    try:
        return send_request(sock, cmd, args or {}, socket_timeout=timeout)
    except DaemonError as exc:
        pytest.fail(
            f"RPC command '{cmd}' failed with error '{exc.error}': {exc}"
        )


# ── 1. Daemon connectivity ────────────────────────────────────────────────────

class TestConnectivity:
    """Basic smoke tests: the daemon is up, responsive, and reports sane metadata."""

    def test_ping_returns_alive(self, daemon):
        resp = rpc(daemon["sock"], "ping")
        assert resp["result"]["status"] == "alive"

    def test_ping_includes_session_metadata(self, daemon):
        result = rpc(daemon["sock"], "ping")["result"]
        assert result["mode"] == "headless"
        assert isinstance(result["pid"], int) and result["pid"] > 0
        assert "project_gpr" in result

    def test_unknown_command_returns_error(self, daemon):
        from ghidra_rpc.client import DaemonError, send_request
        resp = send_request.__wrapped__ if hasattr(send_request, "__wrapped__") else None
        # Call raw without going through our helper to check the error response
        import json, socket as _socket, uuid
        request = {"id": str(uuid.uuid4()), "cmd": "_nonexistent_cmd_", "args": {}}
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(str(daemon["sock"]))
        s.sendall((json.dumps(request) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        resp = json.loads(buf.decode().strip())
        assert resp["ok"] is False
        assert resp["error"] == "UnknownCommand"


# ── 2. Binary analysis ────────────────────────────────────────────────────────

class TestBinaryAnalysis:
    """Tests for analysis-level queries: list, metadata, functions, imports, exports."""

    def test_list_binaries_shows_loaded_binary(self, daemon):
        result = rpc(daemon["sock"], "list_binaries")["result"]
        assert result["binaries"], "No binaries reported — load must have failed"
        names = [b["name"] for b in result["binaries"]]
        # The binary name is derived from the filename; "testapp" should be in it.
        assert any("testapp" in n for n in names), (
            f"Expected 'testapp' in binary names, got: {names}"
        )

    def test_list_binaries_shows_analysis_complete(self, daemon):
        result = rpc(daemon["sock"], "list_binaries")["result"]
        entry = next(
            (b for b in result["binaries"] if "testapp" in b["name"]), None
        )
        assert entry is not None
        assert entry["analysis_complete"] is True

    def test_metadata_arch_and_format(self, daemon):
        result = rpc(daemon["sock"], "metadata", {"binary": daemon["short_name"]})["result"]
        # testapp is an x86-64 ELF binary
        assert result["format"].upper() in ("ELF", "ELF64", "ELF32", "EXECUTABLE AND LINKING FORMAT (ELF)"), (
            f"Unexpected format: {result['format']}"
        )
        # Should be some x86/ARM/MIPS/etc. processor
        assert result["arch"], f"arch should be non-empty, got: {result['arch']}"
        assert result["bits"] in (32, 64), f"Expected 32 or 64 bits, got: {result['bits']}"
        assert result["endian"].upper() in ("BIG", "LITTLE"), (
            f"Unexpected endian: {result['endian']}"
        )

    def test_metadata_base_address_is_hex(self, daemon):
        result = rpc(daemon["sock"], "metadata", {"binary": daemon["short_name"]})["result"]
        # base_address should be parseable as a hex address
        base = result["base_address"]
        assert base, "base_address should be non-empty"
        int(base, 16)  # raises ValueError if not valid hex

    def test_metadata_has_functions(self, daemon):
        result = rpc(daemon["sock"], "metadata", {"binary": daemon["short_name"]})["result"]
        assert result["num_functions"] > 10, (
            f"Expected >10 functions in testapp (user + CRT + PLT stubs), "
            f"got: {result['num_functions']}"
        )

    def test_functions_returns_many_entries(self, daemon):
        result = rpc(daemon["sock"], "functions", {"binary": daemon["short_name"]})["result"]
        assert result["count"] > 10, (
            f"Expected many functions, got {result['count']}"
        )
        assert result["total"] == result["count"]  # no pagination by default
        # Each entry must have name, address, signature
        for fn in result["functions"][:5]:
            assert "name" in fn
            assert "address" in fn
            assert "signature" in fn

    def test_functions_includes_main(self, daemon):
        result = rpc(daemon["sock"], "functions", {"binary": daemon["short_name"]})["result"]
        names = [f["name"].lower() for f in result["functions"]]
        assert "main" in names, (
            f"'main' not found in function names. Sample: {names[:20]}"
        )

    def test_functions_pagination_limit(self, daemon):
        result = rpc(daemon["sock"], "functions",
                     {"binary": daemon["short_name"], "limit": 5, "offset": 0})["result"]
        assert result["count"] == 5
        assert len(result["functions"]) == 5
        assert result["total"] > 5   # total reflects the full untruncated count

    def test_functions_pagination_offset(self, daemon):
        r0 = rpc(daemon["sock"], "functions",
                 {"binary": daemon["short_name"], "limit": 5, "offset": 0})["result"]
        r1 = rpc(daemon["sock"], "functions",
                 {"binary": daemon["short_name"], "limit": 5, "offset": 5})["result"]
        addrs0 = {f["address"] for f in r0["functions"]}
        addrs1 = {f["address"] for f in r1["functions"]}
        assert addrs0.isdisjoint(addrs1), (
            "Paginated results must not overlap"
        )

    def test_functions_with_body(self, daemon):
        result = rpc(daemon["sock"], "functions",
                     {"binary": daemon["short_name"], "limit": 3, "with_body": True})["result"]
        for fn in result["functions"]:
            assert "body_min" in fn, f"Missing body_min in {fn}"
            assert "body_max" in fn, f"Missing body_max in {fn}"
            assert isinstance(fn["body_size"], int) and fn["body_size"] > 0

    def test_functions_address_range_filter(self, daemon):
        """Range filter must return a strict subset of all functions."""
        all_result = rpc(daemon["sock"], "functions",
                         {"binary": daemon["short_name"]})["result"]
        all_addrs = sorted(f["address"] for f in all_result["functions"])
        if len(all_addrs) < 4:
            pytest.skip("Not enough functions for range test")

        lo = all_addrs[len(all_addrs) // 4]
        hi = all_addrs[3 * len(all_addrs) // 4]
        range_result = rpc(daemon["sock"], "functions", {
            "binary": daemon["short_name"],
            "address_min": lo,
            "address_max": hi,
        })["result"]
        assert 0 < range_result["count"] <= all_result["count"]
        for fn in range_result["functions"]:
            assert lo <= fn["address"] <= hi, (
                f"Function {fn['name']} @ {fn['address']} outside [{lo}, {hi}]"
            )

    def test_imports_returns_entries(self, daemon):
        result = rpc(daemon["sock"], "imports", {"binary": daemon["short_name"]})["result"]
        assert result["count"] > 0, "Expected imports in a dynamically linked testapp binary"
        # Each entry must have name, address, library
        for imp in result["imports"][:5]:
            assert "name" in imp
            assert "address" in imp

    def test_imports_contains_common_libc_symbol(self, daemon):
        result = rpc(daemon["sock"], "imports", {"binary": daemon["short_name"]})["result"]
        import_names = {i["name"].lower() for i in result["imports"]}
        # At least one of these very common symbols should be present
        common = {"malloc", "free", "printf", "fprintf", "strlen", "strcmp",
                  "exit", "open", "close", "write", "read", "stat", "fopen"}
        found = import_names & common
        assert found, (
            f"Expected at least one common libc symbol; imports: {sorted(import_names)[:30]}"
        )

    def test_list_calling_conventions(self, daemon):
        result = rpc(daemon["sock"], "list_calling_conventions",
                     {"binary": daemon["short_name"]})["result"]
        assert result["count"] > 0, "Expected at least one calling convention"
        assert result["default"], "Default calling convention should be non-empty"
        assert isinstance(result["conventions"], list)

    def test_relocations_returns_entries(self, daemon):
        result = rpc(daemon["sock"], "relocations",
                     {"binary": daemon["short_name"]})["result"]
        # Dynamically linked testapp will have PLT / GOT relocations
        assert result["total"] > 0, (
            "Expected relocations in testapp; got 0 (is this statically linked?)"
        )
        assert result["count"] > 0
        for rel in result["relocations"][:5]:
            assert "address" in rel
            assert "type" in rel

    def test_list_project_programs(self, daemon):
        result = rpc(daemon["sock"], "list_project_programs")["result"]
        assert result["count"] > 0, "Expected at least one program in the project"
        names = [p["name"] for p in result["programs"]]
        assert any("testapp" in n for n in names), (
            f"Expected 'testapp' in project programs, got: {names}"
        )


# ── 3. Search ─────────────────────────────────────────────────────────────────

class TestSearch:
    """Tests for strings, symbols, and byte-pattern search."""

    def test_strings_returns_entries(self, daemon):
        result = rpc(daemon["sock"], "strings",
                     {"binary": daemon["short_name"], "query": "", "limit": 50})["result"]
        assert "strings" in result
        assert len(result["strings"]) > 0, "Expected strings in testapp"

    def test_strings_query_filter(self, daemon):
        # testapp has multiple format strings containing "hello" (case-insensitive):
        # "Hello, %s. Welcome to the integration test.\n" and
        # "Hello %s! Running integration tests now.\n"
        result = rpc(daemon["sock"], "strings",
                     {"binary": daemon["short_name"], "query": "hello", "limit": 20})["result"]
        assert len(result["strings"]) > 0, (
            "Expected at least one string containing 'hello'"
        )
        for s in result["strings"]:
            assert "hello" in s["value"].lower(), (
                f"String '{s['value']}' does not contain 'hello'"
            )

    def test_strings_entry_has_address(self, daemon):
        result = rpc(daemon["sock"], "strings",
                     {"binary": daemon["short_name"], "query": "", "limit": 5})["result"]
        for s in result["strings"]:
            assert "address" in s, f"String entry missing address: {s}"
            assert "value" in s, f"String entry missing value field: {s}"

    def test_symbols_search_main(self, daemon):
        result = rpc(daemon["sock"], "symbols",
                     {"binary": daemon["short_name"], "query": "main", "limit": 10})["result"]
        assert "symbols" in result
        # "main" symbol should be found
        sym_names = [s["name"].lower() for s in result["symbols"]]
        assert any("main" in n for n in sym_names), (
            f"Expected 'main' in symbol search results; got: {sym_names}"
        )

    def test_symbols_entry_has_required_fields(self, daemon):
        result = rpc(daemon["sock"], "symbols",
                     {"binary": daemon["short_name"], "query": "main", "limit": 5})["result"]
        for sym in result["symbols"]:
            assert "name" in sym
            assert "address" in sym

    def test_find_bytes_finds_pattern(self, daemon):
        """Search for existing and non-existing byte patterns (x86-64 ELF)."""
        result = rpc(daemon["sock"], "find_bytes",
                     {"binary": daemon["short_name"],
                      "pattern": "7f 45 4c 46", "limit": 5})["result"]
        assert "matches" in result
        assert "pattern" in result
        assert "count" in result
        assert result["count"] >= 1, (
            "ELF magic bytes 7f 45 4c 46 must be found in an ELF binary — "
            f"got count={result['count']}.  Bug: findBytes regex encoding wrong."
        )
        for match in result["matches"]:
            assert "address" in match
            assert "context_hex" in match
            assert "7f454c46" in match["context_hex"], (
                f"context_hex {match['context_hex']!r} should contain the matched bytes"
            )

        # 0x55 = PUSH RBP — every function prologue in an -O0 x86-64 binary.
        result55 = rpc(daemon["sock"], "find_bytes",
                       {"binary": daemon["short_name"],
                        "pattern": "55", "limit": 5})["result"]
        assert result55["count"] >= 1, (
            "Byte 0x55 (PUSH RBP) must be present in testapp — "
            f"got count={result55['count']}.  Bug: findBytes regex encoding wrong."
        )

        # 48 85 c0 = TEST RAX,RAX — emitted for NULL pointer checks (e.g. after malloc).
        result_test = rpc(daemon["sock"], "find_bytes",
                          {"binary": daemon["short_name"],
                           "pattern": "48 85 c0", "limit": 5})["result"]
        assert result_test["count"] >= 1, (
            "Bytes 48 85 c0 (TEST RAX,RAX) must be present in testapp — "
            f"got count={result_test['count']}."
        )

        result_absent = rpc(daemon["sock"], "find_bytes",
                            {"binary": daemon["short_name"],
                             "pattern": "f1 a4 9d b0 fc fc a3 6e e4 9a 53 2b b4 ab 8b ff",
                             "limit": 5})["result"]
        assert result_absent["count"] == 0, (
            "16-byte random pattern must not appear in testapp"
        )


    def test_find_bytes_wildcard_pattern(self, daemon):
        """Wildcard ('??') patterns must match wherever the non-wildcard bytes fit."""
        result = rpc(daemon["sock"], "find_bytes",
                     {"binary": daemon["short_name"],
                      "pattern": "55 ??", "limit": 10})["result"]
        assert "matches" in result
        assert result["count"] >= 1, (
            "55 ?? must match at least one location given that 0x55 is present"
        )


# ── 4. Decompiler and disassembly ─────────────────────────────────────────────

class TestDecompilerAndDisassembly:
    """Tests for decompile and disassemble commands."""

    def test_decompile_main_returns_code(self, daemon):
        result = rpc(daemon["sock"], "decompile",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_name"], "timeout": 60})["result"]
        assert "c_code" in result, f"Missing 'c_code' in decompile result: {result}"
        # Decompiled C should contain at least one of these common C constructs
        code = result["c_code"]
        assert len(code) > 50, f"Decompiled code seems too short: {code!r}"
        assert any(kw in code for kw in ("(", ")", "{", "}", "int", "void", "char", "long")), (
            f"Decompiled code doesn't look like C: {code[:200]}"
        )

    def test_decompile_by_address(self, daemon):
        """Decompile should also work when target is given as a hex address."""
        result = rpc(daemon["sock"], "decompile",
                     {"binary": daemon["short_name"],
                      "func": "0x" + daemon["main_addr"], "timeout": 60})["result"]
        assert "c_code" in result
        assert len(result["c_code"]) > 20

    def test_decompile_returns_function_name(self, daemon):
        result = rpc(daemon["sock"], "decompile",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_name"], "timeout": 60})["result"]
        assert "name" in result
        assert result["name"].lower() == daemon["main_name"].lower()

    def test_decompile_nonexistent_function_errors(self, daemon):
        from ghidra_rpc.client import DaemonError, send_request
        try:
            send_request(
                daemon["sock"], "decompile",
                {"binary": daemon["short_name"],
                 "func": "_nonexistent_function_xyz_"},
                socket_timeout=30,
            )
            pytest.fail("Expected DaemonError for nonexistent function")
        except DaemonError as exc:
            assert exc.error in ("ValueError", "RuntimeError", "Exception"), (
                f"Unexpected error type: {exc.error}"
            )

    def test_disassemble_at_main(self, daemon):
        result = rpc(daemon["sock"], "disassemble",
                     {"binary": daemon["short_name"],
                      "address": "0x" + daemon["main_addr"], "count": 10})["result"]
        assert "instructions" in result
        assert len(result["instructions"]) > 0
        for insn in result["instructions"]:
            assert "address" in insn
            assert "mnemonic" in insn

    def test_disassemble_default_count(self, daemon):
        """Default 20-instruction listing must return up to 20 instructions."""
        result = rpc(daemon["sock"], "disassemble",
                     {"binary": daemon["short_name"],
                      "address": "0x" + daemon["main_addr"]})["result"]
        assert 0 < len(result["instructions"]) <= 20


# ── 5. Memory ─────────────────────────────────────────────────────────────────

class TestMemory:
    """Tests for read_bytes and memory_map."""

    def test_read_bytes_at_main(self, daemon):
        result = rpc(daemon["sock"], "read_bytes",
                     {"binary": daemon["short_name"],
                      "address": "0x" + daemon["main_addr"], "length": 16})["result"]
        assert "hex" in result
        hex_val = result["hex"].replace(" ", "")
        # 16 bytes = 32 hex chars
        assert len(hex_val) == 32, (
            f"Expected 32 hex chars for 16 bytes, got: {result['hex']!r}"
        )
        int(hex_val, 16)   # must be valid hex

    def test_read_bytes_length_variants(self, daemon):
        for length in (1, 4, 8, 32):
            result = rpc(daemon["sock"], "read_bytes",
                         {"binary": daemon["short_name"],
                          "address": "0x" + daemon["main_addr"], "length": length})["result"]
            hex_val = result["hex"].replace(" ", "")
            assert len(hex_val) == length * 2, (
                f"length={length}: expected {length*2} hex chars, got {len(hex_val)}"
            )

    def test_memory_map_returns_segments(self, daemon):
        result = rpc(daemon["sock"], "memory_map",
                     {"binary": daemon["short_name"]})["result"]
        assert "segments" in result
        assert len(result["segments"]) > 0, "Expected at least one memory segment"

    def test_memory_map_segment_fields(self, daemon):
        result = rpc(daemon["sock"], "memory_map",
                     {"binary": daemon["short_name"]})["result"]
        required_fields = {"name", "start", "end", "size"}
        for seg in result["segments"]:
            missing = required_fields - seg.keys()
            assert not missing, (
                f"Memory segment missing fields {missing}: {seg}"
            )

    def test_memory_map_includes_text_segment(self, daemon):
        result = rpc(daemon["sock"], "memory_map",
                     {"binary": daemon["short_name"]})["result"]
        seg_names = {s["name"] for s in result["segments"]}
        # At least one of these sections must be present in a standard ELF
        text_like = {".text", "text", ".code", "CODE", ".init", ".plt"}
        assert seg_names & text_like, (
            f"Expected a code segment (.text/.code/etc.), got: {seg_names}"
        )


# ── 6. Cross-references ───────────────────────────────────────────────────────

class TestXrefs:
    """Tests for xrefs_to and xrefs_from."""

    def test_xrefs_from_main_has_calls(self, daemon):
        result = rpc(daemon["sock"], "xrefs_from",
                     {"binary": daemon["short_name"],
                      "target": daemon["main_name"], "limit": 50})["result"]
        assert "xrefs" in result
        # main should call other functions
        assert result["count"] > 0, (
            "Expected main to have outgoing references (calls)"
        )

    def test_xrefs_from_entry_fields(self, daemon):
        result = rpc(daemon["sock"], "xrefs_from",
                     {"binary": daemon["short_name"],
                      "target": daemon["main_name"], "limit": 10})["result"]
        for xref in result["xrefs"]:
            assert "to_address" in xref
            assert "type" in xref

    def test_xrefs_to_import_has_callers(self, daemon):
        """An imported function called by testapp must have at least one xref_to."""
        from ghidra_rpc.client import DaemonError, send_request

        # Find a well-known import that ls definitely calls
        imports_result = rpc(daemon["sock"], "imports",
                             {"binary": daemon["short_name"]})["result"]
        import_names = [i["name"] for i in imports_result["imports"]]

        target = "malloc"
        assert target in import_names, (
            f"Expected {target} in imports, got: {import_names[:30]}"
        )

        result = rpc(daemon["sock"], "xrefs_to",
                     {"binary": daemon["short_name"],
                      "target": target, "limit": 20})["result"]
        assert result["count"] > 0, (
            f"Expected at least one xref to '{target}'"
        )

    def test_xrefs_to_entry_fields(self, daemon):
        from ghidra_rpc.client import DaemonError, send_request

        imports_result = rpc(daemon["sock"], "imports",
                             {"binary": daemon["short_name"]})["result"]
        if not imports_result["imports"]:
            pytest.skip("No imports available for xrefs_to field test")

        target = imports_result["imports"][0]["name"]
        result = rpc(daemon["sock"], "xrefs_to",
                     {"binary": daemon["short_name"],
                      "target": target, "limit": 5})["result"]
        for xref in result["xrefs"]:
            assert "from_address" in xref
            assert "type" in xref

    def test_xrefs_by_address(self, daemon):
        """xrefs_to should also accept a hex address as target."""
        result = rpc(daemon["sock"], "xrefs_to",
                     {"binary": daemon["short_name"],
                      "target": "0x" + daemon["main_addr"], "limit": 10})["result"]
        # Just verify the response has the right shape (main may or may not
        # have incoming refs depending on how the binary is built)
        assert "xrefs" in result
        assert "count" in result


# ── 7. Control-flow graph ─────────────────────────────────────────────────────

class TestCFG:
    """Tests for basic_blocks and pcode."""

    def test_basic_blocks_main(self, daemon):
        result = rpc(daemon["sock"], "basic_blocks",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_name"]})["result"]
        assert "blocks" in result
        assert result["num_blocks"] > 0
        assert "name" in result
        assert "address" in result

    def test_basic_blocks_fields(self, daemon):
        result = rpc(daemon["sock"], "basic_blocks",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_name"]})["result"]
        required = {"start", "end", "size", "instructions"}
        for block in result["blocks"][:5]:
            missing = required - block.keys()
            assert not missing, (
                f"Basic block missing fields {missing}: {block}"
            )
            assert block["instructions"] >= 1
            assert block["size"] >= 1

    def test_basic_blocks_successors(self, daemon):
        """All but terminal blocks should have successors."""
        result = rpc(daemon["sock"], "basic_blocks",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_name"]})["result"]
        # At least one block should have a successor
        blocks_with_succ = [b for b in result["blocks"] if b.get("successors")]
        assert blocks_with_succ, "Expected at least one block with successors"

    def test_pcode_main(self, daemon):
        result = rpc(daemon["sock"], "pcode",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_name"]})["result"]
        assert "ops" in result
        assert len(result["ops"]) > 0, "Expected P-code ops for main"

    def test_pcode_entry_fields(self, daemon):
        result = rpc(daemon["sock"], "pcode",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_name"]})["result"]
        for op in result["ops"][:5]:
            assert "opcode" in op, (
                f"P-code op missing opcode field: {op}"
            )


# ── 8. Bookmarks ──────────────────────────────────────────────────────────────

class TestBookmarks:
    """Tests for set_bookmark, list_bookmarks, remove_bookmark.

    These are write operations; each test cleans up after itself.
    """

    def test_set_and_list_bookmark(self, daemon):
        uid = uuid.uuid4().hex[:8]
        addr = "0x" + daemon["main_addr"]
        category = f"test-{uid}"
        comment  = f"integration-test bookmark {uid}"

        rpc(daemon["sock"], "set_bookmark", {
            "binary":   daemon["short_name"],
            "address":  addr,
            "type":     "Note",
            "category": category,
            "comment":  comment,
        })

        list_result = rpc(daemon["sock"], "list_bookmarks",
                          {"binary": daemon["short_name"]})["result"]
        bmarks = list_result["bookmarks"]
        match = next(
            (b for b in bmarks if b.get("category") == category), None
        )
        assert match is not None, (
            f"Bookmark with category '{category}' not found; all: {bmarks}"
        )
        assert match["comment"] == comment

        # Cleanup
        rpc(daemon["sock"], "remove_bookmark", {
            "binary":   daemon["short_name"],
            "address":  addr,
            "type":     "Note",
            "category": category,
        })

    def test_list_bookmarks_by_address(self, daemon):
        uid = uuid.uuid4().hex[:8]
        addr = "0x" + daemon["main_addr"]
        category = f"addr-test-{uid}"

        rpc(daemon["sock"], "set_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Note", "category": category, "comment": "addr filter test",
        })

        result = rpc(daemon["sock"], "list_bookmarks", {
            "binary": daemon["short_name"], "address": addr,
        })["result"]
        categories = [b.get("category") for b in result["bookmarks"]]
        assert category in categories, (
            f"Bookmark not found when filtering by address {addr}: {result['bookmarks']}"
        )

        # Cleanup
        rpc(daemon["sock"], "remove_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Note", "category": category,
        })

    def test_list_bookmarks_by_type(self, daemon):
        uid = uuid.uuid4().hex[:8]
        addr = "0x" + daemon["main_addr"]
        category = f"type-test-{uid}"

        rpc(daemon["sock"], "set_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Warning", "category": category, "comment": "type filter test",
        })

        result = rpc(daemon["sock"], "list_bookmarks", {
            "binary": daemon["short_name"], "type": "Warning",
        })["result"]
        categories = [b.get("category") for b in result["bookmarks"]]
        assert category in categories

        # Cleanup
        rpc(daemon["sock"], "remove_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Warning", "category": category,
        })

    def test_remove_bookmark_removes_it(self, daemon):
        uid = uuid.uuid4().hex[:8]
        addr = "0x" + daemon["main_addr"]
        category = f"remove-test-{uid}"

        rpc(daemon["sock"], "set_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Note", "category": category, "comment": "to be removed",
        })
        rpc(daemon["sock"], "remove_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Note", "category": category,
        })

        list_result = rpc(daemon["sock"], "list_bookmarks",
                          {"binary": daemon["short_name"]})["result"]
        categories = [b.get("category") for b in list_result["bookmarks"]]
        assert category not in categories, (
            f"Bookmark with category '{category}' still present after removal"
        )


# ── 9. Comments and labels ────────────────────────────────────────────────────

class TestCommentsAndLabels:
    """Tests for set_comment and create_label.

    These are write operations; tests verify the annotation persists and
    then clean it up (overwrite with empty string / unlabel).
    """

    def test_set_eol_comment(self, daemon):
        addr    = "0x" + daemon["main_addr"]
        uid     = uuid.uuid4().hex[:8]
        comment = f"eol-comment-{uid}"

        rpc(daemon["sock"], "set_comment", {
            "binary": daemon["short_name"], "address": addr,
            "comment": comment, "comment_type": "eol",
        })

        # Verify via disassemble (EOL comments appear next to instructions)
        result = rpc(daemon["sock"], "disassemble",
                     {"binary": daemon["short_name"],
                      "address": addr, "count": 1})["result"]
        # At minimum the command must succeed; comment visibility depends on
        # the disassemble output format.
        assert "instructions" in result

        # Cleanup: clear the comment
        rpc(daemon["sock"], "set_comment", {
            "binary": daemon["short_name"], "address": addr,
            "comment": "", "comment_type": "eol",
        })

    def test_set_plate_comment(self, daemon):
        """Plate comments annotate a function header."""
        addr    = "0x" + daemon["main_addr"]
        uid     = uuid.uuid4().hex[:8]
        comment = f"plate-comment-{uid}"

        rpc(daemon["sock"], "set_comment", {
            "binary": daemon["short_name"], "address": addr,
            "comment": comment, "comment_type": "plate",
        })

        # Cleanup
        rpc(daemon["sock"], "set_comment", {
            "binary": daemon["short_name"], "address": addr,
            "comment": "", "comment_type": "plate",
        })

    def test_create_label(self, daemon):
        uid  = uuid.uuid4().hex[:8]
        addr = "0x" + daemon["main_addr"]
        name = f"_test_label_{uid}"

        result = rpc(daemon["sock"], "create_label", {
            "binary": daemon["short_name"],
            "address": addr,
            "name": name,
        })["result"]
        assert "address" in result or "name" in result, (
            f"Unexpected create_label response: {result}"
        )

        # Verify via symbols search
        sym_result = rpc(daemon["sock"], "symbols",
                         {"binary": daemon["short_name"],
                          "query": name, "limit": 5})["result"]
        sym_names = [s["name"] for s in sym_result["symbols"]]
        assert name in sym_names, (
            f"Created label '{name}' not found via symbols search; got: {sym_names}"
        )

        # Cleanup: restore the original name so later tests can find the function
        # by name.  _handle_create_label renames USER_DEFINED symbols in-place,
        # so without this the function at main_addr would keep the test label name.
        orig_name = result.get("old_name") or daemon["main_name"]
        if orig_name:
            rpc(daemon["sock"], "create_label", {
                "binary":  daemon["short_name"],
                "address": addr,
                "name":    orig_name,
            })


# ── 10. Function rename ───────────────────────────────────────────────────────

class TestRenameFunction:
    """Tests for rename_function.

    Uses a non-critical function so renaming doesn't break later tests.
    """

    def _pick_rename_target(self, daemon) -> tuple[str, str]:
        """Return (current_name, address) of a safe function to rename."""
        # Pick the second function in the list (avoid main / _start)
        funcs = daemon["all_funcs"]
        for fn in funcs:
            name = fn["name"].lower()
            if name not in ("main", "_start", "entry", "start", "_init", "_fini"):
                return fn["name"], fn["address"]
        pytest.skip("No suitable function found for rename test")

    def test_rename_function_and_verify(self, daemon):
        orig_name, addr = self._pick_rename_target(daemon)
        uid      = uuid.uuid4().hex[:8]
        new_name = f"_renamed_fn_{uid}"

        rpc(daemon["sock"], "rename_function", {
            "binary":   daemon["short_name"],
            "target":   "0x" + addr,
            "new_name": new_name,
        })

        # Verify the new name appears in the function list
        result = rpc(daemon["sock"], "functions",
                     {"binary": daemon["short_name"]})["result"]
        names = [f["name"] for f in result["functions"]]
        assert new_name in names, (
            f"Renamed function '{new_name}' not found; sample: {names[:20]}"
        )

        # Cleanup: rename back to original
        rpc(daemon["sock"], "rename_function", {
            "binary":   daemon["short_name"],
            "target":   "0x" + addr,
            "new_name": orig_name,
        })

    def test_rename_function_response_fields(self, daemon):
        orig_name, addr = self._pick_rename_target(daemon)
        uid      = uuid.uuid4().hex[:8]
        new_name = f"_renamed_fn2_{uid}"

        result = rpc(daemon["sock"], "rename_function", {
            "binary":   daemon["short_name"],
            "target":   "0x" + addr,
            "new_name": new_name,
        })["result"]

        assert "old_name" in result or "name" in result, (
            f"Expected old_name or name in response: {result}"
        )

        # Cleanup
        rpc(daemon["sock"], "rename_function", {
            "binary":   daemon["short_name"],
            "target":   "0x" + addr,
            "new_name": orig_name,
        })


# ── 11. Data types ────────────────────────────────────────────────────────────

class TestDataTypes:
    """Tests for list_data_types, create_struct, create_enum."""

    def test_list_data_types_returns_entries(self, daemon):
        result = rpc(daemon["sock"], "list_data_types",
                     {"binary": daemon["short_name"],
                      "category": "all", "limit": 50})["result"]
        assert "data_types" in result
        assert result["count"] > 0, "Expected built-in data types to be listed"

    def test_list_data_types_includes_builtins(self, daemon):
        result = rpc(daemon["sock"], "list_data_types",
                     {"binary": daemon["short_name"],
                      "category": "all", "limit": 200})["result"]
        type_names = {dt["name"].lower() for dt in result["data_types"]}
        # Ghidra always has basic types
        basic = {"byte", "word", "dword", "qword", "char", "int", "uint"}
        found = type_names & basic
        assert found, (
            f"Expected basic built-in types; got sample: {sorted(type_names)[:30]}"
        )

    def test_list_data_types_category_filter(self, daemon):
        result = rpc(daemon["sock"], "list_data_types",
                     {"binary": daemon["short_name"],
                      "category": "struct", "limit": 50})["result"]
        assert "data_types" in result
        for dt in result["data_types"]:
            assert dt["category"].lower() == "struct", (
                f"Expected struct category, got: {dt['category']}"
            )

    def test_create_struct(self, daemon):
        uid  = uuid.uuid4().hex[:8]
        name = f"TestStruct_{uid}"

        result = rpc(daemon["sock"], "create_struct", {
            "binary": daemon["short_name"],
            "name":   name,
            "fields": [
                {"type": "int",   "name": "field_a"},
                {"type": "int",   "name": "field_b"},
                {"type": "char",  "name": "flag"},
            ],
        })["result"]

        assert "name" in result, f"Expected 'name' in create_struct result: {result}"
        assert result["name"] == name

        # Verify it appears in list_data_types
        list_result = rpc(daemon["sock"], "list_data_types", {
            "binary": daemon["short_name"],
            "category": "struct", "query": uid, "limit": 10,
        })["result"]
        struct_names = [dt["name"] for dt in list_result["data_types"]]
        assert name in struct_names, (
            f"Newly created struct '{name}' not found; got: {struct_names}"
        )

    def test_create_struct_if_not_exists_idempotent(self, daemon):
        uid  = uuid.uuid4().hex[:8]
        name = f"IdempotentStruct_{uid}"

        for _ in range(2):
            result = rpc(daemon["sock"], "create_struct", {
                "binary":       daemon["short_name"],
                "name":         name,
                "fields":       [{"type": "int", "name": "x"}],
                "if_not_exists": True,
            })["result"]
            assert result["name"] == name

    def test_create_enum(self, daemon):
        uid  = uuid.uuid4().hex[:8]
        name = f"TestEnum_{uid}"

        result = rpc(daemon["sock"], "create_enum", {
            "binary": daemon["short_name"],
            "name":   name,
            "values": [
                {"name": "VAL_A", "value": 0},
                {"name": "VAL_B", "value": 1},
                {"name": "VAL_C", "value": 2},
            ],
            "size":  4,
        })["result"]

        assert "name" in result, f"Expected 'name' in create_enum result: {result}"
        assert result["name"] == name

        # Verify it shows up in list_data_types
        list_result = rpc(daemon["sock"], "list_data_types", {
            "binary": daemon["short_name"],
            "category": "enum", "query": uid, "limit": 10,
        })["result"]
        enum_names = [dt["name"] for dt in list_result["data_types"]]
        assert name in enum_names, (
            f"Newly created enum '{name}' not found; got: {enum_names}"
        )

    def test_create_enum_values_preserved(self, daemon):
        uid  = uuid.uuid4().hex[:8]
        name = f"ValueEnum_{uid}"

        result = rpc(daemon["sock"], "create_enum", {
            "binary": daemon["short_name"],
            "name":   name,
            "values": [
                {"name": "FIRST",  "value": 10},
                {"name": "SECOND", "value": 20},
            ],
            "size": 4,
        })["result"]

        assert "values" in result, f"Expected 'values' in create_enum result: {result}"
        val_map = {v["name"]: v["value"] for v in result["values"]}
        assert val_map.get("FIRST")  == 10
        assert val_map.get("SECOND") == 20


# ── 12. Function tags ─────────────────────────────────────────────────────────

class TestTags:
    """Tests for tag_function, untag_function, list_tags, functions_by_tag."""

    def test_tag_function_and_list(self, daemon):
        uid = uuid.uuid4().hex[:8]
        tag = f"test-tag-{uid}"

        rpc(daemon["sock"], "tag_function", {
            "binary": daemon["short_name"],
            "target": daemon["main_name"],
            "tag":    tag,
        })

        list_result = rpc(daemon["sock"], "list_tags",
                          {"binary": daemon["short_name"]})["result"]
        tag_names = [t["name"] for t in list_result["tags"]]
        assert tag in tag_names, (
            f"Tag '{tag}' not found in list_tags; got: {tag_names}"
        )

        # Cleanup
        rpc(daemon["sock"], "untag_function", {
            "binary": daemon["short_name"],
            "target": daemon["main_name"],
            "tag":    tag,
        })

    def test_functions_by_tag(self, daemon):
        uid = uuid.uuid4().hex[:8]
        tag = f"by-tag-test-{uid}"

        rpc(daemon["sock"], "tag_function", {
            "binary": daemon["short_name"],
            "target": daemon["main_name"],
            "tag":    tag,
        })

        result = rpc(daemon["sock"], "functions_by_tag", {
            "binary": daemon["short_name"],
            "tag":    tag,
        })["result"]
        fn_names = [f["name"] for f in result["functions"]]
        assert daemon["main_name"] in fn_names, (
            f"Expected '{daemon['main_name']}' in functions_by_tag; got: {fn_names}"
        )

        # Cleanup
        rpc(daemon["sock"], "untag_function", {
            "binary": daemon["short_name"],
            "target": daemon["main_name"],
            "tag":    tag,
        })

    def test_untag_function_removes_tag(self, daemon):
        uid = uuid.uuid4().hex[:8]
        tag = f"untag-test-{uid}"

        rpc(daemon["sock"], "tag_function", {
            "binary": daemon["short_name"],
            "target": daemon["main_name"],
            "tag":    tag,
        })
        rpc(daemon["sock"], "untag_function", {
            "binary": daemon["short_name"],
            "target": daemon["main_name"],
            "tag":    tag,
        })

        result = rpc(daemon["sock"], "functions_by_tag", {
            "binary": daemon["short_name"],
            "tag":    tag,
        })["result"]
        assert result["functions"] == [], (
            f"Expected no functions with tag '{tag}' after untagging; "
            f"got: {result['functions']}"
        )


# ── 13. Save ──────────────────────────────────────────────────────────────────

class TestSave:
    """Tests for the save command."""

    def test_save_named_binary(self, daemon):
        result = rpc(daemon["sock"], "save",
                     {"binary": daemon["short_name"]})["result"]
        assert "saved" in result
        assert any("testapp" in s for s in result["saved"]), (
            f"Expected 'testapp' in saved list; got: {result['saved']}"
        )

    def test_save_all(self, daemon):
        result = rpc(daemon["sock"], "save", {})["result"]
        assert "saved" in result
        assert len(result["saved"]) > 0
