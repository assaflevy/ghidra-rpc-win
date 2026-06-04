"""Memory inspection tools: read raw bytes from a program's address space."""

from __future__ import annotations

from ghidra_rpc.server.main import register_handler

_MAX_READ_BYTES = 65536  # 64 KB hard cap per request


def _handle_read_bytes(ctx, args: dict) -> dict:
    """Read raw bytes from a binary address.

    Args (in ``args`` dict):
        binary  -- program name / key
        address -- hex address string (e.g. ``0x102039`` or ``102039``)
        length  -- number of bytes to read (1 – 65536)

    Returns a dict with:
        address  -- canonical Ghidra address string
        length   -- number of bytes actually read
        hex      -- compact lowercase hex string (e.g. ``"257331307300"``)
        hexdump  -- formatted hex + ASCII dump (16 bytes per line), useful for display
    """
    from ghidra_rpc.server.context import _parse_address

    binary = args.get("binary", "")
    address_str = args.get("address", "")
    length = args.get("length")

    if not address_str:
        raise ValueError("Missing required argument: address")
    if length is None:
        raise ValueError("Missing required argument: length")

    length = int(length)
    if length < 1:
        raise ValueError("length must be >= 1")
    if length > _MAX_READ_BYTES:
        raise ValueError(f"length must be <= {_MAX_READ_BYTES} (requested {length})")

    pi = ctx.get_program(binary)
    addr = _parse_address(pi.program, address_str)

    # FlatProgramAPI.getBytes raises MemoryAccessException for unmapped ranges.
    try:
        java_bytes = pi.flat_api.getBytes(addr, length)
    except Exception as e:
        # Catch Java MemoryAccessException (and any other Ghidra memory error)
        raise ValueError(f"Memory read failed at {addr}: {e}")

    # JPype returns Java signed bytes (-128..127); convert to unsigned Python bytes.
    data = bytes(b & 0xFF for b in java_bytes)

    return {
        "address": str(addr),
        "length": len(data),
        "hex": data.hex(),
        "hexdump": _format_hexdump(addr, data),
    }


def _format_hexdump(start_addr, data: bytes, width: int = 16) -> str:
    """Return a classic hex+ASCII dump string.

    Example (width=16)::

        00102039  25 31 30 73 00 43 33 6c  6c 33 62 72 31 74 65 00  |%10s.C3ll3br1te.|
    """
    # Ghidra Address.toString() returns plain hex without 0x prefix (e.g. "00102039").
    # Parse it as base-16 for arithmetic.
    addr_str = str(start_addr)
    base = int(addr_str.lstrip("0") or "0", 16)

    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        line_addr = format(base + offset, "08x")
        # Two groups of 8 hex bytes separated by two spaces
        left  = chunk[:8]
        right = chunk[8:]
        hex_left  = " ".join(f"{b:02x}" for b in left)
        hex_right = " ".join(f"{b:02x}" for b in right)
        # Pad groups to fixed width so columns align even on the last (partial) line
        hex_left  = hex_left.ljust(8 * 3 - 1)
        hex_right = hex_right.ljust(8 * 3 - 1)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{line_addr}  {hex_left}  {hex_right}  |{ascii_part}|")
    return "\n".join(lines)


def _handle_memory_map(ctx, args: dict) -> dict:
    """Return the memory segment map for a binary.

    Args (in ``args`` dict):
        binary -- program name / key

    Returns a dict with:
        segments -- list of memory blocks, each with:
                      name   -- segment name (e.g. ".text", ".data")
                      start  -- start address (hex string)
                      end    -- end address (hex string, inclusive)
                      size   -- size in bytes
                      read   -- readable flag
                      write  -- writable flag
                      execute -- executable flag
                      volatile -- volatile flag
                      initialized -- whether the block has initialized data
                      type   -- block type string (DEFAULT, BIT_MAPPED, BYTE_MAPPED, OVERLAY)
                      source_name -- source info (file section name, if available)
        count   -- number of segments
    """
    binary = args.get("binary", "")
    pi = ctx.get_program(binary)
    memory = pi.program.getMemory()

    segments = []
    for block in memory.getBlocks():
        # getType() returns an int constant; map it to a human-readable string.
        try:
            block_type = str(block.getType())
        except Exception:
            block_type = "UNKNOWN"

        segments.append({
            "name":        str(block.getName()),
            "start":       str(block.getStart()),
            "end":         str(block.getEnd()),
            "size":        int(block.getSize()),
            "read":        bool(block.isRead()),
            "write":       bool(block.isWrite()),
            "execute":     bool(block.isExecute()),
            "volatile":    bool(block.isVolatile()),
            "initialized": bool(block.isInitialized()),
            "type":        block_type,
            "source_name": str(block.getSourceName()) if block.getSourceName() else None,
        })

    return {"segments": segments, "count": len(segments)}



_MAX_WRITE_BYTES = 4096  # 4 KB hard cap per write request


def _handle_write_bytes(ctx, args: dict) -> dict:
    """Write raw bytes to a program address.

    Args (in ``args`` dict):
        binary  -- program name / key
        address -- hex address string (e.g. ``0x401234``)
        hex     -- hex string of bytes to write (e.g. ``"909090"`` or
                   ``"90 90 90"``, spaces are stripped)

    Returns a dict with:
        address  -- canonical Ghidra address string
        length   -- number of bytes written
        hex      -- hex string that was written
        verified -- True if read-back matches the written bytes

    Note: this writes raw bytes into the program database. It does NOT
    automatically re-disassemble the affected region. If you overwrote
    code bytes, use ``disassemble`` or ``assemble`` afterwards to update
    the instruction listing.
    """
    from ghidra_rpc.server.context import _parse_address
    from ghidra_rpc.server.tools.modifications import (
        _maybe_swing,
        ghidra_transaction,
    )

    binary      = args.get("binary", "")
    address_str = args.get("address", "")
    hex_str     = args.get("hex", "")

    if not address_str:
        raise ValueError("Missing required argument: address")
    if not hex_str:
        raise ValueError("Missing required argument: hex")

    # Normalize hex: strip spaces, validate
    hex_clean = hex_str.replace(" ", "").strip()
    if len(hex_clean) % 2 != 0:
        raise ValueError(
            f"Hex string must have an even number of characters (got {len(hex_clean)})"
        )
    try:
        data = bytes.fromhex(hex_clean)
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {e}") from e

    if len(data) < 1:
        raise ValueError("At least 1 byte is required")
    if len(data) > _MAX_WRITE_BYTES:
        raise ValueError(
            f"Write size must be <= {_MAX_WRITE_BYTES} bytes (requested {len(data)})"
        )

    pi = ctx.get_program(binary)
    addr = _parse_address(pi.program, address_str)

    def do_write():
        memory = pi.program.getMemory()

        # Convert Python bytes to Java signed byte array.
        # Java bytes are -128..127; Python bytes are 0..255.
        # Try jpype first (pyghidra), fall back to jarray (Jython).
        signed = [(b if b < 128 else b - 256) for b in data]
        try:
            import jpype  # type: ignore
            java_bytes = jpype.JArray(jpype.JByte)(signed)
        except ImportError:
            import jarray  # type: ignore
            java_bytes = jarray.array(signed, 'b')

        with ghidra_transaction(
            pi.program, f"ghidra-rpc: write {len(data)} bytes @ {addr}"
        ):
            memory.setBytes(addr, java_bytes)

        # Read back to verify
        try:
            read_back = pi.flat_api.getBytes(addr, len(data))
            read_data = bytes(b & 0xFF for b in read_back)
            verified = read_data == data
        except Exception:
            verified = False

        return {
            "address":  str(addr),
            "length":   len(data),
            "hex":      data.hex(),
            "verified": verified,
        }

    result = _maybe_swing(ctx, do_write)
    ctx.save_program(pi)
    return result


register_handler("read_bytes", _handle_read_bytes)
register_handler("write_bytes", _handle_write_bytes)
register_handler("memory_map", _handle_memory_map)
