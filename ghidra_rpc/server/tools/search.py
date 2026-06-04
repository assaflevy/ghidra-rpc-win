"""Search tools: strings and symbols."""

from __future__ import annotations

from ghidra_rpc.server.main import register_handler


def _normalize_byte_pattern(pattern: str) -> str:
    """Normalize a user-provided byte pattern for Ghidra's findBytes.

    Accepts patterns like:
      "55 8b ?? 83 ec"   — ?? wildcards (IDA/x64dbg style)
      "55 8b . 83 ec"    — . wildcards (Ghidra native)
      "558b??83ec"        — no spaces (auto-split into pairs)
      "90 90 90 EB ??"   — mixed case

    Returns Ghidra-compatible format: space-separated hex values with '.' wildcards.
    """
    p = pattern.strip()
    # If no spaces, split into pairs of 2 characters
    if " " not in p and len(p) > 2:
        p = " ".join(p[i:i+2] for i in range(0, len(p), 2))
    # Replace ?? wildcards with Ghidra's . wildcard
    tokens = p.split()
    normalized = []
    for tok in tokens:
        tok = tok.strip()
        if tok in ("??", ".", "**", "xx"):
            normalized.append(".")
        else:
            # Validate it's a hex byte
            try:
                val = int(tok, 16)
                if not (0 <= val <= 0xFF):
                    raise ValueError(f"Byte value out of range: {tok}")
                normalized.append(f"{val:02x}")
            except ValueError:
                raise ValueError(
                    f"Invalid byte pattern token: '{tok}'. "
                    f"Use hex bytes (00-ff) or '??' / '.' for wildcards."
                )
    if not normalized:
        raise ValueError("Empty byte pattern")
    return " ".join(normalized)


_FIND_BYTES_CONTEXT = 16  # bytes of context on each side of a match


def _handle_find_bytes(ctx, args: dict) -> dict:
    """Search for a byte pattern (with optional wildcards) in program memory.

    Args (in ``args`` dict):
        binary  -- program name / key
        pattern -- byte pattern string, e.g. "55 8b ?? 83 ec" or "90 90 90"
                   Wildcards: '??' or '.' for any byte
        limit   -- max number of matches to return (default 100, max 10000)
        address -- optional start address for the search (default: program min)

    Returns a dict with:
        pattern -- normalized pattern used
        matches -- list of dicts with:
                     address     -- hex address of the match
                     context_hex -- hex string of surrounding bytes for verification
        count   -- number of matches returned
        truncated -- true if limit was reached (there may be more matches)
    """
    from ghidra_rpc.server.context import _parse_address

    binary      = args.get("binary", "")
    pattern_str = args.get("pattern", "")
    limit       = int(args.get("limit", 100))
    start_str   = args.get("address", "")

    if not pattern_str:
        raise ValueError("Missing required argument: pattern")
    if limit < 1:
        raise ValueError("limit must be >= 1")
    if limit > 10000:
        limit = 10000

    normalized = _normalize_byte_pattern(pattern_str)

    pi = ctx.get_program(binary)
    memory = pi.program.getMemory()

    if start_str:
        start_addr = _parse_address(pi.program, start_str)
    else:
        start_addr = pi.program.getMinAddress()

    # Use FlatProgramAPI.findBytes(Address, String, int) which returns Address[]
    try:
        addrs = pi.flat_api.findBytes(start_addr, normalized, limit)
    except Exception as e:
        raise RuntimeError(f"Byte search failed: {e}") from e

    if addrs is None:
        addrs = []

    pattern_len = len(normalized.split())
    matches = []
    for addr in addrs:
        # Read context bytes around the match
        context_hex = ""
        try:
            ctx_start = addr.subtract(_FIND_BYTES_CONTEXT)
            ctx_len = _FIND_BYTES_CONTEXT + pattern_len + _FIND_BYTES_CONTEXT
            java_bytes = pi.flat_api.getBytes(ctx_start, ctx_len)
            context_hex = bytes(b & 0xFF for b in java_bytes).hex()
        except Exception:
            # If context read fails (e.g., near memory boundary), just get the match
            try:
                java_bytes = pi.flat_api.getBytes(addr, pattern_len)
                context_hex = bytes(b & 0xFF for b in java_bytes).hex()
            except Exception:
                pass

        matches.append({
            "address": str(addr),
            "context_hex": context_hex,
        })

    return {
        "pattern":   normalized,
        "matches":   matches,
        "count":     len(matches),
        "truncated": len(matches) >= limit,
    }


def _handle_search_strings(ctx, args: dict) -> dict:
    """Search for strings in a binary by substring match."""
    binary = args.get("binary", "")
    query = args.get("query", "")
    limit = args.get("limit", 100)

    if not query and query != "":
        raise ValueError("Missing required argument: query (use empty string to list all)")

    pi = ctx.get_program(binary)

    # Get defined strings
    try:
        from ghidra.program.util import DefinedStringIterator  # type: ignore
        data_iter = DefinedStringIterator.forProgram(pi.program)
    except ImportError:
        from ghidra.program.util import DefinedDataIterator
        data_iter = DefinedDataIterator.definedStrings(pi.program)

    query_lower = query.lower() if query else None
    results = []
    for data in data_iter:
        if len(results) >= limit:
            break
        try:
            val = str(data.getValue())
            if query_lower is None or query_lower in val.lower():
                results.append({
                    "address": str(data.getAddress()),
                    "value": val,
                    "type": str(data.getDataType()),
                })
        except Exception:
            continue

    return {"strings": results, "count": len(results)}


def _handle_search_symbols(ctx, args: dict) -> dict:
    """Search for symbols in a binary by name substring."""
    binary = args.get("binary", "")
    query = args.get("query", "")
    limit = args.get("limit", 25)
    offset = args.get("offset", 0)

    if not query:
        raise ValueError("Missing required argument: query")

    pi = ctx.get_program(binary)
    st = pi.program.getSymbolTable()
    query_lower = query.lower()

    results = []
    for sym in st.getAllSymbols(False):
        name = str(sym.getName())
        full_name = str(sym.getName(True))
        if query_lower in name.lower() or query_lower in full_name.lower():
            results.append({
                "name": full_name,
                "address": str(sym.getAddress()),
                "type": str(sym.getSymbolType()),
            })

    # Sort by exact match first, then alphabetically
    results.sort(key=lambda r: (
        0 if r["name"].lower() == query_lower else 1,
        r["name"].lower(),
    ))

    paginated = results[offset:offset + limit]
    return {"symbols": paginated, "count": len(paginated), "total": len(results)}


register_handler("find_bytes", _handle_find_bytes)
register_handler("strings", _handle_search_strings)
register_handler("symbols", _handle_search_symbols)
