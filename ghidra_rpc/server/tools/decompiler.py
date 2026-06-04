"""Decompiler tools: decompile functions to pseudo-C."""

from __future__ import annotations

from ghidra_rpc.server.main import register_handler


def _find_function(pi, name_or_address: str):
    """Resolve a function by name or hex address. Raises ValueError if not found or ambiguous."""
    prog = pi.program
    fm = prog.getFunctionManager()
    af = prog.getAddressFactory()

    # Try as address first
    if name_or_address.startswith("0x") or name_or_address.startswith("0X"):
        addr_str = name_or_address[2:]
        try:
            addr = af.getAddress(addr_str)
            if addr:
                func = fm.getFunctionAt(addr)
                if func:
                    return func
                # Maybe it's inside a function
                func = fm.getFunctionContaining(addr)
                if func:
                    return func
        except Exception:
            pass

    # Try as exact name
    name_lower = name_or_address.lower()
    exact_matches = []
    partial_matches = []

    for func in fm.getFunctions(True):
        func_name = str(func.getName())
        if func_name.lower() == name_lower:
            exact_matches.append(func)
        elif name_lower in func_name.lower():
            partial_matches.append(func)

    if len(exact_matches) == 1:
        return exact_matches[0]
    elif len(exact_matches) > 1:
        suggestions = [f"{f.getName()} @ {f.getEntryPoint()}" for f in exact_matches]
        raise ValueError(
            f"Ambiguous function name '{name_or_address}'. Matches: {suggestions}"
        )

    if len(partial_matches) == 1:
        return partial_matches[0]
    elif len(partial_matches) > 1:
        suggestions = [f"{f.getName()} @ {f.getEntryPoint()}" for f in partial_matches[:10]]
        raise ValueError(
            f"Ambiguous function name '{name_or_address}'. Partial matches: {suggestions}"
        )

    raise ValueError(f"Function '{name_or_address}' not found.")


def _handle_decompile(ctx, args: dict) -> dict:
    """Decompile a function and return its pseudo-C code."""
    binary = args.get("binary", "")
    func_name = args.get("func", "")
    timeout = args.get("timeout", 60)

    if not func_name:
        raise ValueError("Missing required argument: func")

    pi = ctx.get_program(binary)
    func = _find_function(pi, func_name)

    from ghidra.util.task import TaskMonitor

    with pi.decompiler_pool.acquire() as decompiler:
        result = decompiler.decompileFunction(func, timeout, TaskMonitor.DUMMY)

    error_msg = result.getErrorMessage()
    if error_msg and error_msg.strip():
        return {
            "name": str(func.getName()),
            "address": str(func.getEntryPoint()),
            "c_code": None,
            "error": error_msg,
        }

    decompiled = result.getDecompiledFunction()
    c_code = str(decompiled.getC()) if decompiled else ""

    return {
        "name": str(func.getName()),
        "address": str(func.getEntryPoint()),
        "signature": str(decompiled.getSignature()) if decompiled else str(func.getSignature()),
        "c_code": c_code,
    }


register_handler("decompile", _handle_decompile)
