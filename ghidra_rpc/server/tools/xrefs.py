"""Cross-reference tools: xrefs to and from addresses/functions."""

from __future__ import annotations

from ghidra_rpc.server.main import register_handler
from ghidra_rpc.server.tools.decompiler import _find_function


def _resolve_address(pi, target: str):
    """Resolve a target (function name or hex address) to a Ghidra Address."""
    prog = pi.program
    af = prog.getAddressFactory()

    # Try as address
    if target.startswith("0x") or target.startswith("0X"):
        addr_str = target[2:]
        try:
            addr = af.getAddress(addr_str)
            if addr:
                return addr
        except Exception:
            pass

    # Try as function
    try:
        func = _find_function(pi, target)
        return func.getEntryPoint()
    except ValueError:
        pass

    # Try as symbol — prefer non-external (e.g. PLT thunk) over EXTERNAL space symbols.
    # In ELF binaries an imported function like 'malloc' has both a PLT thunk at a real
    # code address AND an entry in the EXTERNAL address space.  Callers reference the PLT
    # thunk, so we must prefer that address for xref lookups.
    st = prog.getSymbolTable()
    external_fallback = None
    for sym in st.getAllSymbols(False):
        if str(sym.getName()).lower() == target.lower():
            addr = sym.getAddress()
            if not addr.getAddressSpace().isExternalSpace():
                return addr  # non-external (PLT thunk / IAT entry) — use immediately
            if external_fallback is None:
                external_fallback = addr

    if external_fallback is not None:
        return external_fallback

    raise ValueError(f"Cannot resolve target '{target}' to an address.")


def _handle_xrefs_to(ctx, args: dict) -> dict:
    """Find cross-references TO a target (who calls/references this?)."""
    binary = args.get("binary", "")
    target = args.get("target", "")
    limit = args.get("limit", 50)

    if not target:
        raise ValueError("Missing required argument: target")

    pi = ctx.get_program(binary)
    addr = _resolve_address(pi, target)
    rm = pi.program.getReferenceManager()
    fm = pi.program.getFunctionManager()

    # When the resolved address falls in the EXTERNAL address space (e.g. the user
    # passed the import's EXTERNAL symbol address directly), callers don't reference
    # that synthetic address — they call through thunk/PLT stubs.  Collect xrefs to
    # all thunk functions whose immediate thunk target is this external address so that
    # callers of the import are included in the results.
    addrs_to_check = [addr]
    if addr.getAddressSpace().isExternalSpace():
        for func in fm.getFunctions(True):
            if func.isThunk():
                try:
                    thunked = func.getThunkedFunction(False)
                    if thunked is not None and str(thunked.getEntryPoint()) == str(addr):
                        addrs_to_check.append(func.getEntryPoint())
                except Exception:
                    pass

    xrefs = []
    for check_addr in addrs_to_check:
        for ref in rm.getReferencesTo(check_addr):
            if len(xrefs) >= limit:
                break
            from_func = fm.getFunctionContaining(ref.getFromAddress())
            xrefs.append({
                "from_address": str(ref.getFromAddress()),
                "from_function": str(from_func.getName()) if from_func else None,
                "type": str(ref.getReferenceType()),
            })
        if len(xrefs) >= limit:
            break

    return {"xrefs": xrefs, "count": len(xrefs)}


def _is_stack_ref(ref) -> bool:
    """Return True if the reference target is in the stack address space."""
    try:
        return ref.getToAddress().getAddressSpace().isStackSpace()
    except Exception:
        # Fall back to string check for safety
        return str(ref.getToAddress()).startswith("Stack")


def _handle_xrefs_from(ctx, args: dict) -> dict:
    """Find cross-references FROM a target (what does this call/reference?).

    When target is a function, iterates all instructions in the function body
    to collect outgoing references. When target is a specific address, only
    checks that address.
    """
    binary = args.get("binary", "")
    target = args.get("target", "")
    limit = args.get("limit", 50)
    no_stack = bool(args.get("no_stack", False))

    if not target:
        raise ValueError("Missing required argument: target")

    pi = ctx.get_program(binary)
    rm = pi.program.getReferenceManager()
    fm = pi.program.getFunctionManager()

    # Try to resolve as a function first — if so, scan all instructions
    func = None
    try:
        func = _find_function(pi, target)
    except ValueError:
        pass

    xrefs = []
    if func is not None:
        # Iterate over all instructions in the function body
        listing = pi.program.getListing()
        body = func.getBody()
        for insn in listing.getInstructions(body, True):
            for ref in insn.getReferencesFrom():
                if no_stack and _is_stack_ref(ref):
                    continue
                if len(xrefs) >= limit:
                    break
                to_func = fm.getFunctionAt(ref.getToAddress())
                if to_func is None:
                    to_func = fm.getFunctionContaining(ref.getToAddress())
                xrefs.append({
                    "from_address": str(ref.getFromAddress()),
                    "to_address": str(ref.getToAddress()),
                    "to_function": str(to_func.getName()) if to_func else None,
                    "type": str(ref.getReferenceType()),
                })
            if len(xrefs) >= limit:
                break
    else:
        # Single address lookup
        addr = _resolve_address(pi, target)
        for ref in rm.getReferencesFrom(addr):
            if no_stack and _is_stack_ref(ref):
                continue
            if len(xrefs) >= limit:
                break
            to_func = fm.getFunctionContaining(ref.getToAddress())
            xrefs.append({
                "from_address": str(ref.getFromAddress()),
                "to_address": str(ref.getToAddress()),
                "to_function": str(to_func.getName()) if to_func else None,
                "type": str(ref.getReferenceType()),
            })

    return {"xrefs": xrefs, "count": len(xrefs)}


register_handler("xrefs_to", _handle_xrefs_to)
register_handler("xrefs_from", _handle_xrefs_from)
