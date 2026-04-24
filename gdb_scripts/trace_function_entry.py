from __future__ import annotations

import json
import os

import gdb


OFF_ENTRY = int(os.environ["TRACE_OFF"], 0)
OUT_PATH = os.environ.get("TRACE_OUT", "/tmp/gdb_trace_function_entry.json")
READ_SIZE = int(os.environ.get("TRACE_READ_SIZE", "0x100"), 0)
FIELD_OFFSETS = [
    int(x, 0)
    for x in os.environ.get("TRACE_FIELD_OFFSETS", "").split(",")
    if x.strip()
]

state = {"base": None, "hit": False}


def inferior():
    inf = gdb.selected_inferior()
    if inf.pid == 0:
        raise RuntimeError("no inferior pid")
    return inf


def read_maps_base(pid: int) -> int:
    exe = os.readlink(f"/proc/{pid}/exe")
    with open(f"/proc/{pid}/maps", "r", encoding="ascii") as fp:
        for line in fp:
            parts = line.split()
            if len(parts) < 6:
                continue
            addr_range, perms, offset, _dev, _inode, path = parts[:6]
            if path != exe:
                continue
            if "r-xp" not in perms:
                continue
            start = int(addr_range.split("-", 1)[0], 16)
            file_off = int(offset, 16)
            return start - file_off
    raise RuntimeError("failed to locate CodeMeterLin base mapping")


def reg(name: str) -> int:
    return int(gdb.parse_and_eval(f"${name}"))


def safe_read(addr: int, size: int) -> bytes | None:
    try:
        return bytes(inferior().read_memory(addr, size))
    except Exception:
        return None


def maybe_pointer(addr: int) -> bool:
    return addr > 0x10000


def dump_ptr(addr: int, label: str, size: int = READ_SIZE) -> dict[str, object]:
    out: dict[str, object] = {"label": label, "addr": f"0x{addr:x}"}
    if not maybe_pointer(addr):
        out["readable"] = False
        return out
    head = safe_read(addr, size)
    if head is None:
        out["readable"] = False
        return out
    out["readable"] = True
    out["head_hex"] = head.hex()
    if len(head) >= 8:
        out["qword0"] = f"0x{int.from_bytes(head[:8], 'little'):x}"
    for off in FIELD_OFFSETS:
        field = safe_read(addr + off, 0x40)
        if field is not None:
            out[f"plus_{off:#x}_hex"] = field.hex()
    return out


class EntryBP(gdb.Breakpoint):
    def stop(self):
        if state["hit"]:
            return False
        state["hit"] = True

        regs = {
            name: f"0x{reg(name):x}"
            for name in (
                "rip",
                "rsp",
                "rax",
                "rbx",
                "rcx",
                "rdx",
                "rsi",
                "rdi",
                "r8",
                "r9",
                "r10",
                "r11",
                "r12",
                "r13",
                "r14",
                "r15",
                "rbp",
            )
        }
        rsp = reg("rsp")
        stack = safe_read(rsp, 0x120)
        ret_addr = None
        if stack is not None and len(stack) >= 8:
            ret_addr = int.from_bytes(stack[:8], "little")

        result = {
            "pid": inferior().pid,
            "base": f"0x{state['base']:x}",
            "entry": f"0x{state['base'] + OFF_ENTRY:x}",
            "return_addr": (f"0x{ret_addr:x}" if ret_addr is not None else None),
            "regs": regs,
            "stack_hex": stack.hex() if stack is not None else None,
            "disassembly": gdb.execute("x/24i $pc", to_string=True),
            "backtrace": gdb.execute("bt 16", to_string=True),
            "args": [
                dump_ptr(reg("rdi"), "rdi"),
                dump_ptr(reg("rsi"), "rsi"),
                dump_ptr(reg("rdx"), "rdx"),
                dump_ptr(reg("rcx"), "rcx"),
                dump_ptr(reg("r8"), "r8"),
                dump_ptr(reg("r9"), "r9"),
            ],
        }
        with open(OUT_PATH, "w", encoding="ascii") as fp:
            json.dump(result, fp, indent=2)
            fp.write("\n")
        gdb.execute("detach", to_string=True)
        gdb.execute("quit 0", to_string=True)
        return False


def main():
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    inf = inferior()
    state["base"] = read_maps_base(inf.pid)
    EntryBP(
        f"*0x{state['base'] + OFF_ENTRY:x}",
        internal=False,
        type=gdb.BP_HARDWARE_BREAKPOINT,
    )
    gdb.execute("continue")


main()
