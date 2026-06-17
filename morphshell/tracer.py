from dataclasses import dataclass, field
from typing import Any

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import UC_HOOK_CODE, UC_HOOK_INSN_INVALID, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EAX


@dataclass
class TraceResult:
    instructions: list[dict[str, Any]] = field(default_factory=list)
    mem_writes: list[dict[str, int]] = field(default_factory=list)
    syscalls_attempted: list[int] = field(default_factory=list)
    self_modifying: bool = False
    loop_detected: bool = False
    nop_sled: bool = False
    termination_reason: str = "clean"


class Tracer:
    def __init__(self) -> None:
        self.result = TraceResult()
        self._cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self._hits: dict[int, int] = {}
        self._written: list[tuple[int, int]] = []
        self._nop_run = 0

    def attach(self, uc) -> TraceResult:
        uc.hook_add(UC_HOOK_CODE, self._on_code)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._on_mem_write)
        uc.hook_add(UC_HOOK_INSN_INVALID, self._on_invalid)
        return self.result

    def _on_code(self, uc, address: int, size: int, _user_data) -> None:
        code = bytes(uc.mem_read(address, size))
        insn = next(self._cs.disasm(code, address), None)
        mnemonic = insn.mnemonic if insn else "db"
        op_str = insn.op_str if insn else code.hex()
        self.result.instructions.append({"address": address, "mnemonic": mnemonic, "op_str": op_str})

        self._hits[address] = self._hits.get(address, 0) + 1
        if self._hits[address] >= 3:
            self.result.loop_detected = True

        self._nop_run = self._nop_run + 1 if mnemonic == "nop" else 0
        if self._nop_run >= 8:
            self.result.nop_sled = True

        if mnemonic == "int" and op_str == "0x80":
            self.result.syscalls_attempted.append(int(uc.reg_read(UC_X86_REG_EAX)))

        for start, end in self._written:
            if start <= address < end:
                self.result.self_modifying = True
                break

    def _on_mem_write(self, _uc, _access: int, address: int, size: int, value: int, _user_data) -> None:
        self.result.mem_writes.append({"address": address, "size": size, "value": value})
        self._written.append((address, address + max(size, 1)))

    def _on_invalid(self, _uc, _user_data) -> bool:
        self.result.termination_reason = "invalid_insn"
        return False
