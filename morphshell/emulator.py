import time

from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP

from tracer import Tracer, TraceResult

BASE = 0x1000000
SIZE = 2 * 1024 * 1024
STACK_TOP = BASE + SIZE - 0x1000


class Emulator:
    def __init__(self) -> None:
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)

    def map_and_load(self, shellcode: bytes) -> None:
        self.uc.mem_map(BASE, SIZE)
        self.uc.mem_write(BASE, shellcode)
        self.uc.reg_write(UC_X86_REG_ESP, STACK_TOP)

    def run(self, shellcode: bytes, timeout_ms: int = 5000) -> TraceResult:
        tracer = Tracer()
        result = tracer.attach(self.uc)
        try:
            self.map_and_load(shellcode)
            start = time.monotonic()
            self.uc.emu_start(BASE, BASE + len(shellcode), timeout=timeout_ms * 1000, count=10000)
            result.termination_reason = "timeout" if (time.monotonic() - start) * 1000 >= timeout_ms else "clean"
        except UcError as exc:
            msg = str(exc).lower()
            if result.termination_reason != "invalid_insn":
                result.termination_reason = "invalid_insn" if "invalid instruction" in msg else f"error: {exc}"
        except Exception as exc:
            result.termination_reason = f"error: {exc}"
        return result
