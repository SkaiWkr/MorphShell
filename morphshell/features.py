import math

from tracer import TraceResult

TERM_CODES = {"clean": 0, "timeout": 1, "invalid_insn": 2}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def extract(trace: TraceResult, shellcode: bytes) -> dict:
    addrs = [i["address"] for i in trace.instructions]
    term = trace.termination_reason
    return {
        "instruction_count": len(trace.instructions),
        "unique_addresses": len(set(addrs)),
        "mem_write_count": len(trace.mem_writes),
        "self_modifying": int(trace.self_modifying),
        "loop_detected": int(trace.loop_detected),
        "nop_sled": int(trace.nop_sled),
        "syscall_count": len(trace.syscalls_attempted),
        "syscall_diversity": len(set(trace.syscalls_attempted)),
        "written_then_executed": int(trace.self_modifying),
        "entropy_of_shellcode": entropy(shellcode),
        "termination_code": TERM_CODES.get(term, 3),
    }
