import json
import sys
from pathlib import Path

from classifier import load_or_train, predict
from emulator import Emulator
from features import extract

REPORTS = Path(__file__).with_name("reports")


def yesno(value: bool) -> str:
    return "Yes" if value else "No"


def analyze(path: Path) -> dict:
    shellcode = path.read_bytes()
    trace = Emulator().run(shellcode)
    features = extract(trace, shellcode)
    family, confidence = predict(load_or_train(), features)
    return {
        "file": path.name,
        "size": len(shellcode),
        "family": family,
        "confidence": confidence,
        "features": features,
        "trace": {
            "instructions": trace.instructions,
            "mem_writes": trace.mem_writes,
            "syscalls_attempted": trace.syscalls_attempted,
            "self_modifying": trace.self_modifying,
            "loop_detected": trace.loop_detected,
            "nop_sled": trace.nop_sled,
            "termination_reason": trace.termination_reason,
        },
        "classifier_note": "MVP classifier trained on synthetic data; do not treat labels as ground truth.",
    }


def print_report(report: dict) -> None:
    f = report["features"]
    t = report["trace"]
    print("=== MorphShell Analysis Report ===")
    print(f"File        : {report['file']}")
    print(f"Size        : {report['size']} bytes")
    print(f"Entropy     : {f['entropy_of_shellcode']:.2f}")
    print(f"Family      : {report['family']} ({report['confidence'] * 100:.1f}% confidence)")
    print("Classifier  : synthetic MVP model; validate findings manually")
    print(f"Self-mod    : {yesno(t['self_modifying'])}")
    print(f"Loop        : {yesno(t['loop_detected'])}")
    print(f"Syscalls    : {f['syscall_count']} attempted (unique: {f['syscall_diversity']})")
    print(f"Instructions: {f['instruction_count']} executed")
    print(f"Termination : {t['termination_reason']}")
    print("==================================")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: python main.py <path_to_shellcode.bin>")
        return 2
    path = Path(argv[1])
    if not path.is_file():
        print(f"File not found: {path}")
        return 2
    report = analyze(path)
    print_report(report)
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / f"{path.name}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
