from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

FAMILIES = [
    "reverse_shell",
    "bind_shell",
    "stager",
    "encoder_loop",
    "sandbox_evader",
    "process_injector",
    "file_dropper",
    "privilege_escalator",
    "keylogger_stub",
    "unknown",
]

FAMILY_DESCRIPTIONS = {
    "reverse_shell":        "Connects back to attacker C2, redirects stdio over socket",
    "bind_shell":           "Opens a listening port and spawns shell on connection",
    "stager":               "Downloads and maps a second-stage payload into memory",
    "encoder_loop":         "Self-decoding stub — XOR/ADD loop, write-then-execute pattern",
    "sandbox_evader":       "Probes environment before acting, uses timing/CPUID tricks",
    "process_injector":     "Writes shellcode into another process and triggers execution",
    "file_dropper":         "Writes a binary payload to disk via filesystem syscalls",
    "privilege_escalator":  "Exploits kernel/setuid to gain elevated privileges",
    "keylogger_stub":       "Hooks input or reads /dev/input — low syscall diversity",
    "unknown":              "No confident match — inspect trace manually",
}

FEATURES = [
    "instruction_count", "unique_addresses", "mem_write_count", "self_modifying",
    "loop_detected", "nop_sled", "syscall_count", "syscall_diversity",
    "written_then_executed", "entropy_of_shellcode", "termination_code",
]

MODEL_PATH = Path(__file__).with_name("model.joblib")


def _row(rng, fam: str) -> list[float]:
    # (lo_insn, hi_insn, lo_writes, hi_writes, loop, selfmod, lo_sys, hi_sys, lo_ent, hi_ent, term)
    ranges = {
        "reverse_shell":       (200,  900,  2,  20, 0, 0, 3,  7,  4.5, 7.0, 0),
        "bind_shell":          (150,  700,  2,  18, 0, 0, 3,  6,  4.2, 6.8, 0),
        "stager":              (40,   250,  1,  15, 0, 0, 1,  3,  3.8, 6.5, 0),
        "encoder_loop":        (400, 3000, 10,  90, 1, 1, 0,  1,  6.2, 7.9, 1),
        "sandbox_evader":      (80,   700,  0,  20, 1, 0, 0,  3,  3.0, 7.0, 3),
        "process_injector":    (300, 1200,  8,  60, 0, 1, 4,  8,  5.0, 7.5, 0),
        "file_dropper":        (100,  500,  5,  40, 0, 0, 2,  5,  3.5, 6.0, 0),
        "privilege_escalator": (150,  800,  3,  30, 0, 0, 2,  6,  4.0, 7.2, 0),
        "keylogger_stub":      (50,   400,  1,  10, 1, 0, 1,  2,  3.0, 5.5, 0),
        "unknown":             (5,    180,  0,   8, 0, 0, 0,  1,  0.5, 5.0, 3),
    }[fam]
    lo_i, hi_i, lo_w, hi_w, loop, sm, lo_s, hi_s, lo_e, hi_e, term = ranges
    syscalls = int(rng.integers(lo_s, hi_s + 1))
    return [
        int(rng.integers(lo_i, hi_i)),
        int(rng.integers(max(1, lo_i // 3), max(2, hi_i // 2))),
        int(rng.integers(lo_w, hi_w + 1)),
        sm, loop,
        int(rng.random() < 0.2),
        syscalls,
        min(syscalls, int(rng.integers(0, max(1, syscalls) + 1))),
        sm,
        float(rng.uniform(lo_e, hi_e)),
        term,
    ]


def train_dummy_model() -> RandomForestClassifier:
    rng = np.random.default_rng(1337)
    x, y = [], []
    for fam in FAMILIES:
        for _ in range(14):
            x.append(_row(rng, fam))
            y.append(fam)
    model = RandomForestClassifier(n_estimators=120, random_state=1337)
    return model.fit(np.asarray(x), np.asarray(y))


def predict(model, feature_dict: dict) -> tuple[str, float, dict]:
    x = np.asarray([[feature_dict[name] for name in FEATURES]])
    probs = model.predict_proba(x)[0]
    idx = int(np.argmax(probs))
    label = str(model.classes_[idx])
    confidence = float(probs[idx])
    all_scores = {str(model.classes_[i]): float(probs[i]) for i in range(len(probs))}
    return label, confidence, all_scores


def load_or_train(path: Path = MODEL_PATH):
    if path.exists():
        return joblib.load(path)
    model = train_dummy_model()
    joblib.dump(model, path)
    return model
