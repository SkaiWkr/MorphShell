from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

FAMILIES = ["reverse_shell", "stager", "encoder_loop", "sandbox_evader", "unknown"]
FEATURES = [
    "instruction_count", "unique_addresses", "mem_write_count", "self_modifying",
    "loop_detected", "nop_sled", "syscall_count", "syscall_diversity",
    "written_then_executed", "entropy_of_shellcode", "termination_code",
]
MODEL_PATH = Path(__file__).with_name("model.joblib")


def _row(rng, fam: str) -> list[float]:
    ranges = {
        "reverse_shell": (250, 900, 5, 40, 0, 0, 2, 6, 5.0, 7.2, 0),
        "stager": (40, 250, 1, 15, 0, 1, 0, 2, 4.0, 6.5, 0),
        "encoder_loop": (400, 3000, 10, 90, 1, 0, 0, 1, 6.2, 7.9, 1),
        "sandbox_evader": (80, 700, 0, 20, 1, 1, 0, 3, 3.0, 7.0, 3),
        "unknown": (5, 180, 0, 8, 0, 0, 0, 1, 0.5, 5.0, 3),
    }[fam]
    lo_i, hi_i, lo_w, hi_w, loop, sm, lo_s, hi_s, lo_e, hi_e, term = ranges
    syscalls = int(rng.integers(lo_s, hi_s + 1))
    return [
        int(rng.integers(lo_i, hi_i)), int(rng.integers(max(1, lo_i // 3), max(2, hi_i // 2))),
        int(rng.integers(lo_w, hi_w + 1)), sm, loop, int(rng.random() < 0.2),
        syscalls, min(syscalls, int(rng.integers(0, max(1, syscalls) + 1))), sm,
        float(rng.uniform(lo_e, hi_e)), term,
    ]


def train_dummy_model() -> RandomForestClassifier:
    rng = np.random.default_rng(1337)
    x, y = [], []
    for fam in FAMILIES:
        for _ in range(10):
            x.append(_row(rng, fam))
            y.append(fam)
    model = RandomForestClassifier(n_estimators=80, random_state=1337)
    return model.fit(np.asarray(x), np.asarray(y))


def predict(model, feature_dict: dict) -> tuple[str, float]:
    x = np.asarray([[feature_dict[name] for name in FEATURES]])
    probs = model.predict_proba(x)[0]
    idx = int(np.argmax(probs))
    return str(model.classes_[idx]), float(probs[idx])


def load_or_train(path: Path = MODEL_PATH):
    if path.exists():
        return joblib.load(path)
    model = train_dummy_model()
    joblib.dump(model, path)
    return model
