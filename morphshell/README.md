# MorphShell

MorphShell is a Python MVP for **sandboxed shellcode behavioral emulation and classification**. It is designed for defensive security research: samples are mapped into a Unicorn Engine emulator and are never executed natively on the host operating system.

Instead of matching bytes against static signatures, MorphShell observes behavior: instruction flow, memory writes, attempted Linux `int 0x80` syscalls, loops, NOP sleds, and write-then-execute behavior. This helps analysts reason about packed, encoded, or lightly modified shellcode where byte signatures may be brittle.

> Defensive research only: never execute shellcode samples natively. Analyze only samples you are authorized to handle.

## Architecture

```text
+----------------+      +----------------+      +----------------+      +----------------+
| Raw .bin input | ---> | Unicorn x86    | ---> | TraceResult    | ---> | RandomForest   |
| shellcode      |      | emulator       |      | hooks/events   |      | classifier     |
+----------------+      +----------------+      +----------------+      +----------------+
                               |                       |                       |
                               v                       v                       v
                         safe emulation          feature vector          JSON + terminal
```

Pipeline components:

1. **`emulator.py`** maps a 2 MB x86 32-bit sandbox at `0x1000000`, writes the raw bytes, sets `ESP`, and runs with a timeout and instruction cap.
2. **`tracer.py`** attaches Unicorn hooks for code execution, memory writes, and invalid instructions. Capstone disassembly is recorded per instruction.
3. **`features.py`** converts trace data and raw bytes into flat numeric features such as entropy, syscall counts, loop flags, and termination code.
4. **`classifier.py`** trains or loads an MVP `RandomForestClassifier` and predicts a likely family.

## Installation

### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Unicorn, Capstone, scikit-learn, and NumPy publish wheels for common Windows and Linux Python versions, so no compiler should be required for a typical install.

## Usage

Place raw shellcode bytes in `morphshell/samples/`, then run:

```bash
cd morphshell
python main.py samples/sample.bin
```

Example output:

```text
=== MorphShell Analysis Report ===
File        : sample.bin
Size        : 42 bytes
Entropy     : 4.21
Family      : encoder_loop (72.3% confidence)
Classifier  : synthetic MVP model; validate findings manually
Self-mod    : Yes
Loop        : Yes
Syscalls    : 2 attempted (unique: 1)
Instructions: 847 executed
Termination : timeout
==================================
```

A full JSON report is written to `morphshell/reports/<filename>.json` and includes the feature vector, trace summaries, classifier label, and confidence.

## Classifier notes and limitations

The MVP classifier uses `sklearn.ensemble.RandomForestClassifier` with five labels:

- `reverse_shell`
- `stager`
- `encoder_loop`
- `sandbox_evader`
- `unknown`

For now, `train_dummy_model()` creates 50 synthetic training rows with hardcoded, plausible feature ranges. This makes the CLI usable immediately, but the result is **not a production malware-family verdict**. Treat the family and confidence as a demonstration of the pipeline until real labeled data, validation, and calibration are added.

## Folder structure

```text
morphshell/
├── main.py          # CLI entry point and report writer
├── emulator.py      # Unicorn setup, mapping, execution limits, UcError handling
├── tracer.py        # Capstone disassembly and Unicorn event hooks
├── features.py      # Trace-to-feature extraction and entropy calculation
├── classifier.py    # Synthetic MVP RandomForest training, save/load, prediction
├── samples/         # Empty drop folder for user-provided .bin files
├── reports/         # JSON reports written by the CLI
└── README.md        # Project documentation
```

## Roadmap

1. Replace synthetic training data with a real, labeled shellcode trace dataset.
2. Add x86-64 emulation and architecture auto-detection.
3. Hook common API-resolution and OS interaction patterns beyond Linux `int 0x80`.
4. Generate draft YARA rules from behavioral trace features and byte motifs.
5. Build a small web dashboard for triage, report browsing, and sample comparison.

## Safety disclaimer

MorphShell is for defensive research, malware triage, and education in controlled environments. It emulates shellcode in Unicorn and does not intentionally execute samples natively. Do not run unknown shellcode directly on your host, and only analyze files you are legally authorized to inspect.
