# ⬡ MorphShell

> **Shellcode Behavioral Emulation & Classification Engine**  
> Defensive security research tool — shellcode never executes natively on the host.

---

## What is MorphShell?

MorphShell is a sandboxed shellcode analysis tool that classifies unknown shellcode by **behavior**, not by byte signatures.

Traditional antivirus tools match file hashes or byte patterns against known malware databases. This breaks the moment an attacker re-encodes their shellcode — the bytes change, the signature no longer matches, and detection fails. MorphShell sidesteps this entirely by running shellcode inside a **fake CPU emulator** (Unicorn Engine), watching what it actually *does* at runtime, and using a machine learning classifier to label its behavioral family.

This is the same core methodology used by enterprise EDR products like CrowdStrike and SentinelOne — built from scratch as a research prototype.

---

## Architecture

```
┌──────────────────┐
│  Raw .bin input  │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────┐
│  emulator.py  —  Unicorn x86 32-bit sandbox      │
│  Maps 2MB at 0x1000000, sets ESP, starts CPU     │
└────────┬─────────────────────────────────────────┘
         │  hooks fire during execution
         ▼
┌──────────────────────────────────────────────────┐
│  tracer.py  —  Behavioral event logger           │
│  HOOK_CODE → disassembly, loop detect, syscalls  │
│  HOOK_MEM_WRITE → write-then-execute tracking    │
│  HOOK_INSN_INVALID → anti-emulation signals      │
└────────┬─────────────────────────────────────────┘
         │  TraceResult dataclass
         ▼
┌──────────────────────────────────────────────────┐
│  features.py  —  Feature extraction              │
│  Converts trace → 11-number fixed-length vector  │
│  Includes Shannon entropy, syscall diversity     │
└────────┬─────────────────────────────────────────┘
         │  feature dict
         ▼
┌──────────────────────────────────────────────────┐
│  classifier.py  —  RandomForestClassifier        │
│  Predicts behavioral family + confidence score   │
└────────┬─────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────┐
│  Terminal report  +  JSON file  +  GUI display   │
└──────────────────────────────────────────────────┘
```

---

## Behavioral Families

MorphShell classifies shellcode into 10 behavioral families:

| Family | Description |
|---|---|
| `reverse_shell` | Connects back to attacker C2, redirects stdio over socket |
| `bind_shell` | Opens a listening port and spawns shell on connection |
| `stager` | Downloads and maps a second-stage payload into memory |
| `encoder_loop` | Self-decoding stub — XOR/ADD loop, write-then-execute pattern |
| `sandbox_evader` | Probes environment before acting, timing/CPUID tricks |
| `process_injector` | Writes shellcode into another process and triggers execution |
| `file_dropper` | Writes a binary payload to disk via filesystem syscalls |
| `privilege_escalator` | Exploits kernel or setuid to gain elevated privileges |
| `keylogger_stub` | Hooks input or reads device files — low syscall diversity |
| `unknown` | No confident match — inspect trace manually |

---

## Feature Vector

Every shellcode sample is reduced to 11 numerical features before classification:

| Feature | What it captures |
|---|---|
| `instruction_count` | Total instructions executed — complexity signal |
| `unique_addresses` | Unique code addresses — low ratio = heavy loop |
| `mem_write_count` | Memory write operations during execution |
| `self_modifying` | Write-then-execute detected (0 or 1) |
| `loop_detected` | Same address hit 3+ times (0 or 1) |
| `nop_sled` | 8+ consecutive NOPs detected (0 or 1) |
| `syscall_count` | Total `int 0x80` instructions hit |
| `syscall_diversity` | Number of unique syscall numbers attempted |
| `written_then_executed` | Memory written then jumped to (0 or 1) |
| `entropy_of_shellcode` | Shannon entropy of raw input bytes |
| `termination_code` | 0=clean, 1=timeout, 2=invalid_insn, 3=error |

---

## Installation

### Requirements
- Python 3.10+
- Windows or Linux (macOS untested)

### Windows (PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> **Windows note:** Add the `samples/` folder to Windows Defender exclusions before placing shellcode files there, or Defender will quarantine them automatically.

---

## Usage

### GUI (recommended)
```bash
python gui.py
```

Drop a `.bin` shellcode file into the file selector, click **Run Analysis**, and view results across 5 tabs:
- **Family Scores** — probability bars for all 10 families with descriptions
- **Feature Vector** — all 11 ML features with values
- **Instruction Trace** — full disassembly of up to 500 instructions
- **Syscalls** — table of every `int 0x80` attempt with EAX value and syscall name
- **Raw JSON** — complete report with save option

Session history is stored in the left panel — click any past entry to re-render its results.

### CLI
```bash
python main.py samples/sample.bin
```

Example output:
```
=== MorphShell Analysis Report ===
File        : sample.bin
Size        : 63 bytes
Entropy     : 6.84
Family      : encoder_loop (81.3% confidence)
Classifier  : synthetic MVP model; validate findings manually
Self-mod    : Yes
Loop        : Yes
Syscalls    : 1 attempted (unique: 1)
Instructions: 847 executed
Termination : timeout
==================================
```

Reports are saved automatically to `reports/<filename>.json`.

---

## Getting Shellcode Samples

MorphShell analyzes raw binary shellcode files (`.bin`). Public research repositories:

- **Shell-Storm** — `shell-storm.org/shellcode` — annotated x86/x64 samples
- **Exploit-DB** — `exploit-db.com/shellcodes` — categorized by OS and architecture

### Converting a C sample to .bin

Shellcode from these sites is often wrapped in a `.c` file. Extract the bytes and write to binary:

```python
shellcode = b"\x31\xc0\x40\xcd\x80"   # paste your bytes here
with open("samples/sample.bin", "wb") as f:
    f.write(shellcode)
```

---

## Project Structure

```
morphshell/
├── gui.py           — Tkinter GUI, 5-tab analysis interface
├── main.py          — CLI entry point and report writer
├── emulator.py      — Unicorn Engine setup, memory mapping, execution limits
├── tracer.py        — Hook attachment, Capstone disassembly, behavioral logging
├── features.py      — Trace-to-feature extraction, Shannon entropy calculation
├── classifier.py    — RandomForest training, synthetic data, predict(), save/load
├── requirements.txt — Python dependencies
├── samples/         — Drop .bin files here (empty by default)
├── reports/         — JSON reports written automatically after each analysis
└── README.md
```

---

## Dependencies

| Library | Purpose |
|---|---|
| `unicorn` | x86 CPU emulator — sandboxed shellcode execution |
| `capstone` | Disassembly — decodes raw bytes to readable instructions |
| `scikit-learn` | RandomForestClassifier — behavioral family prediction |
| `numpy` | Feature vector construction and synthetic training data |
| `joblib` | Model serialization — saves trained classifier to disk |

---

## Classifier Notes & Limitations

The MVP classifier uses `sklearn.ensemble.RandomForestClassifier` trained on **synthetic data** — programmatically generated feature vectors that approximate realistic behavioral ranges per family.

This means:
- The pipeline and classification logic are fully functional
- Family labels and confidence scores are **demonstrative**, not ground-truth verdicts
- Real accuracy will vary on actual shellcode samples

The first post-MVP improvement is replacing synthetic training data with labeled samples from real shellcode corpora.

---

## Roadmap

1. **Real training dataset** — replace synthetic rows with traced and labeled samples from Exploit-DB and Shell-Storm
2. **x86-64 support** — add `UC_MODE_64` emulation path with architecture auto-detection
3. **Windows API hooking** — simulate `VirtualAlloc`, `CreateThread`, `WriteProcessMemory` for PE shellcode analysis
4. **YARA rule generation** — auto-generate draft YARA rules from high-confidence behavioral trace patterns
5. **Web dashboard** — Flask-based interface for multi-sample triage, comparison, and report history
6. **Anti-emulation detection** — classify samples that probe for emulation as `sandbox_evader` with higher specificity
7. **Entropy visualization** — byte-level entropy heatmap in the GUI for visual pattern analysis

---

## Disclaimer

MorphShell is a **defensive security research tool** built for educational purposes, malware triage, and security research in controlled environments.

- Shellcode is analyzed inside a Unicorn Engine emulator and **never executed natively** on the host machine
- Only analyze samples you are legally authorized to inspect
- Do not use this tool against systems or files you do not own or have explicit permission to analyze
- All shellcode samples used during development were sourced from public security research repositories (Shell-Storm, Exploit-DB)

---

## Author

**Siddhant Mandal**  
B.Tech CSE (Cybersecurity) — SVPCET Nagpur  
`github.com/SkaiWkr`
