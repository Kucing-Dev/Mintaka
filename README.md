


# Mintaka

**Static Analysis & Triage Tool for Binaries** (with special focus on Rust malware)

Mintaka is a lightweight, fast, and modern static analysis tool written in Rust.  
It helps malware analysts quickly triage binaries by extracting key information, detecting suspicious characteristics, and assigning a risk score.

---

## Features

### Core Analysis
- File information (Size, SHA256, Format, Architecture)
- File & Section entropy
- Compile timestamp & Entry Point
- Overlay detection
- Basic packer/protector hints (UPX, etc.)

### Phase 1 - Professional Triage
- **Import Table Analysis**  
  Lists suspicious/dangerous Windows APIs (VirtualAlloc, CreateRemoteThread, WinExec, etc.)
- **Section Analysis**  
  Shows section name, size, entropy, and characteristics (`R`, `W`, `X`)  
  Flags **Writable + Executable** sections
- **IOC Extraction**  
  Extracts IPs, Domains, URLs, Registry keys, and suspicious paths
- **Risk Scoring Engine**  
  Calculates a risk score (0-100) based on multiple indicators

### Rust-Specific
- Detects if the binary was compiled with Rust
- Extracts `rustc` version and commit hash (when available)
- Attempts to recover crate dependencies

---

## Risk Levels

| Score     | Level            | Color  | Meaning                          |
|-----------|------------------|--------|----------------------------------|
| 0 - 44    | `[LOW]`          | Green  | Low suspicion                    |
| 45 - 74   | `[NEEDS REVIEW]` | Yellow | Needs manual inspection          |
| 75 - 100  | `[HIGH RISK]`    | Red    | High suspicion / priority sample |

---

## Installation

### Requirements
- Rust (1.70+)
- Linux / WSL2 / macOS / Windows

```bash
git clone https://github.com/yourusername/mintaka.git
cd mintaka
cargo build --release
```

The binary will be located at:
```bash
./target/release/mintaka
```

---

## Usage

### Basic analysis
```bash
./mintaka sample.exe
```

### JSON output
```bash
./mintaka sample.exe --json
```

### Example
```bash
./mintaka malware.exe
```

---

## Example Output

```text
══════════════════════════════════════════════════════════════════
                          MINTAKA v0.4
            Static Analysis & Triage for Rust Binaries
══════════════════════════════════════════════════════════════════

File          malware.exe
Size          7168 bytes
SHA256        fe3c812c9088dba5ae9d683f705eefa2fb990bd7ad97ee82466f0c5046615a1e
Format        PE
Architecture  x86
File Entropy  1.28
Sections      5
Compiled      2026-04-14 14:29:15 UTC
Entry Point   0x00005000

┌────────────────────────────────────────────────────────────────┐
│  Status      : [LOW]                                           │
│  Risk Score  :  21 / 100                                       │
└────────────────────────────────────────────────────────────────┘

Is Rust       NO

Suspicious Imports
  • kernel32.dll!VirtualProtect

Sections
  Name         Size    Entropy  Flags  Note
  .text         512      0.60     RX
  .rdata        512      2.58     R
  .data        4096      0.03     RW
  .reloc        512      0.14     R
  .jvjp         512      5.64    RWX   ← Suspicious

Notes
  - This does not appear to be a Rust binary
```

---

## Current Limitations

- Not a full malware detector (no sandbox / behavioral analysis)
- YARA engine not yet integrated
- VirusTotal / online lookup not included (offline-first design)
- Best results on PE files (Windows binaries)
- Rust dependency recovery depends on available strings

---

## Roadmap

### Phase 1 (Current)
- [x] Import Table analysis
- [x] Section characteristics + RWX detection
- [x] IOC extraction
- [x] Improved risk scoring

### Phase 2 (Planned)
- [ ] Better packer detection
- [ ] Improved Rust dependency recovery
- [ ] Mass scan mode
- [ ] HTML report export

### Phase 3 (Future)
- [ ] Optional YARA support
- [ ] Fuzzy hashing (ssdeep)
- [ ] Basic disassembly at entry point

---

## License

MIT License

---

**Mintaka** — Fast static triage for modern malware analysis.
```

