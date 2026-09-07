
# Mintaka

**Static Analysis & Triage Tool for Binaries**  
Special focus on Rust malware analysis.

Mintaka is a fast and lightweight static analysis tool written in Rust.  
It helps malware analysts quickly triage suspicious binaries by extracting important information, detecting suspicious characteristics, and assigning a risk score.

---

## Features

### General Analysis
- File information (Size, SHA256, Format, Architecture)
- File entropy & Section entropy
- Compile timestamp & Entry Point
- Overlay detection
- Basic PE / ELF support

### Detection Capabilities
- **Suspicious Imports**  
  Detects dangerous Windows APIs such as `VirtualAlloc`, `VirtualProtect`, `CreateRemoteThread`, `WinExec`, etc.
- **Section Analysis**  
  Shows section name, size, entropy, and characteristics (`R`, `W`, `X`)  
  Automatically flags **Writable + Executable (RWX)** sections
- **Packer / Compiler Detection**  
  Detects common packers and compilers:
  - UPX, VMProtect, Themida, ASPack, PECompact, MPRESS
  - .NET, Go, PyInstaller, AutoIt
  - Rust
  - Unknown / Custom Protector (when RWX section is found)
- **IOC Extraction**  
  Extracts IP addresses, Domains, URLs, Registry keys, and suspicious paths
- **Rust Specific Analysis**  
  - Detects if the binary is compiled with Rust  
  - Extracts `rustc` version and commit hash (when available)  
  - Attempts to recover crate dependencies

### Mass Scan Mode
Scan an entire directory of samples at once and get a clean summary table.

### Risk Scoring
Mintaka calculates a risk score (0-100) based on multiple indicators:

| Score     | Level              | Meaning                        |
|-----------|--------------------|--------------------------------|
| 0 - 44    | `LOW`              | Low suspicion                  |
| 45 - 74   | `NEEDS REVIEW`     | Needs manual inspection        |
| 75 - 100  | `HIGH RISK`        | High suspicion / priority      |

---

## Installation

### Requirements
- Rust 1.70 or newer
- Linux / WSL2 / macOS / Windows

```bash
git clone https://github.com/Kucing-Dev/Mintaka.git
cd Mintaka
cargo build --release
```

Binary location:
```bash
./target/release/mintaka
```

---

## Usage

### Single File Analysis
```bash
./mintaka sample.exe
```

### Mass Scan (Directory)
```bash
./mintaka ./malware_samples/
```

### JSON Output
```bash
./mintaka sample.exe --json
./mintaka ./malware_samples/ --json
```

---

## Example Output

### Single File Mode

```text
══════════════════════════════════════════════════════════════════
                         MINTAKA v0.6
            Static Analysis & Triage for Rust Binaries
══════════════════════════════════════════════════════════════════

File              malware.exe
Size              7168 bytes
SHA256            fe3c812c...
Format            PE
Architecture      x86
File Entropy      1.28
Sections          5
Compiled          2026-04-14 14:29:15 UTC
Entry Point       0x00005000
Packer/Compiler   Unknown Packer / Custom Protector (RWX section)

┌────────────────────────────────────────────────────────────────┐
│  Status      : [LOW]                                           │
│  Risk Score  :  35 / 100                                       │
└────────────────────────────────────────────────────────────────┘

Is Rust           NO

Suspicious Imports
  • kernel32.dll!VirtualProtect

Sections
  Name         Size    Entropy  Flags  Note
  .text         512      0.60     RX
  .jvjp         512      5.64    RWX   ← Suspicious
```

### Mass Scan Mode

```text
═══════════════════════════════════════════════════════════════════════════════════════════
                              MINTAKA v0.6 - Mass Scan Mode
═══════════════════════════════════════════════════════════════════════════════════════════

File                              Score  Risk          Rust  Packer/Compiler
───────────────────────────────────────────────────────────────────────────────────────────
malware_upx.exe                     100  HIGH RISK     NO    UPX
malware_https.exe                    39  LOW           NO    Unknown Packer / Custom Protector...
malware_shikata.exe                  35  LOW           NO    Unknown Packer / Custom Protector...
shell_staged.exe                     35  LOW           NO    Unknown Packer / Custom Protector...
malware_stageless.exe                35  LOW           NO    Unknown Packer / Custom Protector...
malware_standard.exe                 18  LOW           NO    -

───────────────────────────────────────────────────────────────────────────────────────────
Total files scanned: 6
HIGH RISK: 1
NEEDS REVIEW: 0
LOW: 5
```

---

## Current Limitations

- This is a **static analysis** tool only (no dynamic / sandbox analysis)
- Best results on Windows PE files
- YARA rules are not yet integrated
- No online lookup (VirusTotal, etc.) — offline first design
- Rust dependency recovery depends on available strings in the binary
- Very large files (>80MB) are skipped in Mass Scan mode

---

## Roadmap

### Completed
- [x] Basic PE/ELF parsing
- [x] Section analysis + RWX detection
- [x] Suspicious import detection
- [x] IOC extraction
- [x] Packer / Compiler detection
- [x] Risk scoring system
- [x] Rust binary detection
- [x] Mass Scan Mode

### Planned
- [ ] Better resource analysis
- [ ] Optional YARA support
- [ ] HTML report export
- [ ] Entry point disassembly preview
- [ ] CSV export for mass scan

---

## License

MIT License

---

**Mintaka** — Fast static triage for modern malware analysis.
```




