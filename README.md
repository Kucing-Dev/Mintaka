<p align="center">
  <img src="https://github.com/user-attachments/assets/caf10e99-1ba3-489f-a9e2-93dc8c19eeab" alt="logo mintaka" width="40%" />
</p>


# Mintaka

**Static Analysis & Triage Tool for Binaries**  
Special focus on Rust malware analysis.

Mintaka is a fast and lightweight static analysis tool written in Rust.  
It helps malware analysts quickly triage suspicious binaries by extracting key information, detecting suspicious characteristics, and assigning a risk score.

---

## Features

### General Analysis
- File information (Size, SHA256, Format, Architecture)
- File entropy & Section entropy
- Compile timestamp & Entry Point
- Overlay detection
- **Resource detection** (Yes / No + size)
- Basic PE / ELF support

### Detection Capabilities
- **Suspicious Imports**  
  Detects dangerous Windows APIs (`VirtualAlloc`, `VirtualProtect`, `CreateRemoteThread`, `WinExec`, etc.)
- **Section Analysis**  
  Shows name, size, entropy, and characteristics (`R`, `W`, `X`)  
  Flags **Writable + Executable (RWX)** sections
- **Packer / Compiler Detection**  
  Supports:
  - UPX, VMProtect, Themida, ASPack, PECompact, MPRESS
  - .NET, Go, PyInstaller
  - Rust
  - Unknown / Custom Protector (when RWX section is found)
- **IOC Extraction**  
  Extracts IPs, Domains, URLs, Registry keys, and suspicious paths
- **Rust Specific Analysis**  
  - Detects Rust binaries  
  - Extracts `rustc` version and commit hash  
  - Attempts to recover crate dependencies

### Mass Scan Mode
Scan an entire directory of samples and get a clean summary table sorted by risk score.

### Risk Scoring
| Score     | Level            | Meaning                     |
|-----------|------------------|-----------------------------|
| 0 - 44    | `LOW`            | Low suspicion               |
| 45 - 74   | `NEEDS REVIEW`   | Needs manual inspection     |
| 75 - 100  | `HIGH RISK`      | High suspicion / priority   |

---

## Installation

```bash
git clone https://github.com/Kucing-Dev/Mintaka.git
cd Mintaka
cargo build --release
```

Binary:
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
./mintaka ./samples/ --json
```

---

## Example Output

### Single File Mode

```text
══════════════════════════════════════════════════════════════════
                         MINTAKA v0.7
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
Packer/Compiler   Unknown Packer / Custom Protector (RWX)
Resources         No
Overlay           -

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
File                           Size  Score Risk         Rust Packer
──────────────────────────────────────────────────────────────────────────────
malware_upx.exe               24.0KB   100 HIGH RISK    NO   UPX
malware_https.exe              9.2KB    47 NEEDS REVIEW NO   Unknown Packer...
shell_staged.exe               7.1KB    35 LOW          NO   Unknown Packer...
malware_standard.exe           5.1KB    18 LOW          NO   -

Total: 4
HIGH RISK: 1
NEEDS REVIEW: 1
LOW: 2
```

---

## Notes

- Not all malware contains **Resources**. Many modern / packed / generated samples deliberately omit them.
- Best results are obtained on Windows PE files.
- This is a **static analysis** tool only (no dynamic execution).

---

## Roadmap

### Completed
- [x] PE/ELF parsing
- [x] Section analysis + RWX detection
- [x] Suspicious import detection
- [x] IOC extraction
- [x] Packer / Compiler detection
- [x] Resource detection
- [x] Risk scoring
- [x] Rust binary detection
- [x] Mass Scan Mode

### Planned
- [ ] Better resource parsing (version info, icons)
- [ ] Optional YARA support
- [ ] HTML / CSV report export
- [ ] Entry point disassembly preview

---

## License

MIT License



**Mintaka** — Fast static triage for modern malware analysis.

