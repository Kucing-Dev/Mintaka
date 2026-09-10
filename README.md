<p align="center">
  <img src="https://github.com/user-attachments/assets/caf10e99-1ba3-489f-a9e2-93dc8c19eeab" alt="logo mintaka" width="40%" />
</p>

# Mintaka (v0.9)

**Static & Live Process Triage Tool for Malware Analysis**  
*Special focus on Rust binary reverse engineering, Living-off-the-Land (LotL) detection, and live network/process correlation.*

Mintaka is a fast, lightweight hybrid static and dynamic triage utility written in Rust.  
It assists malware analysts and DFIR responders in quickly auditing suspicious binaries, scanning live running processes, inspecting loaded DLL hierarchies, tracking active remote IP connections, and querying VirusTotal.

---

## Key Features

### 1. Interactive TUI Dashboard (`--tui` / `-t`)
- **Ratatui-Powered Terminal Dashboard**: Interactive process manager with real-time UI refresh.
- **Process List & Color-Coded Risk Matrix**: Instant categorization into `HIGH RISK`, `NEEDS REVIEW`, and `LOW`.
- **Live Search & Filtering (`/`)**: Instantly search processes by Name, PID, or File Path.
- **Process Inspector Panel**: Shows command-line arguments, parent process PID/name, risk indicators, socket targets, and DLL trees.

### 2. Live Process & Network Triage (`--live` / `-l` & `--watch` / `-w`)
- **Socket-to-Process Correlation**: Binds active IPv4/IPv6 TCP and UDP sockets directly to the owning PID.
- **Reverse DNS & IP Intelligence**: Resolves PTR hostnames, GeoIP country codes, AS Owners, and VirusTotal flags.
- **Loaded Module / DLL Tree Hierarchy**: Visualizes loaded `.dll` / `.so` libraries grouped by directory structure.
- **Unsigned System DLL Detection**: Automatically flags unsigned DLLs running from system directories (`System32`, `/usr/lib/`).

### 3. VirusTotal API v3 Integration (`--vt-key`)
- Automatically queries executable file hashes, loaded DLL hashes, and remote connection IPs against VirusTotal.
- Built-in rate limiting (4 req/min for free keys) and thread-safe disk caching (`~/.cache/mintaka/vt_cache.json`).

### 4. Static Binary Analysis
- **Format Inspection**: Size, SHA256, PE/ELF architecture, entropy, compile timestamp, entry point, and overlay size.
- **Authenticode Digital Signature Check**: Detects signed PE binaries and extracts publisher certificates.
- **Suspicious Import API Detection**: Detects 34+ dangerous Win32 APIs (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, etc.).
- **Packer / Protector Detection**: UPX, VMProtect, Themida, ASPack, PECompact, MPRESS, .NET, Go, PyInstaller, and custom RWX section detectors.
- **Rust Binary Analysis**: Detects Rust binaries, extracts `rustc` version & commit hash, and recovers `Cargo.toml` crate dependencies.
- **IOC Extraction**: Extracts IPs, Domains, URLs, Registry keys, and temporary file paths.

---

## Installation

```bash
git clone https://github.com/Kucing-Dev/Mintaka.git
cd Mintaka
cargo build --release
```

Compiled binary:
```bash
./target/release/mintaka
```

---

## Usage

### 1. Interactive TUI Dashboard (Recommended)
```bash
# Launch interactive process triage dashboard (auto-refreshes every 2 seconds)
./mintaka --tui

# Custom refresh interval (e.g. 1 second)
./mintaka -t -i 1

# Launch TUI dashboard with VirusTotal integration
./mintaka -t --vt-key YOUR_VIRUSTOTAL_API_KEY
```

**TUI Keybindings:**
- `[↑ / ↓]` or `[k / j]` : Navigate process list
- `[/]` : Live Search / Filter (type process name/PID, press `Enter` to apply, `Esc` to clear)
- `[c]` : Clear filter
- `[r]` : Force manual refresh
- `[q]` or `[Esc]` : Exit TUI

### 2. Live Process Snapshot Scan (`--live`)
```bash
# Single snapshot scan of all running processes
./mintaka --live

# Scan specific process name
./mintaka --live --name powershell

# Target specific PID
./mintaka --live --pid 4812

# Export live scan results to JSON or CSV
./mintaka --live --json
./mintaka --live --csv
```

### 3. Static Binary Analysis Mode
```bash
# Analyze a single binary
./mintaka sample.exe

# Mass scan an entire directory of samples
./mintaka ./malware_samples/

# Export static analysis report to CSV or JSON
./mintaka sample.exe --csv
./mintaka ./malware_samples/ --json
```

---

## Dynamic & Hybrid Risk Scoring Matrix

| Score | Risk Level | Detection Indicators |
| :--- | :--- | :--- |
| **75 - 100** | `HIGH RISK` | VirusTotal malicious flags, un-signed DLL in System32, process running from `/tmp/` or `\Temp\`, connection to suspicious C2 port/IP |
| **45 - 74** | `NEEDS REVIEW` | High section entropy, writable+executable (RWX) sections, suspicious Win32 API imports, custom packers, active external sockets |
| **0 - 44** | `LOW` | Standard signed binary with expected system behavior |

---

## CLI Options Reference

```text
Usage: mintaka [OPTIONS] [PATH]

Arguments:
  [PATH]  File or directory path to analyze statically (optional if using --live or --tui)

Options:
  -l, --live                 Perform live process and network triage scan (single snapshot)
  -t, --tui                  Launch interactive Ratatui TUI dashboard
  -w, --watch                Continuous real-time stream mode
  -i, --interval <INTERVAL>  Watch/TUI refresh interval in seconds (default: 2)
      --pid <PID>            Target specific PID for live scan
      --name <NAME>          Target specific process name for live scan
      --vt-key <VT_KEY>      VirusTotal API v3 Key for hash & IP reputation lookup [env: VT_API_KEY]
      --json                 Output as JSON
      --csv                  Save result as CSV file (mintaka_report.csv or mintaka_live_report.csv)
  -h, --help                 Print help
```

---

## Roadmap

- [x] PE/ELF static binary parsing & entropy analysis
- [x] Rust compiler version & crate recovery
- [x] Live process enumeration & socket-to-PID correlation
- [x] Ratatui interactive TUI dashboard (`--tui`)
- [x] Loaded module / DLL Directory Tree hierarchy
- [x] Reverse DNS hostname lookup & GeoIP/IP intelligence
- [x] Authenticode digital signature verification & unsigned system DLL detection
- [x] VirusTotal API v3 integration with rate limiting and local caching
- [ ] Process action controls (Process Kill `[k]` & Mini-Memory Dump `[d]` in TUI)
- [ ] YARA engine integration (`--yara-rules`)

---

## License

MIT License

**Mintaka** — Fast hybrid static & dynamic triage for modern malware analysis.
