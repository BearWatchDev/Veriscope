# Veriscope

**Automated Malware Analysis & Detection Engineering Platform**

Veriscope transforms raw malware artifacts into actionable detection intelligence through automated deobfuscation, IOC extraction, and detection rule generation.

![Version](https://img.shields.io/badge/version-1.1.0-green) ![License](https://img.shields.io/badge/license-MIT-blue) ![Python](https://img.shields.io/badge/python-3.8+-blue) ![Status](https://img.shields.io/badge/status-active-success)

---

## Overview

Veriscope is a specialized tool for security analysts, threat hunters, and SOC teams that automates the malware analysis workflow:

**Deobfuscate Malware ▶ Extract IOCs ▶ Generate YARA/Sigma Detection Rules**

### What It Does

- **Advanced Multi-Layer Deobfuscation**: Automatically unwraps complex obfuscation chains:
  - **10+ encoding methods**: Base64, Hex, GZIP, zlib, bzip2, UTF-16LE, XOR (single/multi-byte), ROT13, URL encoding
  - **Up to 6 layers deep** with SHA1 cycle detection and timeout protection
  - **Binary data preservation**: Latin-1 encoding for XOR and compressed data
  - **Intelligent stopping**: Marker-based plaintext detection (prevents over-decoding)
  - **Real-world patterns**: Windows/PowerShell malware, nested encodings, compressed payloads
  - **Compression support**: GZIP, zlib (0x78), bzip2 (BZh) with magic byte detection
  - **Multi-byte XOR**: 8 common keys (2/3/4-byte repeating patterns)
- **IOC Extraction**: Identifies URLs, IPv4 addresses, domains, email addresses, registry keys, Windows mutexes, file paths, and cryptocurrency addresses
- **Entropy & Keyword Analysis**: Calculates Shannon entropy and detects suspicious API calls and malicious patterns
- **MITRE ATT&CK Mapping**: Maps detected behaviors to ATT&CK techniques with confidence scoring
- **YARA Rule Generation**: Creates file-based detection signatures with metadata and configurable thresholds
- **Sigma Rule Generation**: Produces SIEM-compatible detection rules in YAML format

### Key Features

✅ **Static Analysis Only** - Safe for production workstations (no execution or dynamic analysis)
✅ **Individual & Catch-All Rules** - Generate targeted rules per IOC type or comprehensive detection rules
✅ **User-Selectable Detection** - Choose specific findings to include in custom rules via Web GUI
✅ **Fast Processing** - Analyzes typical malware samples (1-10MB) in under 5 seconds
✅ **Multiple Interfaces** - Command-line tool, Web GUI, and REST API

---

## Quick Start

### Installation

#### Option 1: Automated Deployment (Recommended)
```bash
# Clone repository
git clone https://github.com/BearWatchDev/Veriscope.git
cd Veriscope

# Run deployment script (handles dependencies automatically)
chmod +x deploy_gui.sh
./deploy_gui.sh

# Or use quick start script
chmod +x quick_start.sh
./quick_start.sh
```

#### Option 2: Manual Installation
```bash
# Install dependencies
pip3 install flask pyyaml

# Or use system packages (Ubuntu/Debian)
sudo apt-get install python3-flask python3-yaml
```

### Usage

#### Web GUI (Recommended for Analysts)
```bash
# Start web interface
python3 src/veriscope/interfaces/web.py

# Open browser to http://localhost:5000
# Upload sample → Analyze → Select findings → Generate custom rules
```

#### Command Line Interface
```bash
# Basic analysis
python3 src/veriscope/cli.py sample.txt --name PhishingCampaign --author YourName

# Specify output directory
python3 src/veriscope/cli.py malware.bin --name Ransomware --out ./analysis_results

# Output files generated:
# - report.md          (human-readable summary)
# - yara_rule.yar      (YARA detection template)
# - sigma_rule.yml     (Sigma SIEM rule template)
# - results.json       (structured data)
```

#### Supported File Types
- Text files: `.txt`, `.log`, `.ps1`, `.bat`, `.sh`, `.js`, `.vbs`
- Binary files: `.exe`, `.dll`, `.bin`
- Maximum file size: 100MB

---

## Web GUI Features

The Web GUI provides a modern, dark-themed interface with:

### 1. Advanced Deobfuscation Results
- **Multi-layer unwrapping**: Automatically decodes up to 10 layers of nested obfuscation
- **Detailed audit trail**: Shows exact deobfuscation chain (e.g., XOR → Base64 → GZIP → ROT13)
- **Method previews**: Displays intermediate decoded content for each layer
- **Intelligent detection**:
  - Plaintext detection stops when high-quality plaintext found
  - SHA1 hash-based cycle prevention
  - English language scoring validates successful decoding
  - Configurable timeout (2s default) and size limits (1MB)
- **Suspicious pattern identification**: Flags PowerShell obfuscation, dangerous commands, URLs, IPs
- **Select specific decoded strings** for custom rule generation

### 2. IOC Detection
- Categorized indicators: URLs, IPs, domains, registry keys, mutexes, file paths, crypto addresses
- Checkbox selection for targeted rule creation
- Export individual IOC-specific YARA/Sigma rules

### 3. MITRE ATT&CK Mapping
- Technique identification with confidence scores
- Tactic categorization (Persistence, Defense Evasion, Command & Control, etc.)
- Direct links to ATT&CK framework documentation

### 4. Dynamic Rule Generation
- Generate rules from selected findings only
- Download individual or combined detection rules
- Modal preview before download

### 5. Comprehensive Reports
- Markdown-formatted analysis reports
- Export-ready for threat intelligence sharing

---

## Architecture

```
Core Engine (Python stdlib)
├── deobfuscator.py      → Advanced multi-layer decoding engine
│                          • GZIP, XOR, Base64, Hex, ROT13, URL encoding
│                          • SHA1 cycle detection, timeout enforcement
│                          • English scoring, plaintext detection
│                          • Configurable depth (default: 6 layers)
├── ioc_detector.py      → Pattern-based IOC extraction
├── attack_mapper.py     → Heuristic ATT&CK mapping
├── yara_generator.py    → YARA rule template creation
├── sigma_generator.py   → Sigma rule template creation
└── engine.py            → Unified analysis orchestrator

Interfaces
├── cli.py               → Command-line interface
├── web.py               → Flask web dashboard
└── api.py               → REST API (future)

Frontend
├── static/css/style.css → Dark cybersecurity theme
├── static/js/app.js     → Dynamic rule generation logic
└── templates/           → HTML templates
```

---

## Deobfuscation Engine

### Supported Encoding Methods

| Method | Description | Key Features |
|--------|-------------|--------------|
| **Base64** | Standard and PowerShell (UTF-16LE) | Automatic UTF-8/UTF-16LE detection |
| **GZIP** | Compressed data streams | Magic byte detection (0x1f 0x8b) |
| **Hexadecimal** | Hex-encoded strings | Binary data preservation via latin-1 |
| **XOR** | Single-byte XOR cipher | 14 common keys + optional brute-force |
| **UTF-16LE** | Windows/PowerShell encoding | Null-byte pattern detection |
| **ROT13** | Caesar cipher rotation | English language scoring |
| **URL Encoding** | Percent-encoded strings | RFC 3986 compliant |

### Configuration

Customize deobfuscation behavior programmatically:

```python
from veriscope.core.engine import VeriscopeEngine
from veriscope.core.deobfuscator import DeobfuscationConfig

# Configure deobfuscation settings
config = DeobfuscationConfig(
    enabled=True,
    max_depth=6,                    # Maximum layers to unwrap
    per_string_timeout_secs=2.0,    # Timeout per string
    max_input_bytes=1_048_576,      # 1 MiB size limit
    xor_enabled=True,
    xor_common_keys=[0x5A, 0x20, 0xFF, 0xAA],
    xor_aggressive_bruteforce=False # Conservative XOR detection
)

# Initialize engine with custom config
engine = VeriscopeEngine(deobfuscation_config=config)
result = engine.analyze_file("sample.txt")

# Access deobfuscation trace
for deob_result in result.deobfuscation_results:
    print(f"Layers: {deob_result.layers_decoded}")
    print(f"Methods: {deob_result.methods_used}")
    for method, success, preview in deob_result.trace:
        print(f"  {'✓' if success else '✗'} {method}: {preview[:60]}")
```

### Safety Features

- **Cycle Detection**: SHA1 hashing prevents infinite loops
- **Timeout Protection**: 2-second default per string
- **Size Limits**: 1 MiB input maximum
- **Intelligent Stopping**: Keyword-based plaintext detection
- **Binary Preservation**: Latin-1 encoding maintains all bytes through decode chains

---

## Detection Rules

### YARA Rules
Generated YARA rules include:
- **Metadata**: Author, date, MITRE ATT&CK techniques, TLP classification, confidence level
- **String Conditions**: URLs, IPs, domains, registry keys, mutexes, high-entropy strings, PowerShell indicators
- **Configurable Thresholds**: File size limits, minimum string matches (default: 3 of *)
- **IOC-Specific Rules**: Individual rules per IOC category for targeted detection

Example output:
```yara
rule PhishingCampaign_URLs {
    meta:
        author = "YourName"
        date = "2025-10-04"
        ioc_type = "URL"
    strings:
        $url1 = "http://malicious-site.com/payload" nocase
        $url2 = "https://phishing-domain.net/login" nocase
    condition:
        any of ($url*)
}
```

### Sigma Rules
Generated Sigma rules include:
- **Log Source Definitions**: Proxy, DNS, process execution, registry, file operations
- **Detection Logic**: Keyword-based selection criteria
- **Severity Levels**: High/Medium/Low based on indicator confidence
- **Export Formats**: Compatible with Splunk, Elastic, QRadar, ArcSight

Example output:
```yaml
title: PhishingCampaign - Network Activity
logsource:
  category: proxy
  product: windows
detection:
  selection:
    c-uri|contains:
      - 'http://malicious-site.com/payload'
      - 'https://phishing-domain.net/login'
  condition: selection
level: high
```

---

## MITRE ATT&CK Coverage

Veriscope maps indicators to ATT&CK techniques across multiple tactics:

| Tactic | Example Techniques |
|--------|-------------------|
| Persistence | Registry Run Keys, Scheduled Tasks, Service Creation |
| Privilege Escalation | DLL Hijacking, UAC Bypass, Token Manipulation |
| Defense Evasion | Obfuscated Files, Process Injection, Indicator Removal |
| Credential Access | Credential Dumping, Keylogging, Browser Credentials |
| Discovery | System Information, Network Discovery, Process Discovery |
| Lateral Movement | Remote Services, SMB/Windows Admin Shares |
| Command and Control | Web Protocols, DNS Tunneling, Encrypted Channels |
| Exfiltration | Data Compressed, C2 Channel, Web Services |

**Note**: Mappings are heuristic-based and require validation with threat intelligence.

---

## Security & Best Practices

### Static Analysis Only
Veriscope performs **static text analysis exclusively**. It does NOT:
- Execute binaries or scripts
- Run sandboxed environments
- Perform dynamic/behavioral analysis
- Modify or write to samples

All operations are read-only and safe for production analyst workstations.

### Rule Templates Require Review
Generated YARA and Sigma rules are **TEMPLATES** designed to accelerate detection engineering. They require:
- Human review and tuning
- Validation in test environments
- False positive analysis before production deployment

### ATT&CK Mapping Limitations
Technique mappings are derived from keyword matching and pattern detection. Always:
- Correlate with sandbox reports and threat intelligence
- Validate behavioral analysis
- Review confidence scores before attribution

---

## Process Cleanup

When closing the Web GUI via terminal (Ctrl+C), Veriscope automatically:
- Cleans up temporary files
- Terminates all background processes
- Removes PID and lock files

Manual cleanup (if needed):
```bash
chmod +x cleanup_veriscope.sh
./cleanup_veriscope.sh
```

---

## Project Information

**Version**: 1.1.0
**License**: MIT
**Platform**: Linux-first, cross-platform compatible (Windows, macOS)
**Dependencies**: Python 3.8+, Flask, PyYAML
**Contact**: BearWatchDev@pm.me

### Changelog

**v1.1.0** (2025-10-05)
- ✨ **NEW**: Compression support (GZIP, zlib, bzip2) with magic byte detection
- ✨ **NEW**: Multi-byte XOR decoding (2/3/4-byte repeating keys, 8 common patterns)
- ✨ **NEW**: UTF-16LE support for Windows/PowerShell malware
- ✨ **NEW**: Marker-based plaintext detection (prevents over-decoding)
- ✨ **NEW**: DeobfuscationConfig class for engine configuration
- ✨ **NEW**: Latin-1 encoding fallback for binary data preservation
- 🔧 **IMPROVED**: Base64 noise filtering and conditional padding normalization
- 🔧 **IMPROVED**: ROT13 keyword expansion (added: token, shell, alert, process)
- 🔧 **IMPROVED**: Quality tracking with degradation detection
- 🔧 **IMPROVED**: Method execution ordering (Hex → UTF-16LE → ROT13 → Base64 → XOR)
- 🔧 **IMPROVED**: Detailed audit trail with method traces

**v1.0.0** (2025-10-04)
- 🎉 Initial release
- Core deobfuscation: Base64, Hex, URL encoding, PowerShell
- IOC extraction and MITRE ATT&CK mapping
- YARA and Sigma rule generation
- Web GUI and CLI interfaces

### Repository Structure
```
Veriscope/
├── src/veriscope/          # Core engine modules
│   ├── core/               # Analysis components
│   └── interfaces/         # CLI, Web, API
├── static/                 # Web GUI assets (CSS, JS, images)
├── templates/              # HTML templates
├── tests/                  # Unit tests
├── deploy_gui.sh           # Automated deployment script
├── quick_start.sh          # Simple startup script
├── cleanup_veriscope.sh    # Process cleanup utility
└── README.md               # This file
```

---

## Ethical Use

Veriscope is developed and distributed **exclusively for defensive cybersecurity operations**. It is intended for use by:
- Security analysts and threat hunters
- Incident responders
- SOC teams and detection engineers
- Malware researchers (academic/defensive)

**Prohibited Uses**:
- Malicious purposes or offensive operations outside authorized penetration testing
- Any activity that violates applicable laws (CFAA, GDPR, local cybersecurity regulations)

Users are responsible for ensuring compliance with all relevant regulations and ethical guidelines.

---

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes with clear messages
4. Push to your branch (`git push origin feature/improvement`)
5. Open a Pull Request

For bug reports or feature requests, please open an issue with:
- Detailed description
- Steps to reproduce (for bugs)
- Expected vs actual behavior
- System information (OS, Python version)

---

## Support

**Email**: BearWatchDev@pm.me
**Issues**: https://github.com/BearWatchDev/Veriscope/issues
**Documentation**: This README and inline code comments

---

## License

MIT License - See LICENSE file for details

---

**Made with ❤ for the cybersecurity community**

*Veriscope v1.1.0 | Advanced multi-layer deobfuscation for defensive security operations*
