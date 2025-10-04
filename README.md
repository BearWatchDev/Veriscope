# Veriscope

**Automated Malware Analysis & Detection Engineering Platform**

Veriscope transforms raw malware artifacts into actionable detection intelligence through automated deobfuscation, IOC extraction, and detection rule generation.

![Version](https://img.shields.io/badge/version-1.0.0-green) ![License](https://img.shields.io/badge/license-MIT-blue) ![Python](https://img.shields.io/badge/python-3.8+-blue)

---

## Overview

Veriscope is a specialized tool for security analysts, threat hunters, and SOC teams that automates the malware analysis workflow:

**Deobfuscate Malware ▶ Extract IOCs ▶ Generate YARA/Sigma Detection Rules**

### What It Does

- **Multi-Layer Deobfuscation**: Automatically decodes Base64, hexadecimal, URL encoding, PowerShell obfuscation, and nested encoding chains
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

### 1. Deobfuscation Results
- View decoded layers with entropy scores
- Identify suspicious patterns automatically
- Select specific decoded strings for custom rule generation

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
├── deobfuscator.py      → Multi-layer decoding engine
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

**Version**: 1.0.0
**License**: MIT
**Platform**: Linux-first, cross-platform compatible (Windows, macOS)
**Dependencies**: Python 3.8+, Flask, PyYAML
**Contact**: BearWatchDev@pm.me

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

*Veriscope v1.0.0 | For ethical & defensive security operations only*
