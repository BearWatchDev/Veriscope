# Changelog

All notable changes to Veriscope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2025-10-06

### Added
- **Real-time deobfuscation progress tracking** with Server-Sent Events (SSE)
- **Animated progress bar** showing live method attempts and successful decodes
- **Dynamic method chain visualization** displaying decode sequence (e.g., `base64 → hex → rot13`)
- **Enhanced detection rules** now include BOTH obfuscated AND deobfuscated strings in YARA/Sigma rules
- **High-entropy string inclusion** automatically adds suspicious encoded content (40+ chars) to detection rules
- **Queued UI updates** with 400ms delays for smooth, sequential method chain animations

### Improved
- **Base64 detection in XOR methods** prevents false positives with 95% character ratio threshold
- **Minimum string length** for deobfuscation increased to 40 characters (reduces noise from fragments)
- **Duplicate filtering** automatically removes duplicate deobfuscation results
- **Plaintext marker detection** no longer adds unnecessary trace entries (cleaner output)
- **Progress bar completion** guaranteed to reach 100% before results display
- **Sigma rule generation** includes high-entropy encoded strings for better malware detection coverage

### Fixed
- **XOR false positives**: XOR methods no longer trigger on valid Base64 strings
- **Progress bar synchronization**: Resolved timing issues between SSE updates and UI display
- **Method chain display**: Now builds sequentially with delays instead of appearing all at once
- **Layer counting**: Plaintext marker detection no longer counted as an additional layer

### Technical
- Added progress callback system with decimal layer values for granular updates (e.g., 2.3 = layer 2, 30% through methods)
- Implemented Server-Sent Events endpoint (`/progress/<session_id>`) for real-time streaming
- Added JavaScript queue system for controlled UI update pacing
- Enhanced deobfuscator to track method attempts vs successes separately

---

## [1.1.0] - 2025-10-05

### Added
- **Compression support**: GZIP, zlib, bzip2 with magic byte detection
- **Multi-byte XOR decoding**: 2/3/4-byte repeating keys with 8 common patterns
- **UTF-16LE support**: Handles Windows/PowerShell malware encodings
- **Marker-based plaintext detection**: Prevents over-decoding with keyword recognition
- **DeobfuscationConfig class**: Programmatic engine configuration
- **Latin-1 encoding fallback**: Preserves binary data through decode chains

### Improved
- **Base64 decoder**: Noise filtering and conditional padding normalization
- **ROT13 keywords**: Expanded to include token, shell, alert, process
- **Quality tracking**: Detects degradation to prevent bad decodes
- **Method ordering**: Optimized execution sequence (Hex → UTF-16LE → ROT13 → Base64 → XOR)
- **Audit trail**: Detailed method traces with success/failure indicators

### Technical
- Implemented SHA1-based cycle detection
- Added configurable timeout protection (2s default per string)
- Size limits enforced (1 MiB input maximum)
- Binary data preservation through all decode operations

---

## [1.0.0] - 2025-10-04

### Added
- **Initial release** of Veriscope malware analysis platform
- **Core deobfuscation engine**: Base64, Hex, URL encoding, PowerShell
- **IOC extraction**: URLs, IPs, domains, emails, registry keys, file paths, mutexes, crypto addresses
- **MITRE ATT&CK mapping**: Heuristic-based technique identification
- **YARA rule generation**: File-based detection signatures with metadata
- **Sigma rule generation**: SIEM-compatible detection rules in YAML format
- **Web GUI**: Dark-themed interface with drag-and-drop file upload
- **CLI interface**: Command-line tool for batch processing
- **REST API**: FastAPI-based HTTP endpoints (experimental)

### Features
- Static analysis only (no execution or dynamic analysis)
- Individual and catch-all rule generation
- User-selectable detection via Web GUI
- Fast processing (< 5 seconds for typical samples)
- Multiple interfaces (CLI, Web, API)

---

## Release Notes

### Version Scheme
- **Major** (x.0.0): Breaking changes, major architecture updates
- **Minor** (1.x.0): New features, enhancements, non-breaking changes
- **Patch** (1.1.x): Bug fixes, performance improvements

### Compatibility
- **Python**: 3.8+
- **Platform**: Linux-first, cross-platform compatible (Windows, macOS)
- **Dependencies**: Flask, PyYAML (minimal external dependencies)

### Support
- **Email**: BearWatchDev@pm.me
- **Issues**: https://github.com/BearWatchDev/Veriscope/issues
- **License**: MIT
