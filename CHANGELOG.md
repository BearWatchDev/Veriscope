# Changelog

All notable changes to Veriscope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2025-10-07

### Added
- **Quality Regression Detection**: NEW validation strategy that detects when decoding degrades output quality
  - Automatically truncates decode chains at quality peaks (prevents over-decoding)
  - Preserves good intermediate results even when further decoding produces garbage
  - Configurable quality threshold (0.47) and minimum improvement delta (0.05)
  - Example: `hex → "TEST MESSAGE 2" (quality 0.50) → base64 → garbage (quality 0.43)` now stops at layer 1
- **HTML Entity Decoder** (`HTMLEntityDecoder`): Decodes HTML entities (`&lt;`, `&gt;`, `&amp;`, etc.)
  - Handles HTML-encoded malware scripts and payloads
  - Only activates when entities detected (conservative heuristics)
- **JSON/JavaScript Extractors**: Extract payloads from wrapped encoded data
  - `JSONExtractorDecoder`: Extracts from JSON fields (`{"payload": "base64..."}` → `"base64..."`)
  - `JSAtobExtractorDecoder`: Extracts from JavaScript atob() calls (`eval(atob("VEV..."))` → `"VEV..."`)
  - Critical for modern JavaScript-based malware obfuscation
- **Base64/PowerShell skip logic**: Prevents premature matching on JSON/JS wrapped data
  - Base64 and PowerShell decoders now skip inputs that look like JSON (`{`) or JS (`atob(`, `btoa(`)
  - Allows extractors to run first before attempting decode

### Improved
- **Short string threshold**: Reduced from 10 to 4 characters to allow valid short outputs like "TEST"
- **Intermediate result validation**: Multi-stage validation checks final result first, then searches intermediates
  - Checks for null bytes (< 3% threshold)
  - Checks for excessive non-ASCII (< 5% threshold)
  - Checks for hex-only patterns (> 90% hex digits indicates still-encoded)
  - Requires minimum quality improvement of 0.05 over final result
- **Hex pattern detection**: Filters out intermediate results that are still hex-encoded (prevents false stops)

### Fixed
- **Over-decoding problem**: System no longer continues decoding past the correct plaintext
  - Example: `"54 45 53 54..."` (hex) → `"TEST MESSAGE 2"` (correct) → continued to garbage
  - Now stops at quality peak and truncates result list
- **Strategy fallback quality**: Fallback strategies now correctly compare quality scores to select best result
- **Deobfuscated list truncation**: When intermediate result selected, list is truncated to stop at that point

### Validation
- **Internal test suites**: Validated against progressive difficulty malware samples
- **Quality improvements**: +10% success rate on complex multi-layer obfuscation chains
- **Key capabilities verified**:
  - Hex-encoded plaintext detection
  - ROT13 cipher handling
  - HTML entity-encoded payloads
  - JSON-wrapped Base64 extraction
  - JavaScript atob() wrapper extraction

### Technical
- **Quality-based stopping**: `_validate_result_quality()` now examines entire decode chain
- **Intermediate result scoring**: Each layer evaluated independently for quality regression
- **Conservative thresholds**:
  - Only checks intermediates if final quality < 0.47 and layers >= 2
  - Requires intermediate quality >= 0.50 AND >= final + 0.05
  - Filters out binary data (nulls), non-ASCII, and hex-pattern strings
- **Result truncation**: `result.deobfuscated = result.deobfuscated[:best_index + 1]`

---

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
