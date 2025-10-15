# Changelog

All notable changes to Veriscope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2025-10-15

### Major Enhancements

#### Quality Regression System Improvements
- **CRITICAL FIX**: Quality regression now handles short strings and moderate-quality results correctly
  - Added relative quality threshold for intermediates with quality ≥0.35
  - Fixed false rejection of valid short strings (e.g., "Credential: admin:P@ssw0rd123!@#")
  - System now selects best intermediate layer even if below absolute threshold when significantly better than final
  - Prevents over-decoding when early layers contain correct plaintext

#### String Reversal Decoder
- **NEW**: Added `StringReversalDecoder` to handle reversed Base64 patterns
  - Detects reversed base64 padding (`=` or `==` at start instead of end)
  - Validates base64 alphabet ratio (>85%) before reversing
  - Integrated into decoder pipeline before standard decoders
  - Handles common obfuscation technique of reversing encoded strings

#### Enhanced ROT13 Detection
- **Expanded keyword library**: Added malware/security-specific terms
  - New keywords: backdoor, bash, bin, netcat, tmp, shell, malware, trojan, credential, registry, persistence
  - Total keywords: 45+ terms covering security operations and malware behaviors
- **Fixed Base64 false-positive check**: No longer counts forward slash `/` as Base64 indicator
  - Only counts `+` and `=` characters (actual Base64-specific chars)
  - Prevents rejection of legitimate shell commands like `/bin/bash`
- **Decoder ordering fix**: URL decoder now runs before ROT13
  - Ensures URL-encoded ROT13 text is properly decoded in sequence
- **Enhanced quality scoring**: Added security terms to quality calculation
  - Malware/security keywords now boost quality scores
  - Prevents quality regression from truncating correctly decoded security-related text

#### Multi-byte XOR Improvements
- **Added 0xDEAD key**: Common 2-byte XOR key now in default key list
  - Complements existing 0xDEADBE and 0xDEADBEEF keys
  - Handles common malware XOR patterns
- **Decoder ordering optimization**: Multi-byte XOR now runs before single-byte XOR
  - More specific decoder (limited key list) before generic brute-force
  - Prevents single-byte XOR from corrupting multi-byte encrypted data
  - Improves detection accuracy for multi-byte encrypted payloads

### Performance & Testing
- **Custom test suite**: 80% pass rate on 20 diverse encoding patterns (up from 55%)
  - Tests cover: GZIP compression, PowerShell UTF-16LE, JSON/JS wrappers, character codes, multi-byte XOR, ROT13, string reversal, complex 3-4 layer chains
- **Validation**: No regressions on existing test packs (easy50: 84%, hardset_30: 80%)
- **Quality score improvements**: Average quality increased from 0.45 to 0.54

### Fixed
- Quality regression selecting over-decoded results instead of correct intermediate layers
- String reversal decoder not being called (existed but wasn't in pipeline)
- ROT13 decoder rejecting valid shell commands due to `/` character
- Multi-byte XOR failing due to single-byte XOR running first
- Security-related plaintext scoring lower than encoded garbage

### Added
- `StringReversalDecoder` class in `string_transforms.py`
- 0xDEAD to multi-byte XOR key list in `xor_encoding.py`
- Security/malware keywords to ROT13 keyword set
- Security/malware keywords to quality scoring word list
- Relative quality threshold logic for moderate-quality intermediates

### Changed
- Decoder execution order: String reversal added early, URL before ROT13, multi-byte XOR before single-byte XOR
- Base64 false-positive check in ROT13 decoder (slash no longer counted)
- Quality regression intermediate selection logic (relative vs absolute thresholds)
- Quality scoring weights and keyword expansion

### Technical Details
- Modified files: `deobfuscator.py`, `string_transforms.py`, `xor_encoding.py`, `rot13_url.py`, `__init__.py`
- Quality threshold formula: `intermediate_quality >= 0.35 AND improvement >= 0.05`
- Decoder order: Extractors → Transforms (incl. reversal) → URL → ROT13 → Base64 → Compression → Multi-byte XOR → Single-byte XOR

## [1.4.2] - 2025-10-15

### Fixed
- **CRITICAL BUG FIX**: Quality scoring algorithm now properly detects ROT13-encoded text
  - Fixed under-decoding issue where ROT13-encoded text scored the same as plaintext
  - Added ROT13 word dictionary (cebkl→proxy, nhgu→auth, onfvp→basic, etc.)
  - ROT13 detection now returns quality score of 0.0 when 2+ ROT13 words detected
  - Fixed intermediate layer selection incorrectly choosing encoded text over final plaintext

### Added
- **Encoding artifact penalty system** (`_encoding_artifact_penalty()` method)
  - Detects Base64 padding (== or = at end) - adds 0.3-0.4 penalty
  - Detects URL encoding (%XX patterns) - adds 0.3-0.5 penalty based on ratio
  - Detects hex-only patterns (95%+ hex digits) - adds 0.6 penalty
  - Detects Base64-like character distribution without spaces - adds 0.3-0.5 penalty
- **Enhanced English word detection** using regex word boundaries (`\b`)
  - Handles punctuation correctly (e.g., "proxy:" now matches "proxy")
  - Expanded common word dictionary to 50+ words for better accuracy
  - Proper word boundary matching prevents false matches (e.g., "the" in "other")

### Improved
- **Quality scoring weights** rebalanced for better accuracy
  - word_score: 40% → 45% (primary signal increased)
  - letter_ratio: 30% → 25% (reduced to make room for encoding penalty)
  - structure_score: 30% → 20% (reduced to make room for encoding penalty)
  - encoding_penalty: 0% → 10% (NEW - penalizes remaining encoding artifacts)
- **Intermediate result selection** now properly truncates methods_used list
  - When intermediate result selected, methods_used is also truncated to match
  - Prevents misleading method chains in results

### Validated
- **Test improvement**: easy50 success rate increased from 16% to 84% (+68 percentage points)
- **DeepSeek benchmark**: Maintained 60% success rate (no regression on complex samples)
- **Quality detection**: ROT13-encoded text now scores 0.28, plaintext scores 0.73 (properly differentiated)

### Technical
- Added `import re` for regex word boundary matching in `_english_score()`
- Quality calculation formula: `(letter * 0.25) + (word * 0.45) + (structure * 0.20) - (penalty * 0.10)`
- Encoding penalty capped at 1.0 maximum, quality clamped to [0.0, 1.0] range

## [1.4.1] - 2025-10-14

### Added
- **Automatic Preset Rotation**: NEW intelligent fallback system that automatically tries multiple presets when default fails
  - Automatically rotates through presets: `balanced` → `malware_analysis` → `aggressive` → `deepseek_optimized`
  - No manual configuration required - happens transparently in background
  - Early termination when a preset succeeds (performance optimized)
  - Returns best result based on quality score across all attempts
  - Adds `_enable_auto_rotation` parameter to prevent infinite recursion
  - Tags results with `auto_fallback` strategy indicator
  - Comprehensive test suite validates no infinite loops (`test_auto_rotation.py`)

### Improved
- **Deobfuscator robustness**: Significantly improved success rate on difficult obfuscation patterns
  - Automatically handles edge cases that previously required manual preset selection
  - Graceful degradation: tries up to 4 different preset configurations
  - Best-effort result selection when all presets fail

### Documentation
- Updated CLAUDE.md with automatic preset rotation usage examples
- Added troubleshooting guidance for v1.4.1+ automatic handling

## [1.4.0] - 2025-10-08

### Improved
- **ROT13Decoder performance optimization**: Cached common keywords and Base64 alphabet as class-level `frozenset` constants
  - Eliminates list recreation on every decode operation (213k ops/sec throughput)
  - Reduces memory allocations during high-volume processing
  - Changed `common_words` list to `COMMON_KEYWORDS` frozenset (faster membership testing)
- **HexDecoder odd-length handling**: Now handles odd-length hex strings by prepending '0' instead of rejecting them
  - More forgiving for malformed hex-encoded payloads found in obfuscated JavaScript
- **Base64Decoder hex detection optimization**: More efficient hex string detection
  - Reduced sample size from 100 chars to 60 chars for hex checking (139k ops/sec throughput)
  - Uses `frozenset` for faster character membership testing
  - Maintains accuracy while improving performance on long strings
- **CharCodesDecoder hex format support**: Now supports hexadecimal character codes in addition to decimal
  - Formats supported: `"0x48,0x65,0x6c,0x6c,0x6f"` (hex) and `"72,101,108,108,111"` (decimal)
  - Automatically detects and parses hex prefix (`0x`)
  - Handles JavaScript `String.fromCharCode(0x48, ...)` obfuscation patterns

### Performance
- **Batch processing**: 71k samples/sec in realistic multi-decoder workflow (50% improvement)
- **Memory efficiency**: Class-level constants reduce allocations during high-volume analysis

### Technical
- **Decoder constants**: Moved frequently-used constants to class level for memory efficiency
- **Algorithm improvements**: Optimized character set lookups with `frozenset` instead of string containment checks
- **Edge case handling**: Better handling of malformed inputs (odd-length hex, mixed format char codes)

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
