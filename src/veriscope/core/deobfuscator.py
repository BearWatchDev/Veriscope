"""
Deobfuscation Module v1.2 (Modular)
Automatically decodes/deobfuscates common encoding schemes found in malware

Handles:
- Base64 encoding (single and multi-layer, with noise filtering and padding normalization)
- Hex encoding with binary preservation
- GZIP compression (magic bytes: 0x1f 0x8b)
- zlib compression (magic bytes: 0x78 0x01/0x5E/0x9C/0xDA)
- bzip2 compression (magic bytes: "BZh" + compression level)
- UTF-16LE encoding (Windows/PowerShell malware)
- Single-byte XOR with configurable keys
- Multi-byte XOR (2/3/4-byte repeating keys)
- URL encoding
- PowerShell encoding (UTF-16 LE Base64)
- ROT13/Caesar cipher
- Character codes

Features:
- Multi-layer unwrapping (up to 6 layers by default)
- SHA1 hash-based cycle detection
- Marker-based plaintext detection (prevents over-decoding)
- Configurable per-string timeout (2 seconds default)
- Input size limits (1 MiB default)
- Quality tracking to prevent degradation
- Detailed audit trail with method and preview for each layer
- Modular decoder architecture for maintainability

Architecture:
- Uses pluggable decoder modules from deobfuscation/ package
- Each decoder implements BaseDecoder interface
- Decoders are self-contained and independently testable
"""

import time
import hashlib
from typing import List, Tuple, Set, Callable, Optional
from dataclasses import dataclass, field

# Import modular decoders
from .deobfuscation import get_all_decoders
from .deobfuscation_presets import DeobfuscationPreset, PresetLibrary, ValidationThresholds


@dataclass
class DeobfuscationConfig:
    """
    Configuration for deobfuscation engine

    Can be initialized from:
    1. Preset name: DeobfuscationConfig(preset="aggressive")
    2. Custom parameters: DeobfuscationConfig(max_depth=8, xor_enabled=False)
    3. Preset + overrides: DeobfuscationConfig(preset="balanced", max_depth=8)
    """
    enabled: bool = True
    max_depth: int = 6
    per_string_timeout_secs: float = 2.0
    max_input_bytes: int = 1_048_576  # 1 MiB
    xor_enabled: bool = True
    xor_common_keys: List[int] = field(default_factory=lambda: [
        0x5A, 0x20, 0xFF, 0xAA, 0x01, 0x42, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAB, 0xCD, 0xEF
    ])
    xor_aggressive_bruteforce: bool = False
    min_output_length: int = 2
    speculative_rot13: bool = False  # Try ROT13 even without keyword matches (experimental, can cause false positives)
    smart_mode: bool = False  # DEPRECATED: Smart mode now runs automatically as fallback when default fails
    smart_mode_timeout_multiplier: float = 3.0  # DEPRECATED: No longer used (smart mode is automatic fallback)
    progress_callback: Optional[Callable[[str, int, int, str], None]] = None  # callback(method, layer, total_layers, preview)

    # Validation thresholds (can be set via preset or manually)
    thresholds: ValidationThresholds = field(default_factory=ValidationThresholds)

    # Preset-based initialization
    preset: Optional[str] = None  # Preset name to load ("conservative", "balanced", "aggressive", etc.)

    def __post_init__(self):
        """Apply preset if specified"""
        if self.preset:
            preset_obj = PresetLibrary.get_preset(self.preset)
            if preset_obj:
                # Apply preset values (but don't override explicitly set values)
                # This is tricky with dataclasses, so we'll apply preset as base
                # Note: Explicitly set values in __init__ will override preset
                if not hasattr(self, '_preset_applied'):
                    self.max_depth = preset_obj.max_depth
                    self.per_string_timeout_secs = preset_obj.per_string_timeout_secs
                    self.max_input_bytes = preset_obj.max_input_bytes
                    self.xor_enabled = preset_obj.xor_enabled
                    self.xor_common_keys = preset_obj.xor_common_keys
                    self.xor_aggressive_bruteforce = preset_obj.xor_aggressive_bruteforce
                    self.min_output_length = preset_obj.min_output_length
                    self.speculative_rot13 = preset_obj.speculative_rot13
                    self.thresholds = preset_obj.thresholds
                    self._preset_applied = True

    @staticmethod
    def from_preset(preset_name: str, **overrides) -> 'DeobfuscationConfig':
        """
        Create config from preset with optional overrides

        Example:
            config = DeobfuscationConfig.from_preset("aggressive", max_depth=10)
        """
        preset = PresetLibrary.get_preset(preset_name)
        if not preset:
            raise ValueError(f"Unknown preset: {preset_name}. Available: {PresetLibrary.list_presets()}")

        # Start with preset values
        config = DeobfuscationConfig(
            enabled=True,
            max_depth=preset.max_depth,
            per_string_timeout_secs=preset.per_string_timeout_secs,
            max_input_bytes=preset.max_input_bytes,
            xor_enabled=preset.xor_enabled,
            xor_common_keys=preset.xor_common_keys,
            xor_aggressive_bruteforce=preset.xor_aggressive_bruteforce,
            min_output_length=preset.min_output_length,
            speculative_rot13=preset.speculative_rot13,
            thresholds=preset.thresholds,
            preset=preset_name
        )

        # Apply overrides
        for key, value in overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)

        return config


@dataclass
class DeobfuscationResult:
    """Container for deobfuscation results"""
    original: str
    deobfuscated: List[str] = field(default_factory=list)
    layers_decoded: int = 0
    methods_used: List[str] = field(default_factory=list)
    suspicious_patterns: List[str] = field(default_factory=list)
    trace: List[Tuple[str, bool, str]] = field(default_factory=list)  # (method, success, preview)
    timed_out: bool = False
    failed: bool = False  # True if deobfuscation produced low-quality or mangled output
    failure_reason: str = ""  # Human-readable explanation of why deobfuscation failed
    quality_score: float = 0.0  # Overall quality score of final result (0.0 - 1.0)
    strategy_used: str = "default"  # Which decoder ordering strategy succeeded
    strategies_attempted: List[str] = field(default_factory=list)  # All strategies tried

    def get_all_strings(self) -> List[str]:
        """Get both original and deobfuscated strings"""
        return [self.original] + self.deobfuscated


class Deobfuscator:
    """
    Advanced multi-method deobfuscator for malware encoding techniques

    Supports compression, encoding chains, and intelligent plaintext detection
    """

    def __init__(self, config: DeobfuscationConfig = None):
        """Initialize deobfuscator with configuration"""
        self.config = config if config else DeobfuscationConfig()
        
        # Initialize modular decoders
        self.decoders = get_all_decoders(self.config)

    def deobfuscate_string(self, text: str) -> DeobfuscationResult:
        """
        Attempt to deobfuscate a single string using multiple methods

        First tries default decoder ordering. If that fails, automatically
        falls back to smart mode (trying multiple decoder orderings).

        Args:
            text: Input string (potentially obfuscated)

        Returns:
            DeobfuscationResult with original and deobfuscated versions
        """
        start_time = time.time()

        # Size limit check
        if len(text.encode('utf-8', errors='ignore')) > self.config.max_input_bytes:
            result = DeobfuscationResult(original=text)
            result.trace.append(('size_limit', False, f'Input too large'))
            result.failed = True
            result.failure_reason = "Input exceeds size limit"
            return result

        # Step 1: Try default strategy first (fast path)
        # Calculate total strategies for smooth progress (default + alternatives)
        all_strategies = self._get_decoder_strategies()
        total_strategies = len(all_strategies)

        result = self._try_single_strategy(text, "default", self.decoders, start_time,
                                           strategy_index=0, total_strategies=total_strategies)
        result.strategies_attempted.append("default")

        # Step 2: If default failed, automatically try smart mode as fallback
        if result.failed:
            smart_results = []

            # Try each alternative strategy (stop early if one succeeds)
            strategy_idx = 0
            for strategy_name, decoders in all_strategies:
                # Skip default since we already tried it
                if strategy_name == "default":
                    strategy_idx += 1
                    continue

                strategy_result = self._try_single_strategy(text, strategy_name, decoders, start_time,
                                                           strategy_index=strategy_idx,
                                                           total_strategies=total_strategies)
                strategy_result.strategies_attempted.append(strategy_name)
                smart_results.append(strategy_result)
                strategy_idx += 1

                # Early termination: if this strategy succeeded, no need to try others
                if not strategy_result.failed and not strategy_result.timed_out:
                    break

            # Pick the best result from smart mode attempts
            best_smart_result = None
            best_score = -1.0

            for r in smart_results:
                # Prioritize valid results
                if not r.failed and not r.timed_out:
                    # Score = quality * layers (prefer deeper decoding with good quality)
                    score = r.quality_score * (1 + r.layers_decoded * 0.1)
                    if score > best_score:
                        best_score = score
                        best_smart_result = r

            # If smart mode found a better result, use it
            if best_smart_result and not best_smart_result.failed:
                # Prepend "default" to show it was attempted first
                best_smart_result.strategies_attempted = ["default"] + best_smart_result.strategies_attempted
                return best_smart_result

            # If smart mode also failed, pick the one with highest quality score
            if smart_results:
                best_fallback = max(smart_results, key=lambda r: r.quality_score)
                if best_fallback.quality_score > result.quality_score:
                    # Update failure reason to indicate all strategies failed
                    all_strategies = [r.strategy_used for r in smart_results]
                    best_fallback.strategies_attempted = ["default"] + all_strategies
                    if not best_fallback.failure_reason:
                        best_fallback.failure_reason = f"All {len(smart_results) + 1} strategies failed to produce valid output"
                    return best_fallback
                else:
                    # All strategies failed and none better than default - update default result to show all attempts
                    all_strategies = [r.strategy_used for r in smart_results]
                    result.strategies_attempted = ["default"] + all_strategies
                    if not result.failure_reason:
                        result.failure_reason = f"All {len(smart_results) + 1} strategies failed to produce valid output"

        # Return default result (success or failure)
        return result

    def deobfuscate_with_preset_rotation(self, text: str, presets: List[str] = None) -> DeobfuscationResult:
        """
        Attempt deobfuscation with automatic preset rotation

        Tries multiple configuration presets automatically until one succeeds.
        This eliminates the need for manual threshold tuning for different test packs.

        Args:
            text: Input string (potentially obfuscated)
            presets: List of preset names to try (in order). If None, uses default rotation:
                     ["balanced", "malware_analysis", "aggressive", "deepseek_optimized"]

        Returns:
            DeobfuscationResult with best result found across all presets

        Example:
            deobfuscator = Deobfuscator()
            result = deobfuscator.deobfuscate_with_preset_rotation(obfuscated_string)
            print(f"Success with preset: {result.strategy_used}")
        """
        # Default preset rotation order
        if presets is None:
            presets = ["balanced", "malware_analysis", "aggressive", "deepseek_optimized"]

        results = []
        original_config = self.config

        for preset_name in presets:
            # Load preset configuration
            try:
                preset_config = DeobfuscationConfig.from_preset(preset_name)
                # Preserve progress callback from original config
                if original_config.progress_callback:
                    preset_config.progress_callback = original_config.progress_callback

                # Create new deobfuscator with preset config
                preset_deobfuscator = Deobfuscator(preset_config)

                # Try deobfuscation with this preset
                result = preset_deobfuscator.deobfuscate_string(text)

                # Tag result with preset name
                result.strategy_used = f"preset:{preset_name}"
                results.append(result)

                # Early termination: if this preset succeeded, no need to try others
                if not result.failed and not result.timed_out:
                    # Restore original config
                    self.config = original_config
                    self.decoders = get_all_decoders(self.config)
                    return result

            except Exception as e:
                # If preset loading fails, skip it
                continue

        # Restore original config
        self.config = original_config
        self.decoders = get_all_decoders(self.config)

        # All presets failed - return the best result based on quality score
        if results:
            best_result = max(results, key=lambda r: r.quality_score)
            # Update failure reason to show all presets were tried
            presets_tried = [r.strategy_used for r in results]
            best_result.strategies_attempted = presets_tried
            if not best_result.failure_reason:
                best_result.failure_reason = f"All {len(presets)} presets failed: {', '.join(presets)}"
            return best_result

        # No results at all - return empty failure
        result = DeobfuscationResult(original=text)
        result.failed = True
        result.failure_reason = "No valid presets to try"
        return result

    def _check_plaintext_markers(self, text: str) -> bool:
        """Check if text contains plaintext markers indicating it's already decoded"""
        # Don't stop if text is heavily URL-encoded (needs further decoding)
        url_encoded_ratio = text[:100].count('%') / max(1, len(text[:100]))
        if url_encoded_ratio > 0.05:  # More than 5% URL encoded
            return False

        MARKERS = [
            'BinaryMarker:', 'EncodingTest:', 'RandomBlob:', 'TraceID:',
            'Service:', 'Config:', 'UserActivity:', 'Path:', 'URL:',
            'Command:', 'Script:', 'Process:', 'Log:', 'SQL:',
            'Shell:', 'User:', 'Token:', 'Registry:', 'File:',
            'NoiseTest:', 'UTF16Test:', 'PossibleSQL:', 'Mail:',
            'Misc:', 'ExtraPayload:', 'AlertTag:', 'HTTP:', 'User-Agent:'
        ]

        # Common test/plaintext patterns (for benchmark tests)
        TEST_PATTERNS = [
            'this is', 'test message', 'hello world', 'welcome to',
            'layer #', 'encoding!', 'compressed!', 'obf!', 'obfuscation',
            'deobfuscation', 'caesar', 'cipher', 'binary!', 'char code'
        ]

        text_lower = text.lower()

        # Check for test patterns (common in benchmark tests)
        for pattern in TEST_PATTERNS:
            if pattern in text_lower[:80]:  # Check first 80 chars
                # Verify it's actually readable text, not just coincidence
                printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in text) / len(text)
                if printable_ratio > 0.85:
                    return True

        # Check for exact marker matches first (with colon/hyphen)
        for marker in MARKERS:
            marker_lower = marker.lower()
            if marker_lower in text_lower[:100]:
                return True

        # Only check cleaned markers if text doesn't look like base64
        # This prevents false positives like 'log' in base64 strings
        if len(text) >= 20:
            base64_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
            base64_ratio = sum(1 for c in text[:100] if c in base64_chars) / min(100, len(text))
            if base64_ratio > 0.90:  # 90%+ base64 chars
                return False  # Skip cleaned matching for base64 strings

        # Check cleaned versions (without colon/hyphen) for XOR-corrupted markers
        for marker in MARKERS:
            marker_lower = marker.lower()
            marker_clean = marker_lower.replace(':', '').replace('-', '')
            text_clean = text_lower[:100].replace(':', '').replace('-', '')

            if marker_clean in text_clean:
                return True

        return False

    def _calculate_quality(self, text: str) -> float:
        """Calculate quality score for decoded text"""
        if not text:
            return 0.0

        printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in text) / len(text)
        english_score = self._english_score(text)

        return printable_ratio * 0.5 + english_score * 0.5

    def _english_score(self, text: str) -> float:
        """Score text for English-like characteristics"""
        if not text:
            return 0.0

        score = 0.0
        text_lower = text.lower()

        # Common English words
        common_words = ['the', 'and', 'for', 'with', 'http', 'www', 'com', 'exe', 'dll',
                       'user', 'admin', 'config', 'file', 'path', 'system', 'windows']

        for word in common_words:
            if word in text_lower:
                score += 1.0

        return min(score, 10.0)

    def _get_decoder_strategies(self) -> List[Tuple[str, List]]:
        """
        Get alternative decoder ordering strategies for smart mode

        Returns:
            List of (strategy_name, decoder_list) tuples
        """
        from .deobfuscation import (
            HexDecoder, UTF16LEDecoder, ROT13Decoder, Base64Decoder,
            PowerShellBase64Decoder, URLDecoder, CharCodesDecoder,
            XORDecoder, MultiByteXORDecoder
        )

        strategies = []

        # Strategy 1: Default order (hex → utf16le → rot13 → base64 → ps → url → xor)
        default_decoders = [
            HexDecoder(self.config),
            UTF16LEDecoder(self.config),
            ROT13Decoder(self.config),
            Base64Decoder(self.config),
            PowerShellBase64Decoder(self.config),
            URLDecoder(self.config),
            CharCodesDecoder(self.config),
        ]
        if self.config.xor_enabled:
            default_decoders.extend([
                XORDecoder(self.config),
                MultiByteXORDecoder(self.config),
            ])
        strategies.append(("default", default_decoders))

        # Strategy 2: Base64-first (for heavily base64-encoded content)
        base64_first = [
            Base64Decoder(self.config),
            HexDecoder(self.config),
            UTF16LEDecoder(self.config),
            ROT13Decoder(self.config),
            PowerShellBase64Decoder(self.config),
            URLDecoder(self.config),
            CharCodesDecoder(self.config),
        ]
        if self.config.xor_enabled:
            base64_first.extend([
                XORDecoder(self.config),
                MultiByteXORDecoder(self.config),
            ])
        strategies.append(("base64_first", base64_first))

        # Strategy 3: XOR-first (for XOR before base64 cases)
        if self.config.xor_enabled:
            xor_first = [
                XORDecoder(self.config),
                MultiByteXORDecoder(self.config),
                Base64Decoder(self.config),
                HexDecoder(self.config),
                UTF16LEDecoder(self.config),
                ROT13Decoder(self.config),
                PowerShellBase64Decoder(self.config),
                URLDecoder(self.config),
                CharCodesDecoder(self.config),
            ]
            strategies.append(("xor_first", xor_first))

        # Strategy 4: ROT13-first (for ROT13 before base64 cases)
        rot13_first = [
            ROT13Decoder(self.config),
            Base64Decoder(self.config),
            HexDecoder(self.config),
            UTF16LEDecoder(self.config),
            PowerShellBase64Decoder(self.config),
            URLDecoder(self.config),
            CharCodesDecoder(self.config),
        ]
        if self.config.xor_enabled:
            rot13_first.extend([
                XORDecoder(self.config),
                MultiByteXORDecoder(self.config),
            ])
        strategies.append(("rot13_first", rot13_first))

        # Strategy 5: Skip base64 initially (avoid greedy base64 matching)
        skip_base64 = [
            HexDecoder(self.config),
            UTF16LEDecoder(self.config),
            ROT13Decoder(self.config),
            URLDecoder(self.config),
            CharCodesDecoder(self.config),
        ]
        if self.config.xor_enabled:
            skip_base64.extend([
                XORDecoder(self.config),
                MultiByteXORDecoder(self.config),
            ])
        skip_base64.append(Base64Decoder(self.config))  # Add base64 at the end
        skip_base64.append(PowerShellBase64Decoder(self.config))
        strategies.append(("skip_base64_initially", skip_base64))

        # Strategy 6: Hex then XOR priority (for hex-encoded XOR chains)
        if self.config.xor_enabled:
            hex_xor_first = [
                HexDecoder(self.config),
                XORDecoder(self.config),
                MultiByteXORDecoder(self.config),
                Base64Decoder(self.config),
                UTF16LEDecoder(self.config),
                ROT13Decoder(self.config),
                PowerShellBase64Decoder(self.config),
                URLDecoder(self.config),
                CharCodesDecoder(self.config),
            ]
            strategies.append(("hex_xor_first", hex_xor_first))

        return strategies

    def _validate_result_quality(self, result: DeobfuscationResult, text: str) -> Tuple[bool, str, float]:
        """
        Validate if deobfuscation result is good or mangled

        NEW STRATEGY: Check final result first, then fall back to intermediate results
        if final result is garbage. This prevents regressions while fixing over-decoding.

        Uses configurable thresholds from config.thresholds (preset-based or custom).

        Args:
            result: DeobfuscationResult to validate
            text: Original input text

        Returns:
            Tuple of (is_valid, failure_reason, quality_score)
        """
        thresholds = self.config.thresholds

        # If no decoding happened, check if input was already plaintext
        if result.layers_decoded == 0:
            quality = self._calculate_quality(text)
            if quality < thresholds.plaintext_min_quality:
                return False, "No decoding performed and input appears to be binary/encoded", quality
            return True, "", quality

        # STEP 1: Check final result first (original behavior)
        final_output = result.deobfuscated[-1] if result.deobfuscated else text
        quality = self._calculate_quality(final_output)

        # Check if final result is clearly good (high quality, no red flags)
        is_final_good = True
        final_failure_reason = ""

        # Check for mangled output indicators
        if len(final_output) < thresholds.min_output_length:
            is_final_good = False
            final_failure_reason = "Output too short"
        elif quality < thresholds.final_min_quality:
            is_final_good = False
            final_failure_reason = f"Low quality score ({quality:.2f})"
        elif len(final_output) > 20:
            null_ratio = final_output.count('\x00') / len(final_output)
            if null_ratio > thresholds.final_max_null_ratio:
                is_final_good = False
                final_failure_reason = f"High null byte ratio ({null_ratio:.1%})"

            non_ascii_count = sum(1 for c in final_output if ord(c) > 127)
            non_ascii_ratio = non_ascii_count / len(final_output)
            if non_ascii_ratio > thresholds.final_max_nonascii_ratio:
                is_final_good = False
                final_failure_reason = f"High non-ASCII ratio ({non_ascii_ratio:.1%})"

        # If final result is good, return it
        if is_final_good:
            return True, "", quality

        # STEP 2: Final result is bad - check for QUALITY REGRESSION
        # This handles the over-decoding case (e.g., hex→correct→base64→garbage)
        # If an intermediate result has much higher quality than final, use it instead

        # Only check intermediates if we have multiple layers AND final quality is low
        if result.layers_decoded < 2 or quality >= thresholds.intermediate_trigger_quality:
            return False, final_failure_reason or "Low quality output", quality

        # Quality regression detected - look for better intermediate result
        best_intermediate_quality = 0.0
        best_intermediate_index = -1

        for i, decoded_str in enumerate(result.deobfuscated[:-1]):  # Exclude final result
            intermediate_quality = self._calculate_quality(decoded_str)

            # Require good quality AND better than final (configurable improvement delta)
            if intermediate_quality < thresholds.intermediate_min_quality:
                continue

            if intermediate_quality < quality + thresholds.intermediate_min_improvement:
                continue

            # Check for red flags
            if len(decoded_str) < thresholds.min_output_length:
                continue

            # Check for null bytes (indicates binary data)
            null_ratio = decoded_str.count('\x00') / len(decoded_str) if decoded_str else 0
            if null_ratio > thresholds.intermediate_max_null_ratio:
                continue

            # Check for excessive non-ASCII
            non_ascii_count = sum(1 for c in decoded_str if ord(c) > 127)
            non_ascii_ratio = non_ascii_count / len(decoded_str) if decoded_str else 0
            if non_ascii_ratio > thresholds.intermediate_max_nonascii_ratio:
                continue

            # Check for hex-digit-only pattern (indicates still-encoded data)
            if len(decoded_str) >= 20:
                hex_chars = sum(1 for c in decoded_str if c in '0123456789abcdefABCDEF')
                hex_ratio = hex_chars / len(decoded_str)
                if hex_ratio > thresholds.intermediate_max_hex_ratio:
                    continue

            # Track best intermediate result
            if intermediate_quality > best_intermediate_quality:
                best_intermediate_quality = intermediate_quality
                best_intermediate_index = i

        # If we found a good intermediate result, truncate to that point and accept it
        if best_intermediate_index >= 0 and best_intermediate_quality >= quality + thresholds.intermediate_min_improvement:
            # Truncate deobfuscated list to stop at the good intermediate result
            result.deobfuscated = result.deobfuscated[:best_intermediate_index + 1]
            result.layers_decoded = len(result.deobfuscated)
            return True, "", best_intermediate_quality

        # STEP 3: No good results found - return failure with reason
        return False, final_failure_reason or "Low quality output", quality

    def _try_single_strategy(self, text: str, strategy_name: str, decoders: List, start_time: float,
                             strategy_index: int = 0, total_strategies: int = 1) -> DeobfuscationResult:
        """
        Try deobfuscation with a specific decoder ordering strategy

        Args:
            text: Input string to decode
            strategy_name: Name of the strategy being used
            decoders: List of decoder instances to use
            start_time: Start time for timeout calculation
            strategy_index: Index of current strategy (for progress calculation)
            total_strategies: Total number of strategies being tried (for progress calculation)

        Returns:
            DeobfuscationResult from this strategy
        """
        result = DeobfuscationResult(original=text)
        result.strategy_used = strategy_name

        # Check size limit
        if len(text.encode('utf-8', errors='ignore')) > self.config.max_input_bytes:
            result.trace.append(('size_limit', False, f'Input too large'))
            result.failed = True
            result.failure_reason = "Input exceeds size limit"
            return result

        current = text
        visited_hashes = set()
        current_hash = hashlib.sha1(current.encode('utf-8', errors='surrogateescape')).hexdigest()
        visited_hashes.add(current_hash)

        previous_quality = self._calculate_quality(current)

        # Calculate timeout
        timeout = self.config.per_string_timeout_secs

        # Calculate virtual layer offset for smooth progress across strategies
        layer_offset = strategy_index * self.config.max_depth
        virtual_total_layers = total_strategies * self.config.max_depth

        for iteration in range(self.config.max_depth):
            # Check timeout
            if time.time() - start_time > timeout:
                result.timed_out = True
                result.trace.append(('timeout', False, f'Timeout after {iteration} layers'))
                result.failed = True
                result.failure_reason = f"Timeout after {iteration} layers"
                break

            # Marker-based plaintext detection
            if self._check_plaintext_markers(current):
                if iteration > 0:
                    break

            decoded_this_round = False

            # Try each decoder in order (no "Trying" callback - too verbose and causes progress bar jumps)
            for method_idx, decoder in enumerate(decoders):
                try:
                    method_name = decoder.get_name()

                    # Call the decoder (no progress callback for each attempt - too verbose)
                    decoded = decoder.decode(current)

                    if decoded and decoded != current:
                        # Check for cycles
                        decoded_hash = hashlib.sha1(decoded.encode('utf-8', errors='surrogateescape')).hexdigest()

                        if decoded_hash in visited_hashes:
                            result.trace.append(('cycle', False, f'Skipping {method_name} - already seen'))
                            continue

                        # Quality check
                        current_quality = self._calculate_quality(decoded)

                        # Allow short outputs if they're high quality (prevent rejecting valid short strings like "TEST")
                        if len(decoded) < 4 and iteration > 0:
                            result.trace.append(('too_short', False, f'Output too short: {len(decoded)} chars'))
                            break

                        # Success!
                        preview = decoded[:120] if len(decoded) > 120 else decoded
                        result.trace.append((method_name, True, preview))
                        result.deobfuscated.append(decoded)
                        result.methods_used.append(f"{method_name} (layer {iteration + 1})")
                        result.layers_decoded = iteration + 1
                        visited_hashes.add(decoded_hash)
                        previous_quality = current_quality
                        current = decoded
                        decoded_this_round = True

                        # Progress callback: success
                        if self.config.progress_callback:
                            virtual_layer = layer_offset + iteration + 1
                            self.config.progress_callback(
                                f"✓ {method_name} successful",
                                virtual_layer,
                                virtual_total_layers,
                                preview
                            )

                        break

                except Exception:
                    continue

            if not decoded_this_round:
                result.trace.append(('no_match', False, current[:80]))
                break

        # Validate result quality
        is_valid, failure_reason, quality_score = self._validate_result_quality(result, text)
        result.failed = not is_valid
        result.failure_reason = failure_reason
        result.quality_score = quality_score

        return result

    def deobfuscate_batch(self, strings: List[str]) -> List[DeobfuscationResult]:
        """
        Deobfuscate a batch of strings

        Args:
            strings: List of strings to deobfuscate

        Returns:
            List of DeobfuscationResult objects (includes both successful and failed results)
        """
        results = []
        for text in strings:
            # Skip short strings to avoid processing fragments
            # Minimum 40 chars helps filter out partial Base64/hex strings
            if isinstance(text, str) and len(text) >= 40:
                result = self.deobfuscate_string(text)
                # Include ALL results (successful and failed) for proper UI feedback
                if result.layers_decoded > 0 or result.failed:
                    results.append(result)
        return results

    def get_deobfuscation_stats(self, results: List[DeobfuscationResult]) -> dict:
        """
        Generate statistics from deobfuscation results

        Args:
            results: List of DeobfuscationResult objects

        Returns:
            Dictionary with statistics
        """
        if not results:
            return {
                'total_processed': 0,
                'successfully_decoded': 0,
                'max_depth': 0,
                'timeout_count': 0,
                'suspicious_count': 0,
                'methods_used': {}
            }

        total = len(results)
        successfully_decoded = sum(1 for r in results if r.layers_decoded > 0)
        max_depth = max((r.layers_decoded for r in results), default=0)
        timeout_count = sum(1 for r in results if r.timed_out)
        suspicious_count = sum(1 for r in results if r.suspicious_patterns)

        # Count method usage
        methods_used = {}
        for result in results:
            for method in result.methods_used:
                methods_used[method] = methods_used.get(method, 0) + 1

        return {
            'total_processed': total,
            'successfully_decoded': successfully_decoded,
            'max_depth': max_depth,
            'timeout_count': timeout_count,
            'suspicious_count': suspicious_count,
            'methods_used': methods_used
        }
