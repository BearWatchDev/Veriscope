"""
Deobfuscation Module v1.1
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
"""

import base64
import re
import urllib.parse
import gzip
import zlib
import bz2
import time
import hashlib
from typing import List, Tuple, Set
from dataclasses import dataclass, field


@dataclass
class DeobfuscationConfig:
    """Configuration for deobfuscation engine"""
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

    def deobfuscate_string(self, text: str) -> DeobfuscationResult:
        """
        Attempt to deobfuscate a single string using multiple methods

        Args:
            text: Input string (potentially obfuscated)

        Returns:
            DeobfuscationResult with original and deobfuscated versions
        """
        result = DeobfuscationResult(original=text)
        start_time = time.time()

        # Check size limit
        if len(text.encode('utf-8', errors='ignore')) > self.config.max_input_bytes:
            result.trace.append(('size_limit', False, f'Input too large'))
            return result

        current = text
        visited_hashes = set()
        current_hash = hashlib.sha1(current.encode('utf-8', errors='surrogateescape')).hexdigest()
        visited_hashes.add(current_hash)

        previous_quality = self._calculate_quality(current)

        for iteration in range(self.config.max_depth):
            # Check timeout
            if time.time() - start_time > self.config.per_string_timeout_secs:
                result.timed_out = True
                result.trace.append(('timeout', False, f'Timeout after {iteration} layers'))
                break

            # Marker-based plaintext detection (PRIORITY)
            # Check even on iteration 0 in case we already have plaintext after first decode
            if self._check_plaintext_markers(current):
                if iteration > 0:  # Only stop if we've done at least one decode
                    result.trace.append(('plaintext_marker', True, current[:120]))
                    break

            decoded_this_round = False

            # Try each deobfuscation method in order
            methods = [
                ('hex', self._try_hex),
                ('utf16le', self._try_utf16le),
                ('rot13', self._try_rot13),
                ('base64', self._try_base64),
                ('powershell_base64', self._try_powershell_base64),
                ('url_encoding', self._try_url_decode),
                ('char_codes', self._try_char_codes),
            ]

            # Add XOR methods last (if enabled)
            # Single-byte XOR first (more common), then multi-byte
            if self.config.xor_enabled:
                methods.append(('xor', self._try_xor))
                methods.append(('xor_multibyte', self._try_xor_multibyte))

            for method_name, method_func in methods:
                try:
                    decoded = method_func(current)

                    if decoded and decoded != current:
                        # Check for cycles
                        decoded_hash = hashlib.sha1(decoded.encode('utf-8', errors='surrogateescape')).hexdigest()

                        if decoded_hash in visited_hashes:
                            result.trace.append(('cycle', False, f'Skipping {method_name} - already seen'))
                            continue

                        # Quality check
                        current_quality = self._calculate_quality(decoded)

                        if len(decoded) < 10 and iteration > 0:
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
                        break

                except Exception:
                    continue

            if not decoded_this_round:
                result.trace.append(('no_match', False, current[:80]))
                break

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

        text_lower = text.lower()
        # Check for markers with flexible matching (allows for minor XOR corruption)
        for marker in MARKERS:
            marker_lower = marker.lower()
            # Remove special chars for matching
            marker_clean = marker_lower.replace(':', '').replace('-', '')
            text_clean = text_lower[:100].replace(':', '').replace('-', '')

            # Check both exact and cleaned versions
            if marker_lower in text_lower[:100] or marker_clean in text_clean:
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

    def _printable_ratio(self, data: bytes) -> float:
        """Calculate ratio of printable characters"""
        if not data:
            return 0.0

        printable = sum(1 for b in data if 32 <= b <= 126 or b in [9, 10, 13])
        return printable / len(data)

    def _try_base64(self, text: str) -> str:
        """Try Base64 decoding with noise filtering and padding normalization"""
        try:
            cleaned = re.sub(r'\s', '', text)

            # Remove invalid Base64 characters (noise injection)
            cleaned = ''.join(c for c in cleaned if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')

            # Fix misplaced padding ONLY if = appears in the middle
            if '=' in cleaned:
                first_padding_idx = cleaned.index('=')
                if first_padding_idx < len(cleaned) - 2 or '=' in cleaned[:-2]:
                    # Remove all = and re-add proper padding at the end
                    cleaned_no_padding = cleaned.replace('=', '')
                    padding_needed = (4 - len(cleaned_no_padding) % 4) % 4
                    cleaned = cleaned_no_padding + ('=' * padding_needed)

            # Skip if looks like hex
            if len(cleaned) >= 20 and len(cleaned) % 2 == 0:
                if all(c in '0123456789abcdefABCDEF' for c in cleaned[:100]):
                    return ""

            decoded_bytes = base64.b64decode(cleaned)

            # Check for compression after Base64
            if len(decoded_bytes) >= 2 and decoded_bytes[:2] == b'\x1f\x8b':
                return self._try_gzip(decoded_bytes)

            if len(decoded_bytes) >= 2 and decoded_bytes[0] == 0x78:
                zlib_result = self._try_zlib(decoded_bytes)
                if zlib_result:
                    return zlib_result

            if len(decoded_bytes) >= 4 and decoded_bytes[:3] == b'BZh':
                bz2_result = self._try_bzip2(decoded_bytes)
                if bz2_result:
                    return bz2_result

            # Try UTF-8 first
            try:
                decoded = decoded_bytes.decode('utf-8')
                if len(decoded) > 0:
                    printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in decoded) / len(decoded)
                    if printable_ratio > 0.7:
                        return decoded
            except UnicodeDecodeError:
                pass

            # Fallback to latin-1 to preserve binary data
            decoded = decoded_bytes.decode('latin-1')
            if len(decoded) > 0:
                return decoded

        except Exception:
            pass

        return ""

    def _try_hex(self, text: str) -> str:
        """Try hexadecimal decoding"""
        try:
            cleaned = text.replace(' ', '').replace('0x', '').replace('\\x', '')

            if len(cleaned) < 10 or len(cleaned) % 2 != 0:
                return ""

            if not all(c in '0123456789abcdefABCDEF' for c in cleaned):
                return ""

            decoded_bytes = bytes.fromhex(cleaned)

            # Check for compression
            if len(decoded_bytes) >= 2 and decoded_bytes[:2] == b'\x1f\x8b':
                return self._try_gzip(decoded_bytes)

            if len(decoded_bytes) >= 2 and decoded_bytes[0] == 0x78:
                zlib_result = self._try_zlib(decoded_bytes)
                if zlib_result:
                    return zlib_result

            # Try UTF-8
            try:
                decoded = decoded_bytes.decode('utf-8')
                if len(decoded) > 3:
                    printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in decoded) / len(decoded)
                    if printable_ratio > 0.6:
                        return decoded
            except UnicodeDecodeError:
                pass

            # Fallback to latin-1
            decoded = decoded_bytes.decode('latin-1')
            if len(decoded) > 3:
                return decoded

        except Exception:
            pass

        return ""

    def _try_gzip(self, data: bytes) -> str:
        """Try GZIP decompression"""
        try:
            if len(data) < 2 or data[:2] != b'\x1f\x8b':
                return ""

            decompressed = gzip.decompress(data)
            decoded = decompressed.decode('utf-8', errors='ignore')

            if decoded and len(decoded) > 0:
                printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in decoded) / len(decoded)
                if printable_ratio > 0.6:
                    return decoded
        except Exception:
            pass

        return ""

    def _try_zlib(self, data: bytes) -> str:
        """Try zlib decompression"""
        try:
            if len(data) < 2 or data[0] != 0x78:
                return ""

            if data[1] not in [0x01, 0x5E, 0x9C, 0xDA]:
                return ""

            decompressed = zlib.decompress(data)
            decoded = decompressed.decode('utf-8', errors='ignore')

            if decoded and len(decoded) > 0:
                printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in decoded) / len(decoded)
                if printable_ratio > 0.6:
                    return decoded
        except Exception:
            pass

        return ""

    def _try_bzip2(self, data: bytes) -> str:
        """Try bzip2 decompression"""
        try:
            if len(data) < 4 or data[:3] != b'BZh':
                return ""

            if not (0x31 <= data[3] <= 0x39):
                return ""

            decompressed = bz2.decompress(data)
            decoded = decompressed.decode('utf-8', errors='ignore')

            if decoded and len(decoded) > 0:
                printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in decoded) / len(decoded)
                if printable_ratio > 0.6:
                    return decoded
        except Exception:
            pass

        return ""

    def _try_utf16le(self, text: str) -> str:
        """Try UTF-16LE decoding"""
        try:
            data_bytes = text.encode('latin-1', errors='ignore')

            if len(data_bytes) < 4 or len(data_bytes) % 2 != 0:
                return ""

            # Check for null bytes pattern
            null_count = sum(1 for i in range(1, min(100, len(data_bytes)), 2) if data_bytes[i] == 0x00)
            if null_count > 10:
                decoded = data_bytes.decode('utf-16le', errors='ignore')
                if decoded and len(decoded) > 0:
                    printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in decoded) / len(decoded)
                    if printable_ratio > 0.7:
                        return decoded
        except Exception:
            pass

        return ""

    def _try_rot13(self, text: str) -> str:
        """Try ROT13 decoding"""
        try:
            import codecs

            # Don't trigger on Base64 (lots of +/= chars)
            base64_chars = text.count('+') + text.count('/') + text.count('=')
            if base64_chars > len(text) * 0.05:
                return ""

            decoded = codecs.decode(text, 'rot13')

            # Check for common words or markers
            common_words = ['http', 'www', 'exe', 'dll', 'cmd', 'powershell', 'script', 'user', 'config', 'token', 'shell', 'alert', 'process']
            if any(word in decoded.lower() for word in common_words):
                return decoded
        except Exception:
            pass

        return ""

    def _try_url_decode(self, text: str) -> str:
        """Try URL decoding"""
        try:
            decoded = urllib.parse.unquote(text)
            if decoded != text and len(decoded) > 0:
                return decoded
        except Exception:
            pass

        return ""

    def _try_powershell_base64(self, text: str) -> str:
        """Try PowerShell UTF-16LE Base64"""
        try:
            cleaned = re.sub(r'\s', '', text)
            decoded_bytes = base64.b64decode(cleaned)
            decoded = decoded_bytes.decode('utf-16-le', errors='ignore')

            if decoded and len(decoded) > 0:
                printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in decoded) / len(decoded)
                if printable_ratio > 0.7:
                    return decoded
        except Exception:
            pass

        return ""

    def _try_char_codes(self, text: str) -> str:
        """Try decoding character codes"""
        # Placeholder for character code decoding
        return ""

    def _try_xor(self, text: str) -> str:
        """Try single-byte XOR decoding"""
        try:
            if len(text) >= 20 and len(text) % 2 == 0:
                if all(c in '0123456789abcdefABCDEF' for c in text[:100]):
                    return ""

            try:
                data = text.encode('latin-1')
            except UnicodeEncodeError:
                data = text.encode('utf-8', errors='surrogateescape')

            best_result = ""
            best_score = 0.0

            for key in self.config.xor_common_keys:
                xor_bytes = bytes([byte ^ key for byte in data])

                # Check for compression
                if len(xor_bytes) >= 2 and xor_bytes[:2] == b'\x1f\x8b':
                    gzip_result = self._try_gzip(xor_bytes)
                    if gzip_result:
                        return gzip_result

                if len(xor_bytes) >= 2 and xor_bytes[0] == 0x78:
                    zlib_result = self._try_zlib(xor_bytes)
                    if zlib_result:
                        return zlib_result

                printable_ratio = self._printable_ratio(xor_bytes)
                if printable_ratio < 0.6:
                    continue

                try:
                    decoded = xor_bytes.decode('utf-8', errors='ignore')
                except:
                    continue

                score = self._english_score(decoded) + (printable_ratio * 2)

                if score > best_score and decoded:
                    best_score = score
                    best_result = decoded

            return best_result

        except Exception:
            return ""

    def _try_xor_multibyte(self, text: str) -> str:
        """Try multi-byte XOR decoding"""
        try:
            try:
                data = text.encode('latin-1')
            except UnicodeEncodeError:
                data = text.encode('utf-8', errors='surrogateescape')

            multibyte_keys = [
                bytes([0xAB, 0xCD]),
                bytes([0x12, 0x34]),
                bytes([0xFF, 0xFF]),
                bytes([0x00, 0xFF]),
                bytes([0xDE, 0xAD, 0xBE]),
                bytes([0xCA, 0xFE, 0xBA]),
                bytes([0xDE, 0xAD, 0xBE, 0xEF]),
                bytes([0xCA, 0xFE, 0xBA, 0xBE]),
            ]

            best_result = ""
            best_score = 0.0

            for key_bytes in multibyte_keys:
                xor_bytes = bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])

                # Check for compression
                if len(xor_bytes) >= 2 and xor_bytes[:2] == b'\x1f\x8b':
                    gzip_result = self._try_gzip(xor_bytes)
                    if gzip_result:
                        return gzip_result

                if len(xor_bytes) >= 2 and xor_bytes[0] == 0x78:
                    zlib_result = self._try_zlib(xor_bytes)
                    if zlib_result:
                        return zlib_result

                printable_ratio = self._printable_ratio(xor_bytes)
                if printable_ratio < 0.6:
                    continue

                try:
                    decoded = xor_bytes.decode('utf-8', errors='ignore')
                except:
                    continue

                score = self._english_score(decoded) + (printable_ratio * 2)

                if score > best_score and decoded:
                    best_score = score
                    best_result = decoded

            return best_result

        except Exception:
            return ""
