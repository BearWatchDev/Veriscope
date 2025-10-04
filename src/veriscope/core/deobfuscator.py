"""
Deobfuscation Module
Automatically decodes/deobfuscates common encoding schemes found in malware

Handles:
- Base64 encoding (single and multi-layer)
- Hex encoding
- URL encoding
- PowerShell encoding (UTF-16 LE Base64)
- JavaScript/HTML character codes
- ROT13/Caesar cipher
- String concatenation obfuscation
- Character substitution patterns
"""

import base64
import re
import urllib.parse
from typing import List, Tuple, Set
from dataclasses import dataclass, field


@dataclass
class DeobfuscationResult:
    """Container for deobfuscation results"""
    original: str
    deobfuscated: List[str] = field(default_factory=list)
    layers_decoded: int = 0
    methods_used: List[str] = field(default_factory=list)
    suspicious_patterns: List[str] = field(default_factory=list)

    def get_all_strings(self) -> List[str]:
        """Get both original and deobfuscated strings"""
        return [self.original] + self.deobfuscated


class Deobfuscator:
    """
    Multi-method deobfuscator for common malware encoding techniques

    Attempts multiple decoding strategies and tracks success/failure.
    Iterates multiple layers (Base64 of Base64, etc.)
    """

    def __init__(self, max_iterations: int = 5):
        """
        Initialize deobfuscator

        Args:
            max_iterations: Maximum deobfuscation depth (prevents infinite loops)
        """
        self.max_iterations = max_iterations

        # Regex patterns for encoded data detection
        self.base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        self.hex_pattern = re.compile(r'(?:0x)?([A-Fa-f0-9]{2})+')
        self.url_encoded_pattern = re.compile(r'(?:%[0-9A-Fa-f]{2}){3,}')

        # PowerShell specific patterns
        self.ps_encoded_pattern = re.compile(
            r'(?:-enc|-encodedcommand|-e)\s+([A-Za-z0-9+/=]+)',
            re.IGNORECASE
        )

        # JavaScript/VBScript character code patterns
        self.char_code_pattern = re.compile(
            r'(?:String\.fromCharCode|Chr|chr)\s*\(\s*(\d+(?:\s*,\s*\d+)*)\s*\)',
            re.IGNORECASE
        )

        # Suspicious PowerShell obfuscation markers
        self.ps_obfuscation_markers = [
            re.compile(r'\$\w+\s*=\s*\$\w+\.replace', re.IGNORECASE),  # String replace
            re.compile(r'\[char\]\d+', re.IGNORECASE),  # Char casting
            re.compile(r'-join', re.IGNORECASE),  # Join operator
            re.compile(r'\.split\(', re.IGNORECASE),  # Split operations
        ]

    def deobfuscate_string(self, text: str) -> DeobfuscationResult:
        """
        Attempt to deobfuscate a single string using multiple methods

        Args:
            text: Input string (potentially obfuscated)

        Returns:
            DeobfuscationResult with original and deobfuscated versions
        """
        result = DeobfuscationResult(original=text)
        current = text
        seen = {text}  # Track decoded strings to prevent loops

        for iteration in range(self.max_iterations):
            decoded_this_round = False

            # Try each deobfuscation method
            methods = [
                ('base64', self._try_base64),
                ('powershell_base64', self._try_powershell_base64),
                ('hex', self._try_hex),
                ('url_encoding', self._try_url_decode),
                ('char_codes', self._try_char_codes),
                ('rot13', self._try_rot13),
            ]

            for method_name, method_func in methods:
                try:
                    decoded = method_func(current)

                    # Check if decoding was successful and produced new content
                    if decoded and decoded != current and decoded not in seen:
                        result.deobfuscated.append(decoded)
                        result.methods_used.append(f"{method_name} (layer {iteration + 1})")
                        result.layers_decoded = iteration + 1
                        seen.add(decoded)
                        current = decoded
                        decoded_this_round = True
                        break  # Move to next iteration with new decoded string

                except Exception:
                    continue

            # If no method succeeded this round, we're done
            if not decoded_this_round:
                break

        # Detect suspicious patterns in results
        self._detect_suspicious_patterns(result)

        return result

    def deobfuscate_batch(self, strings: List[str]) -> List[DeobfuscationResult]:
        """
        Deobfuscate multiple strings

        Args:
            strings: List of potentially obfuscated strings

        Returns:
            List of DeobfuscationResults
        """
        results = []
        for string in strings:
            # Only attempt deobfuscation on strings that look encoded
            if self._looks_encoded(string):
                result = self.deobfuscate_string(string)
                if result.layers_decoded > 0:
                    results.append(result)

        return results

    def extract_and_deobfuscate(self, text: str) -> Tuple[List[str], List[DeobfuscationResult]]:
        """
        Extract encoded patterns and deobfuscate them

        Args:
            text: Full text to search for encoded patterns

        Returns:
            Tuple of (all_strings, deobfuscation_results)
        """
        all_strings = []
        deobfuscation_results = []

        # Extract Base64 patterns
        base64_matches = self.base64_pattern.findall(text)
        for match in base64_matches:
            if len(match) >= 20:  # Minimum length
                result = self.deobfuscate_string(match)
                if result.layers_decoded > 0:
                    deobfuscation_results.append(result)
                    all_strings.extend(result.get_all_strings())

        # Extract PowerShell encoded commands
        ps_matches = self.ps_encoded_pattern.findall(text)
        for match in ps_matches:
            result = self.deobfuscate_string(match)
            if result.layers_decoded > 0:
                deobfuscation_results.append(result)
                all_strings.extend(result.get_all_strings())

        # Extract hex patterns
        hex_matches = self.hex_pattern.findall(text)
        for match in hex_matches:
            if len(match) >= 20:
                result = self.deobfuscate_string(match)
                if result.layers_decoded > 0:
                    deobfuscation_results.append(result)
                    all_strings.extend(result.get_all_strings())

        return all_strings, deobfuscation_results

    def _try_base64(self, text: str) -> str:
        """Try Base64 decoding"""
        try:
            # Clean whitespace
            cleaned = re.sub(r'\s', '', text)

            # Try standard Base64
            decoded_bytes = base64.b64decode(cleaned)

            # Try to decode as UTF-8
            decoded = decoded_bytes.decode('utf-8', errors='ignore')

            # Validate: decoded should be printable and different from input
            if decoded and len(decoded) > 0:
                # Check if mostly printable
                printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in decoded) / len(decoded)
                if printable_ratio > 0.7:  # At least 70% printable
                    return decoded

        except Exception:
            pass

        return ""

    def _try_powershell_base64(self, text: str) -> str:
        """Try PowerShell-style Base64 (UTF-16 LE encoded)"""
        try:
            # Clean whitespace
            cleaned = re.sub(r'\s', '', text)

            # Decode Base64
            decoded_bytes = base64.b64decode(cleaned)

            # Try UTF-16 LE (PowerShell encoding)
            decoded = decoded_bytes.decode('utf-16-le', errors='ignore')

            if decoded and len(decoded) > 0:
                printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in decoded) / len(decoded)
                if printable_ratio > 0.7:
                    return decoded

        except Exception:
            pass

        return ""

    def _try_hex(self, text: str) -> str:
        """Try hexadecimal decoding"""
        try:
            # Remove 0x prefix and spaces
            cleaned = text.replace('0x', '').replace('\\x', '').replace(' ', '')

            # Ensure even length
            if len(cleaned) % 2 != 0:
                return ""

            # Decode hex
            decoded_bytes = bytes.fromhex(cleaned)

            # Try UTF-8
            decoded = decoded_bytes.decode('utf-8', errors='ignore')

            if decoded and len(decoded) > 3:
                printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in decoded) / len(decoded)
                if printable_ratio > 0.6:
                    return decoded

        except Exception:
            pass

        return ""

    def _try_url_decode(self, text: str) -> str:
        """Try URL percent-encoding decoding"""
        try:
            decoded = urllib.parse.unquote(text)

            # Only return if it actually changed
            if decoded != text and len(decoded) > 0:
                return decoded

        except Exception:
            pass

        return ""

    def _try_char_codes(self, text: str) -> str:
        """Try JavaScript/VBScript character code decoding"""
        try:
            matches = self.char_code_pattern.findall(text)

            for match in matches:
                # Parse comma-separated character codes
                codes = [int(c.strip()) for c in match.split(',')]

                # Convert to characters
                decoded = ''.join(chr(code) for code in codes if 0 <= code <= 1114111)

                if decoded and len(decoded) > 0:
                    return decoded

        except Exception:
            pass

        return ""

    def _try_rot13(self, text: str) -> str:
        """Try ROT13 decoding (simple Caesar cipher)"""
        try:
            import codecs
            decoded = codecs.decode(text, 'rot13')

            # Only return if it contains common English words (basic heuristic)
            common_words = ['http', 'www', 'exe', 'dll', 'cmd', 'powershell', 'script']
            if any(word in decoded.lower() for word in common_words):
                return decoded

        except Exception:
            pass

        return ""

    def _looks_encoded(self, text: str) -> bool:
        """
        Heuristic to determine if string looks encoded

        Args:
            text: String to check

        Returns:
            True if string appears to be encoded
        """
        # Too short to be interesting
        if len(text) < 20:
            return False

        # Check for Base64 pattern
        if self.base64_pattern.search(text):
            return True

        # Check for hex pattern
        if self.hex_pattern.search(text) and len(text) > 30:
            return True

        # Check for URL encoding
        if self.url_encoded_pattern.search(text):
            return True

        # Check entropy (high entropy suggests encoding/encryption)
        # Calculate Shannon entropy
        from collections import Counter
        import math
        if text:
            counter = Counter(text)
            length = len(text)
            entropy = 0.0
            for count in counter.values():
                probability = count / length
                if probability > 0:
                    entropy -= probability * math.log2(probability)

            # High entropy (> 4.5) suggests encoding
            if entropy > 4.5:
                return True

        return False

    def _detect_suspicious_patterns(self, result: DeobfuscationResult):
        """
        Detect suspicious patterns in deobfuscated content

        Args:
            result: DeobfuscationResult to analyze
        """
        all_text = ' '.join(result.get_all_strings())

        # PowerShell obfuscation patterns
        for pattern in self.ps_obfuscation_markers:
            if pattern.search(all_text):
                result.suspicious_patterns.append("PowerShell obfuscation detected")
                break

        # Suspicious commands
        dangerous_commands = [
            'Invoke-Expression', 'IEX', 'DownloadString', 'DownloadFile',
            'WebClient', 'Start-Process', 'cmd /c', 'wscript', 'cscript',
            'regsvr32', 'rundll32', 'certutil', 'bitsadmin'
        ]

        for cmd in dangerous_commands:
            if cmd.lower() in all_text.lower():
                result.suspicious_patterns.append(f"Suspicious command: {cmd}")

        # Network indicators in decoded content
        if re.search(r'https?://', all_text, re.IGNORECASE):
            result.suspicious_patterns.append("URLs found in decoded content")

        if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', all_text):
            result.suspicious_patterns.append("IP addresses found in decoded content")

    def get_deobfuscation_stats(self, results: List[DeobfuscationResult]) -> dict:
        """
        Get statistics about deobfuscation results

        Args:
            results: List of DeobfuscationResults

        Returns:
            Dictionary with statistics
        """
        if not results:
            return {
                'total_strings': 0,
                'successfully_decoded': 0,
                'total_layers': 0,
                'max_depth': 0,
                'methods_used': [],
                'suspicious_count': 0
            }

        methods_used = set()
        total_layers = 0
        max_depth = 0
        suspicious_count = 0

        for result in results:
            total_layers += result.layers_decoded
            max_depth = max(max_depth, result.layers_decoded)
            methods_used.update(result.methods_used)
            if result.suspicious_patterns:
                suspicious_count += 1

        return {
            'total_strings': len(results),
            'successfully_decoded': sum(1 for r in results if r.layers_decoded > 0),
            'total_layers': total_layers,
            'max_depth': max_depth,
            'methods_used': sorted(list(methods_used)),
            'suspicious_count': suspicious_count
        }
