"""
Base64 and Hexadecimal Decoders
Most common encoding methods in malware
"""

import base64
import re
from .base import BaseDecoder
from .compression import get_compression_decoders


class Base64Decoder(BaseDecoder):
    """Base64 decoding with noise filtering and compression detection"""

    # Class-level constant for efficient hex checking
    HEX_CHARS = frozenset('0123456789abcdefABCDEF')

    def __init__(self, config=None):
        super().__init__(config)
        self.compression_decoders = get_compression_decoders()

    def get_name(self) -> str:
        return "base64"

    def decode(self, text: str) -> str:
        """
        Decode Base64-encoded string

        Features:
        - Whitespace removal
        - Noise character filtering
        - Misplaced padding correction
        - Hex string avoidance
        - Compression detection (GZIP/zlib/bzip2)

        Args:
            text: Input string (potentially base64-encoded)

        Returns:
            Decoded string, or empty string if not base64
        """
        try:
            # Skip if looks like JSON or JS that needs extraction first
            if text.strip().startswith('{') or 'atob(' in text or 'btoa(' in text:
                return ""

            # Remove all whitespace
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

            # Skip if looks like hex (check sample for efficiency)
            if len(cleaned) >= 20 and len(cleaned) % 2 == 0:
                # Check a sample of the string for hex characteristics
                sample_size = min(60, len(cleaned))
                if all(c in self.HEX_CHARS for c in cleaned[:sample_size]):
                    return ""

            # Decode
            decoded_bytes = base64.b64decode(cleaned)

            # Check for compression after Base64
            for decoder in self.compression_decoders:
                compressed_result = decoder.decode(decoded_bytes.decode('latin-1', errors='ignore'))
                if compressed_result:
                    return compressed_result

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


class HexDecoder(BaseDecoder):
    """Hexadecimal decoding with compression detection"""

    def __init__(self, config=None):
        super().__init__(config)
        self.compression_decoders = get_compression_decoders()

    def get_name(self) -> str:
        return "hex"

    def decode(self, text: str) -> str:
        """
        Decode hexadecimal-encoded string

        Features:
        - Prefix removal (0x, \\x)
        - Noise removal (ALL non-hex chars) - handles obfuscation with mixed separators
        - Odd-length handling (prepend 0)
        - Compression detection (GZIP/zlib)

        Args:
            text: Input string (potentially hex-encoded)

        Returns:
            Decoded string, or empty string if not hex
        """
        try:
            # Remove ALL non-hex characters (v1.4.2 - more lenient for obfuscated hex)
            # Handles tabs, dashes, equals, newlines, and other separator noise
            import re
            cleaned = re.sub(r'[^0-9a-fA-F]', '', text)

            # Validation - require at least 10 hex chars after cleaning
            if len(cleaned) < 10:
                return ""

            # Check hex ratio - at least 80% of original must be hex (prevents false positives)
            hex_ratio = len(cleaned) / len(text) if len(text) > 0 else 0
            if hex_ratio < 0.60:  # At least 60% hex chars in original
                return ""

            # Handle odd-length hex strings by prepending '0'
            if len(cleaned) % 2 != 0:
                cleaned = '0' + cleaned

            # Decode
            decoded_bytes = bytes.fromhex(cleaned)

            # Check for compression
            for decoder in self.compression_decoders:
                compressed_result = decoder.decode(decoded_bytes.decode('latin-1', errors='ignore'))
                if compressed_result:
                    return compressed_result

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


class Base64URLDecoder(BaseDecoder):
    """Base64URL decoding (URL-safe alphabet, padding optional)"""

    def get_name(self) -> str:
        return "base64url"

    def can_decode(self, text: str) -> bool:
        # Check for URL-safe base64 characters (- and _ instead of + and /)
        # Must have at least one - or _ to distinguish from standard base64
        if len(text) < 4:
            return False
        return ('-' in text or '_' in text) and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=' for c in text.strip())

    def decode(self, text: str) -> str:
        """
        Decode Base64URL-encoded string (RFC 4648)

        Features:
        - URL-safe alphabet (- instead of +, _ instead of /)
        - Padding optional
        - Whitespace removal

        Args:
            text: Input string (potentially base64url-encoded)

        Returns:
            Decoded string, or empty string if not base64url
        """
        try:
            # Remove all whitespace
            cleaned = re.sub(r'\s', '', text)

            # Add padding if missing
            padding_needed = (4 - len(cleaned) % 4) % 4
            cleaned += '=' * padding_needed

            # Decode using urlsafe base64
            decoded_bytes = base64.urlsafe_b64decode(cleaned)

            # Try UTF-8 first
            try:
                decoded = decoded_bytes.decode('utf-8')
                if len(decoded) > 0:
                    printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in decoded) / len(decoded)
                    if printable_ratio > 0.7:
                        return decoded
            except UnicodeDecodeError:
                pass

            # Fallback to latin-1
            decoded = decoded_bytes.decode('latin-1')
            if len(decoded) > 0:
                return decoded

        except Exception:
            pass

        return ""


class PowerShellBase64Decoder(BaseDecoder):
    """PowerShell Base64 (UTF-16LE encoded)"""

    def get_name(self) -> str:
        return "powershell_base64"

    def decode(self, text: str) -> str:
        """
        Decode PowerShell Base64 (UTF-16LE)

        PowerShell encodes strings as UTF-16LE before Base64 encoding

        Args:
            text: Input string (potentially PowerShell base64)

        Returns:
            Decoded UTF-16LE string, or empty string if not PowerShell base64
        """
        try:
            # Skip if looks like JSON or JS that needs extraction first
            if text.strip().startswith('{') or 'atob(' in text or 'btoa(' in text:
                return ""

            # Remove whitespace
            cleaned = re.sub(r'\s', '', text)

            # Base64 decode
            decoded_bytes = base64.b64decode(cleaned)

            # UTF-16LE decode
            decoded = decoded_bytes.decode('utf-16-le', errors='ignore')

            if decoded and len(decoded) > 0:
                printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in decoded) / len(decoded)
                if printable_ratio > 0.7:
                    return decoded

        except Exception:
            pass

        return ""
