"""
XOR Decoders and Encoding Methods
Single-byte, multi-byte XOR, and UTF-16LE decoding
"""

from typing import List
from .base import BaseDecoder
from .compression import get_compression_decoders


class XORDecoder(BaseDecoder):
    """Single-byte XOR cipher decoding"""

    def __init__(self, config=None):
        super().__init__(config)
        self.common_keys = config.xor_common_keys if config else [
            0x5A, 0x20, 0xFF, 0xAA, 0x01, 0x42, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xAB, 0xCD, 0xEF
        ]
        self.compression_decoders = get_compression_decoders()

    def get_name(self) -> str:
        return "xor"

    def decode(self, text: str) -> str:
        """
        Decode single-byte XOR-encrypted string

        Features:
        - Tries common XOR keys
        - Hex string avoidance
        - Base64 string avoidance
        - Compression detection (GZIP/zlib)
        - English scoring for best result

        Common Keys: 0x5A, 0x20, 0xFF, 0xAA, etc.

        Args:
            text: Input string (potentially XOR-encrypted)

        Returns:
            Best-scoring XOR-decoded string, or empty if no good results
        """
        try:
            # Skip if looks like hex
            if len(text) >= 20 and len(text) % 2 == 0:
                if all(c in '0123456789abcdefABCDEF' for c in text[:100]):
                    return ""

            # Skip if looks like valid Base64 (let Base64 decoder handle it)
            if len(text) >= 20:
                base64_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
                base64_ratio = sum(1 for c in text if c in base64_chars) / len(text)
                if base64_ratio > 0.95:  # 95% Base64 characters
                    return ""

            # Encode to bytes
            try:
                data = text.encode('latin-1')
            except UnicodeEncodeError:
                data = text.encode('utf-8', errors='surrogateescape')

            best_result = ""
            best_score = 0.0

            # Try each common key
            for key in self.common_keys:
                xor_bytes = bytes([byte ^ key for byte in data])

                # Check for compression
                for decoder in self.compression_decoders:
                    compressed_result = decoder.decode(xor_bytes.decode('latin-1', errors='ignore'))
                    if compressed_result:
                        return compressed_result

                # Check printable ratio
                printable_ratio = self._printable_ratio(xor_bytes)
                if printable_ratio < 0.6:
                    continue

                # Decode to string
                try:
                    decoded = xor_bytes.decode('utf-8', errors='ignore')
                except:
                    continue

                # Score result
                score = self._english_score(decoded) + (printable_ratio * 2)

                if score > best_score and decoded:
                    best_score = score
                    best_result = decoded

            return best_result

        except Exception:
            return ""


class MultiByteXORDecoder(BaseDecoder):
    """Multi-byte XOR cipher decoding (2/3/4-byte repeating keys)"""

    def __init__(self, config=None):
        super().__init__(config)
        self.compression_decoders = get_compression_decoders()

        # Common multi-byte keys
        # EXPANDED (v1.4.2): Added 0xDEAD (common in malware samples)
        self.multibyte_keys = [
            bytes([0xAB, 0xCD]),
            bytes([0x12, 0x34]),
            bytes([0xFF, 0xFF]),
            bytes([0x00, 0xFF]),
            bytes([0xDE, 0xAD]),              # 2-byte DEAD
            bytes([0xDE, 0xAD, 0xBE]),
            bytes([0xCA, 0xFE, 0xBA]),
            bytes([0xDE, 0xAD, 0xBE, 0xEF]),
            bytes([0xCA, 0xFE, 0xBA, 0xBE]),
        ]

    def get_name(self) -> str:
        return "xor_multibyte"

    def decode(self, text: str) -> str:
        """
        Decode multi-byte XOR-encrypted string

        Features:
        - Tries 2/3/4-byte repeating XOR keys
        - Base64 string avoidance
        - Compression detection (GZIP/zlib)
        - English scoring for best result

        Multi-byte Keys: 0xABCD, 0x1234, 0xDEADBEEF, etc.

        Args:
            text: Input string (potentially XOR-encrypted)

        Returns:
            Best-scoring XOR-decoded string, or empty if no good results
        """
        try:
            # Skip if looks like valid Base64
            if len(text) >= 20:
                base64_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
                base64_ratio = sum(1 for c in text if c in base64_chars) / len(text)
                if base64_ratio > 0.95:
                    return ""

            # Encode to bytes
            try:
                data = text.encode('latin-1')
            except UnicodeEncodeError:
                data = text.encode('utf-8', errors='surrogateescape')

            best_result = ""
            best_score = 0.0

            # Try each multi-byte key
            for key_bytes in self.multibyte_keys:
                xor_bytes = bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])

                # Check for compression
                for decoder in self.compression_decoders:
                    compressed_result = decoder.decode(xor_bytes.decode('latin-1', errors='ignore'))
                    if compressed_result:
                        return compressed_result

                # Check printable ratio
                printable_ratio = self._printable_ratio(xor_bytes)
                if printable_ratio < 0.6:
                    continue

                # Decode to string
                try:
                    decoded = xor_bytes.decode('utf-8', errors='ignore')
                except:
                    continue

                # Score result
                score = self._english_score(decoded) + (printable_ratio * 2)

                if score > best_score and decoded:
                    best_score = score
                    best_result = decoded

            return best_result

        except Exception:
            return ""


class UTF16LEDecoder(BaseDecoder):
    """UTF-16LE encoding decoder (Windows/PowerShell)"""

    def get_name(self) -> str:
        return "utf16le"

    def decode(self, text: str) -> str:
        """
        Decode UTF-16LE-encoded string

        Features:
        - Null byte pattern detection
        - Even length validation
        - Printable ratio check

        Args:
            text: Input string (latin-1 encoded UTF-16LE bytes)

        Returns:
            UTF-16LE-decoded string if valid, empty otherwise
        """
        try:
            # Convert to bytes
            data_bytes = text.encode('latin-1', errors='ignore')

            # Validation
            if len(data_bytes) < 4 or len(data_bytes) % 2 != 0:
                return ""

            # Check for null bytes pattern (UTF-16LE has nulls at odd positions)
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
