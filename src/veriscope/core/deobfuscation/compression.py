"""
Compression Decoders
Handles GZIP, zlib, and bzip2 decompression
"""

import gzip
import zlib
import bz2
from .base import CompressionDecoder


class GzipDecoder(CompressionDecoder):
    """GZIP decompression decoder"""

    def get_name(self) -> str:
        return "gzip"

    def decode(self, text: str) -> str:
        """
        Decompress GZIP data

        Detects GZIP magic bytes (0x1f 0x8b) and decompresses

        Args:
            text: Input string (latin-1 encoded binary data)

        Returns:
            Decompressed UTF-8 string, or empty string if not GZIP
        """
        try:
            # Convert string to bytes
            data_bytes = text.encode('latin-1', errors='ignore')

            # Check magic bytes
            if len(data_bytes) < 2 or data_bytes[:2] != b'\x1f\x8b':
                return ""

            # Decompress
            decompressed = gzip.decompress(data_bytes)

            if self._check_printable(decompressed):
                return decompressed.decode('utf-8', errors='ignore')

        except Exception:
            pass

        return ""


class ZlibDecoder(CompressionDecoder):
    """zlib decompression decoder"""

    def get_name(self) -> str:
        return "zlib"

    def decode(self, text: str) -> str:
        """
        Decompress zlib data

        Detects zlib magic bytes (0x78 followed by 0x01/0x5E/0x9C/0xDA)

        Args:
            text: Input string (latin-1 encoded binary data)

        Returns:
            Decompressed UTF-8 string, or empty string if not zlib
        """
        try:
            # Convert string to bytes
            data_bytes = text.encode('latin-1', errors='ignore')

            # Check magic bytes
            if len(data_bytes) < 2 or data_bytes[0] != 0x78:
                return ""

            if data_bytes[1] not in [0x01, 0x5E, 0x9C, 0xDA]:
                return ""

            # Decompress
            decompressed = zlib.decompress(data_bytes)

            if self._check_printable(decompressed):
                return decompressed.decode('utf-8', errors='ignore')

        except Exception:
            pass

        return ""


class Bzip2Decoder(CompressionDecoder):
    """bzip2 decompression decoder"""

    def get_name(self) -> str:
        return "bzip2"

    def decode(self, text: str) -> str:
        """
        Decompress bzip2 data

        Detects bzip2 magic bytes (BZh followed by compression level 1-9)

        Args:
            text: Input string (latin-1 encoded binary data)

        Returns:
            Decompressed UTF-8 string, or empty string if not bzip2
        """
        try:
            # Convert string to bytes
            data_bytes = text.encode('latin-1', errors='ignore')

            # Check magic bytes
            if len(data_bytes) < 4 or data_bytes[:3] != b'BZh':
                return ""

            # Check compression level (1-9)
            if not (0x31 <= data_bytes[3] <= 0x39):
                return ""

            # Decompress
            decompressed = bz2.decompress(data_bytes)

            if self._check_printable(decompressed):
                return decompressed.decode('utf-8', errors='ignore')

        except Exception:
            pass

        return ""


# Factory function for easy access
def get_compression_decoders():
    """
    Get all compression decoders

    Returns:
        List of initialized compression decoder instances
    """
    return [
        GzipDecoder(),
        ZlibDecoder(),
        Bzip2Decoder()
    ]
