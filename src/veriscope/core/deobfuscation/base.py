"""
Base Decoder Interface
Defines the abstract interface all decoders must implement
"""

from abc import ABC, abstractmethod
from typing import Optional


class BaseDecoder(ABC):
    """Abstract base class for all decoding methods"""

    def __init__(self, config=None):
        """
        Initialize decoder with optional configuration

        Args:
            config: Decoder-specific configuration object
        """
        self.config = config

    @abstractmethod
    def decode(self, text: str) -> str:
        """
        Attempt to decode the input text

        Args:
            text: Input string (potentially encoded)

        Returns:
            Decoded string if successful, empty string if decoding not applicable/failed
        """
        pass

    @abstractmethod
    def get_name(self) -> str:
        """
        Get the name of this decoding method

        Returns:
            Human-readable name (e.g., "base64", "hex", "xor")
        """
        pass

    def _printable_ratio(self, data: bytes) -> float:
        """
        Calculate ratio of printable characters in byte data

        Args:
            data: Byte string to analyze

        Returns:
            Ratio of printable bytes (0.0 to 1.0)
        """
        if not data:
            return 0.0

        printable = sum(1 for b in data if 32 <= b <= 126 or b in [9, 10, 13])
        return printable / len(data)

    def _english_score(self, text: str) -> float:
        """
        Score text for English-like characteristics

        Args:
            text: String to analyze

        Returns:
            Score based on common English words (0.0 to 10.0)
        """
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


class CompressionDecoder(BaseDecoder):
    """Base class for compression decoders (GZIP, zlib, bzip2)"""

    def _check_printable(self, data: bytes, threshold: float = 0.6) -> bool:
        """
        Check if decompressed data has sufficient printable content

        Args:
            data: Decompressed byte data
            threshold: Minimum printable ratio (default: 0.6)

        Returns:
            True if data meets printable threshold
        """
        if not data or len(data) == 0:
            return False

        try:
            decoded = data.decode('utf-8', errors='ignore')
            if decoded and len(decoded) > 0:
                printable_ratio = sum(c.isprintable() or c in '\n\r\t' for c in decoded) / len(decoded)
                return printable_ratio > threshold
        except Exception:
            pass

        return False
