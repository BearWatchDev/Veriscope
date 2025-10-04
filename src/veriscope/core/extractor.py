"""
String Extraction Module
Extracts printable ASCII/UTF-8 strings from binary or text files
Minimum length: 6 characters (configurable)
"""

import re
from typing import List, BinaryIO, TextIO, Union
from pathlib import Path


class StringExtractor:
    """
    Extracts printable strings from files for malware analysis

    Handles both text and binary files, extracting ASCII and UTF-8 strings
    that meet minimum length requirements.
    """

    def __init__(self, min_length: int = 6, max_length: int = 1000):
        """
        Initialize string extractor

        Args:
            min_length: Minimum string length to extract (default: 6)
            max_length: Maximum string length to prevent memory issues (default: 1000)
        """
        self.min_length = min_length
        self.max_length = max_length

        # Regex pattern for printable ASCII strings
        # Matches sequences of printable ASCII characters (space through ~)
        self.ascii_pattern = re.compile(
            rb'[ -~]{%d,%d}' % (self.min_length, self.max_length)
        )

        # Regex pattern for UTF-16 LE strings (common in Windows binaries)
        # Matches ASCII chars encoded as UTF-16 LE (char followed by null byte)
        self.utf16_pattern = re.compile(
            rb'(?:[ -~]\x00){%d,%d}' % (self.min_length, self.max_length)
        )

    def extract_from_file(self, file_path: Union[str, Path]) -> List[str]:
        """
        Extract strings from a file (binary or text)

        Args:
            file_path: Path to input file

        Returns:
            List of extracted strings (deduplicated, sorted by frequency)
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Read file as binary to handle both text and binary files
        with open(file_path, 'rb') as f:
            content = f.read()

        return self.extract_from_bytes(content)

    def extract_from_bytes(self, data: bytes) -> List[str]:
        """
        Extract strings from raw bytes

        Args:
            data: Raw byte data

        Returns:
            List of extracted strings (deduplicated, sorted by frequency)
        """
        strings = set()

        # Extract ASCII strings
        ascii_matches = self.ascii_pattern.findall(data)
        for match in ascii_matches:
            try:
                decoded = match.decode('ascii', errors='ignore').strip()
                if len(decoded) >= self.min_length:
                    strings.add(decoded)
            except:
                continue

        # Extract UTF-16 LE strings (Windows binaries)
        utf16_matches = self.utf16_pattern.findall(data)
        for match in utf16_matches:
            try:
                # Decode UTF-16 LE by removing null bytes
                decoded = match.decode('utf-16-le', errors='ignore').strip()
                if len(decoded) >= self.min_length:
                    strings.add(decoded)
            except:
                continue

        # Convert to sorted list (alphabetically for consistency)
        return sorted(list(strings))

    def extract_from_text(self, text: str) -> List[str]:
        """
        Extract strings from plain text (already decoded)
        Useful for processing deobfuscated scripts

        Args:
            text: Plain text string

        Returns:
            List of extracted strings (lines/tokens meeting min length)
        """
        strings = set()

        # Split by common delimiters and newlines
        for line in text.splitlines():
            line = line.strip()
            if len(line) >= self.min_length:
                strings.add(line)

        return sorted(list(strings))

    def get_stats(self, strings: List[str]) -> dict:
        """
        Get statistics about extracted strings

        Args:
            strings: List of extracted strings

        Returns:
            Dictionary with string extraction statistics
        """
        if not strings:
            return {
                'total_count': 0,
                'unique_count': 0,
                'avg_length': 0,
                'min_length': 0,
                'max_length': 0
            }

        lengths = [len(s) for s in strings]

        return {
            'total_count': len(strings),
            'unique_count': len(set(strings)),
            'avg_length': sum(lengths) / len(lengths),
            'min_length': min(lengths),
            'max_length': max(lengths)
        }
