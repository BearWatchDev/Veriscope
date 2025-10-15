"""
String transformation decoders
Handles string-based transforms like reversal, binary, unicode escapes, etc.
"""

import re
from typing import Optional
from .base import BaseDecoder


class BinaryStringDecoder(BaseDecoder):
    """Decode binary strings like '01010100 01000101 01010011 01010100' → 'TEST'"""

    def get_name(self) -> str:
        return "binary_string"

    def can_decode(self, text: str) -> bool:
        # VERY conservative - must be ONLY 0s, 1s, and whitespace
        # AND have at least 2 space-separated 8-bit groups
        if len(text) < 17:  # At minimum "01010100 01000101"
            return False

        # Strip whitespace and check
        clean = text.replace(' ', '').replace('\n', '').replace('\t', '')

        # Must be ALL binary digits
        if not all(c in '01' for c in clean):
            return False

        # Must have spaces (indicating groups)
        if ' ' not in text:
            return False

        # Check for 8-bit groups pattern
        parts = text.split()
        valid_groups = sum(1 for p in parts if len(p) == 8 and all(c in '01' for c in p))

        # Must have at least 2 valid 8-bit groups
        return valid_groups >= 2

    def decode(self, text: str) -> Optional[str]:
        try:
            # Split by whitespace and parse each 8-bit group
            clean = text.replace('\n', ' ').replace('\t', ' ')
            parts = clean.split()

            bytes_list = []
            for part in parts:
                # Each part should be 8 bits
                if len(part) == 8 and all(c in '01' for c in part):
                    byte_val = int(part, 2)
                    bytes_list.append(byte_val)
                elif all(c in '01' for c in part):
                    # Handle parts that aren't exactly 8 bits
                    byte_val = int(part, 2)
                    bytes_list.append(byte_val)

            if bytes_list:
                result = bytes(bytes_list).decode('utf-8', errors='ignore')
                if result and result.isprintable():
                    return result
        except:
            pass
        return None


class UnicodeEscapeDecoder(BaseDecoder):
    """Decode unicode escapes like '\\u0054\\u0045\\u0053\\u0054' → 'TEST'"""

    def get_name(self) -> str:
        return "unicode_escape"

    def can_decode(self, text: str) -> bool:
        # Check for \uXXXX or \UXXXXXXXX patterns
        return bool(re.search(r'\\u[0-9a-fA-F]{4}', text) or
                   re.search(r'\\U[0-9a-fA-F]{8}', text))

    def decode(self, text: str) -> Optional[str]:
        try:
            # Decode unicode escapes
            result = text.encode().decode('unicode-escape')
            if result != text and result.isprintable():
                return result
        except:
            pass
        return None


class StringReversalDecoder(BaseDecoder):
    """Reverse string before decoding (helps with obfuscation)"""

    def get_name(self) -> str:
        return "string_reversal"

    def can_decode(self, text: str) -> bool:
        # FIXED (v1.4.2): Detect reversed base64 by checking for padding at start
        # Reversed base64 will have = or == at the beginning instead of end
        if len(text) < 10:
            return False

        # Check for = or == at start (reversed base64 padding)
        if text.startswith('=='):
            # Double padding - check if rest looks like base64
            rest = text[2:]
            base64_chars = sum(1 for c in rest if c.isalnum() or c in '+/=')
            return base64_chars / len(rest) > 0.85
        elif text.startswith('='):
            # Single padding - check if rest looks like base64
            rest = text[1:]
            base64_chars = sum(1 for c in rest if c.isalnum() or c in '+/=')
            return base64_chars / len(rest) > 0.85

        return False

    def decode(self, text: str) -> Optional[str]:
        # Check if this looks like reversed base64 before reversing
        if not self.can_decode(text):
            return None

        # Reverse the string
        reversed_text = text[::-1]
        if reversed_text != text:
            return reversed_text
        return None


class HexEscapeDecoder(BaseDecoder):
    """Decode hex escapes like '\\x54\\x45\\x53\\x54' → 'TEST'"""

    def get_name(self) -> str:
        return "hex_escape"

    def can_decode(self, text: str) -> bool:
        # Check for \xHH patterns
        return bool(re.search(r'\\x[0-9a-fA-F]{2}', text))

    def decode(self, text: str) -> Optional[str]:
        try:
            # Find all \xHH patterns
            hex_pattern = re.compile(r'\\x([0-9a-fA-F]{2})')
            matches = hex_pattern.findall(text)

            if matches:
                # Convert hex values to bytes
                byte_values = [int(h, 16) for h in matches]
                result = bytes(byte_values).decode('utf-8', errors='ignore')
                if result and result.isprintable():
                    return result
        except:
            pass
        return None
