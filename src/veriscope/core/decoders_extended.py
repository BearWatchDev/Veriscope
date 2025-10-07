"""
Extended decoders for improved obfuscation detection
Handles: ASCII85, Base32, URL encoding, UTF-16, compression formats
"""

import base64
import binascii
import gzip
import zlib
import bz2
import lzma
import re
from typing import Optional
from .deobfuscation.base import BaseDecoder


class ASCII85Decoder(BaseDecoder):
    """Decode ASCII85 / Base85 encoded strings"""

    def get_name(self) -> str:
        return "ascii85"

    def can_decode(self, text: str) -> bool:
        # ASCII85 typically starts with <~ and ends with ~>
        if text.strip().startswith('<~') and text.strip().endswith('~>'):
            return True
        # Also check for high concentration of ASCII85 chars (33-117 range)
        if len(text) > 10:
            ascii85_chars = sum(1 for c in text if 33 <= ord(c) <= 117)
            return ascii85_chars / len(text) > 0.8
        return False

    def decode(self, text: str) -> Optional[str]:
        try:
            # Try standard ASCII85 with <~ ~> markers
            if text.strip().startswith('<~') and text.strip().endswith('~>'):
                decoded_bytes = base64.a85decode(text.strip())
                return decoded_bytes.decode('utf-8', errors='ignore')

            # Try without markers
            decoded_bytes = base64.a85decode(text.strip())
            return decoded_bytes.decode('utf-8', errors='ignore')
        except:
            return None


class Base32Decoder(BaseDecoder):
    """Decode Base32 encoded strings"""

    def get_name(self) -> str:
        return "base32"

    def can_decode(self, text: str) -> bool:
        # Base32 uses A-Z and 2-7
        if len(text) < 8:
            return False
        base32_pattern = re.compile(r'^[A-Z2-7=]+$')
        return bool(base32_pattern.match(text.strip()))

    def decode(self, text: str) -> Optional[str]:
        try:
            # Remove whitespace and normalize
            clean_text = text.strip().replace(' ', '').replace('\n', '')
            decoded_bytes = base64.b32decode(clean_text)
            return decoded_bytes.decode('utf-8', errors='ignore')
        except:
            return None


class Base32HexDecoder(BaseDecoder):
    """Decode Base32Hex encoded strings"""

    def get_name(self) -> str:
        return "base32hex"

    def can_decode(self, text: str) -> bool:
        # Base32Hex uses 0-9 and A-V
        if len(text) < 8:
            return False
        base32hex_pattern = re.compile(r'^[0-9A-V=]+$')
        return bool(base32hex_pattern.match(text.strip()))

    def decode(self, text: str) -> Optional[str]:
        try:
            clean_text = text.strip().replace(' ', '').replace('\n', '')
            decoded_bytes = base64.b32hexdecode(clean_text)
            return decoded_bytes.decode('utf-8', errors='ignore')
        except:
            return None


class URLPercentDecoder(BaseDecoder):
    """Decode URL percent-encoded strings (repeated if necessary)"""

    def get_name(self) -> str:
        return "url_percent"

    def can_decode(self, text: str) -> bool:
        # Check for % followed by hex digits
        return '%' in text and bool(re.search(r'%[0-9A-Fa-f]{2}', text))

    def decode(self, text: str) -> Optional[str]:
        try:
            import urllib.parse
            # Repeatedly decode until no more % encoding
            decoded = text
            max_iterations = 5
            for _ in range(max_iterations):
                prev = decoded
                decoded = urllib.parse.unquote(decoded)
                if decoded == prev:
                    break

            return decoded if decoded != text else None
        except:
            return None


class UTF16Decoder(BaseDecoder):
    """Detect and decode UTF-16 LE/BE encoded strings"""

    def get_name(self) -> str:
        return "utf16"

    def can_decode(self, text: str) -> bool:
        # Look for many null bytes (0x00) which is typical of UTF-16
        if len(text) < 4:
            return False

        # Check for BOM markers
        if text.startswith('\ufeff') or text.startswith('\ufffe'):
            return True

        # Count null bytes
        null_count = text.count('\x00')
        # If >30% null bytes, likely UTF-16
        return null_count / len(text) > 0.3

    def decode(self, text: str) -> Optional[str]:
        try:
            # Try UTF-16 LE
            try:
                decoded = text.encode('latin-1').decode('utf-16-le')
                if decoded.isprintable() or '\n' in decoded or '\r' in decoded:
                    return decoded
            except:
                pass

            # Try UTF-16 BE
            try:
                decoded = text.encode('latin-1').decode('utf-16-be')
                if decoded.isprintable() or '\n' in decoded or '\r' in decoded:
                    return decoded
            except:
                pass

            return None
        except:
            return None


class GzipDecoder(BaseDecoder):
    """Decompress gzip-compressed data"""

    def get_name(self) -> str:
        return "gzip"

    def can_decode(self, text: str) -> bool:
        # Gzip magic bytes: 1f 8b
        if len(text) < 2:
            return False
        try:
            bytes_data = text.encode('latin-1')
            return bytes_data[:2] == b'\x1f\x8b'
        except:
            return False

    def decode(self, text: str) -> Optional[str]:
        try:
            bytes_data = text.encode('latin-1')
            decompressed = gzip.decompress(bytes_data)
            return decompressed.decode('utf-8', errors='ignore')
        except:
            return None


class ZlibDecoder(BaseDecoder):
    """Decompress zlib-compressed data"""

    def get_name(self) -> str:
        return "zlib"

    def can_decode(self, text: str) -> bool:
        # Zlib magic bytes: 78 (most common)
        if len(text) < 2:
            return False
        try:
            bytes_data = text.encode('latin-1')
            return bytes_data[0] == 0x78
        except:
            return False

    def decode(self, text: str) -> Optional[str]:
        try:
            bytes_data = text.encode('latin-1')
            decompressed = zlib.decompress(bytes_data)
            return decompressed.decode('utf-8', errors='ignore')
        except:
            return None


class NoiseNormalizer(BaseDecoder):
    """Strip whitespace/noise from base64/hex candidates before decode"""

    def get_name(self) -> str:
        return "noise_normalize"

    def can_decode(self, text: str) -> bool:
        # Check if text has base64/hex chars mixed with noise
        clean = re.sub(r'[^A-Za-z0-9+/=]', '', text)
        if len(clean) > len(text) * 0.5:  # If >50% is valid chars
            return True
        return False

    def decode(self, text: str) -> Optional[str]:
        # This decoder is special - it normalizes but doesn't decode
        # Remove common noise: spaces, newlines, dashes, equals (will be re-added for base64)
        clean = text.replace(' ', '').replace('\n', '').replace('\r', '').replace('-', '')

        # If significantly cleaned, return cleaned version
        if len(clean) < len(text) * 0.9:
            return clean
        return None
