"""
ROT13 and URL Decoding
Simple substitution and percent-encoding methods
"""

import codecs
import urllib.parse
import base64
from .base import BaseDecoder


class ROT13Decoder(BaseDecoder):
    """ROT13 Caesar cipher decoding with keyword detection"""

    # Class-level constants for better performance (avoid recreating on each decode)
    # EXPANDED (v1.4.2): Added more malware/shell keywords for better detection
    COMMON_KEYWORDS = frozenset([
        'http', 'www', 'exe', 'dll', 'cmd', 'powershell', 'script',
        'user', 'config', 'token', 'shell', 'alert', 'process',
        'mail', 'from', 'subject', 'message', 'email', 'sender',
        'recipient', 'attacker', 'example', 'update', 'urgent',
        'bash', 'backdoor', 'bin', 'tmp', 'malware', 'payload',
        'download', 'upload', 'reverse', 'netcat', 'connect'
    ])
    BASE64_ALPHABET = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')

    def __init__(self, config=None):
        super().__init__(config)
        self.speculative_mode = config.speculative_rot13 if config else False

    def get_name(self) -> str:
        return "rot13"

    def decode(self, text: str) -> str:
        """
        Decode ROT13-encoded string

        Features:
        - Base64 indicator avoidance
        - Keyword-based detection
        - Speculative mode (checks if output is base64/hex)

        Common Keywords:
        http, www, exe, dll, cmd, powershell, script, user, config,
        token, shell, alert, process, mail, etc.

        Args:
            text: Input string (potentially ROT13-encoded)

        Returns:
            ROT13-decoded string if keywords found, empty otherwise
        """
        try:
            # Don't trigger on Base64 (lots of +/= chars)
            # FIXED (v1.4.2): Only skip if we have actual Base64 indicators (+ or =), not just /
            # Forward slash appears in file paths (/bin/bash), not indicative of Base64 alone
            plus_count = text.count('+')
            equals_count = text.count('=')
            slash_count = text.count('/')

            # Only skip if we have Base64 padding (=) or Base64-specific chars (+)
            if (plus_count + equals_count) > len(text) * 0.05:
                return ""

            # Don't trigger if input itself looks like base64 (would cause ROT13 → Base64 false positive)
            # Check if input has high ratio of base64 alphabet characters
            if len(text) >= 20:
                base64_ratio = sum(1 for c in text if c in self.BASE64_ALPHABET) / len(text)
                if base64_ratio > 0.92:  # 92%+ base64 chars in input = probably already base64, skip ROT13
                    return ""

            decoded = codecs.decode(text, 'rot13')

            # Check for common words or markers
            decoded_lower = decoded.lower()
            if any(word in decoded_lower for word in self.COMMON_KEYWORDS):
                return decoded

            # Speculative ROT13: If enabled, also check if output looks like it could be further decoded
            if self.speculative_mode and len(decoded) >= 20:
                # Check if decoded output looks like valid Base64
                base64_ratio = sum(1 for c in decoded if c in self.BASE64_ALPHABET) / len(decoded)

                if base64_ratio > 0.90:  # 90% Base64 characters
                    # Verify it can actually be decoded as Base64
                    try:
                        cleaned = ''.join(c for c in decoded if c in self.BASE64_ALPHABET)
                        test_decode = base64.b64decode(cleaned)
                        if len(test_decode) >= 10:  # Non-trivial output
                            return decoded
                    except:
                        pass

                # Check if output looks like hex-encoded data
                if len(decoded) % 2 == 0:
                    hex_chars = sum(1 for c in decoded if c in '0123456789abcdefABCDEF')
                    if hex_chars / len(decoded) > 0.95:
                        try:
                            test_hex = bytes.fromhex(decoded)
                            if len(test_hex) >= 10:
                                return decoded
                        except:
                            pass

        except Exception:
            pass

        return ""


class URLDecoder(BaseDecoder):
    """URL percent-encoding decoder"""

    def get_name(self) -> str:
        return "url_encoding"

    def decode(self, text: str) -> str:
        """
        Decode URL percent-encoded string

        Decodes %XX sequences to their character equivalents

        Args:
            text: Input string (potentially URL-encoded)

        Returns:
            URL-decoded string if different from input, empty otherwise
        """
        try:
            decoded = urllib.parse.unquote(text)
            if decoded != text and len(decoded) > 0:
                return decoded
        except Exception:
            pass

        return ""


class CharCodesDecoder(BaseDecoder):
    """Character code decoding for comma-separated, colon-separated, or space-separated decimal/hex codes"""

    def get_name(self) -> str:
        return "char_codes"

    def decode(self, text: str) -> str:
        """
        Decode character codes (e.g., JavaScript String.fromCharCode)

        Supports formats:
        - Comma-separated decimal: "72,101,108,108,111"
        - Colon-separated decimal: "72:101:108:108:111"
        - Space-separated decimal: "72 101 108 108 111"
        - Hex format: "0x48,0x65,0x6c,0x6c,0x6f" or "0x48 0x65 0x6c"

        Args:
            text: Input string with character codes

        Returns:
            Decoded string if valid char codes found, empty otherwise
        """
        try:
            # Check for hex format (0x prefix)
            has_hex_prefix = '0x' in text.lower()

            # Determine delimiter
            delimiter = None
            if ',' in text and text.count(',') >= 3:
                delimiter = ','
            elif ':' in text and text.count(':') >= 3 and not has_hex_prefix:
                # Avoid confusing : delimiter with 0x: pattern
                delimiter = ':'
            elif ' ' in text and text.count(' ') >= 3:
                # Only if no other delimiters
                if ',' not in text and ':' not in text:
                    delimiter = ' '

            if not delimiter:
                return ""

            # Split and parse
            parts = [p.strip() for p in text.split(delimiter)]

            # Parse numbers (handle both decimal and hex)
            char_codes = []
            for p in parts:
                if not p:
                    continue
                try:
                    # Try hex first if it looks like hex
                    if p.lower().startswith('0x'):
                        char_codes.append(int(p, 16))
                    elif p.isdigit():
                        char_codes.append(int(p))
                except ValueError:
                    continue

            # Must have at least 4 char codes
            if len(char_codes) < 4:
                return ""

            # All codes must be valid ASCII/Unicode range (0-1114111)
            if not all(0 <= code <= 1114111 for code in char_codes):
                return ""

            # Convert to string
            decoded = ''.join(chr(code) for code in char_codes)

            # Only return if result is printable
            if decoded and len(decoded) >= 4:
                # Check if mostly printable
                printable_ratio = sum(1 for c in decoded if c.isprintable()) / len(decoded)
                if printable_ratio > 0.75:  # Slightly more lenient than before
                    return decoded

        except Exception:
            pass

        return ""
