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
            base64_chars = text.count('+') + text.count('/') + text.count('=')
            if base64_chars > len(text) * 0.05:
                return ""

            decoded = codecs.decode(text, 'rot13')

            # Check for common words or markers
            common_words = [
                'http', 'www', 'exe', 'dll', 'cmd', 'powershell', 'script',
                'user', 'config', 'token', 'shell', 'alert', 'process',
                'mail', 'from', 'subject', 'message', 'email', 'sender',
                'recipient', 'attacker', 'example', 'update', 'urgent'
            ]
            if any(word in decoded.lower() for word in common_words):
                return decoded

            # Speculative ROT13: If enabled, also check if output looks like it could be further decoded
            if self.speculative_mode and len(decoded) >= 20:
                # Check if decoded output looks like valid Base64
                base64_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
                base64_ratio = sum(1 for c in decoded if c in base64_alphabet) / len(decoded)

                if base64_ratio > 0.90:  # 90% Base64 characters
                    # Verify it can actually be decoded as Base64
                    try:
                        cleaned = ''.join(c for c in decoded if c in base64_alphabet)
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
    """Character code decoding (placeholder for future implementation)"""

    def get_name(self) -> str:
        return "char_codes"

    def decode(self, text: str) -> str:
        """
        Decode character codes (e.g., JavaScript String.fromCharCode)

        Currently a placeholder for future implementation

        Args:
            text: Input string

        Returns:
            Empty string (not implemented)
        """
        # Placeholder for character code decoding
        return ""
