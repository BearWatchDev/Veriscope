"""
Advanced XOR decoders with repeating-key breaking and crib-dragging
"""

from .base import BaseDecoder
from ..xor_breaker import XORBreaker


class RepeatingKeyXORDecoder(BaseDecoder):
    """Break repeating-key XOR using frequency analysis"""

    def __init__(self, config=None):
        super().__init__(config)
        self.breaker = XORBreaker(max_key_len=12)

    def get_name(self) -> str:
        return "xor_repeating"

    def decode(self, text: str) -> str:
        try:
            # Convert to bytes
            ciphertext = text.encode('latin-1')

            # Skip if too short
            if len(ciphertext) < 20:
                return ""

            # Break repeating-key XOR
            results = self.breaker.break_repeating_key_xor(ciphertext)

            if results:
                # Return best candidate
                key, plaintext, score = results[0]

                # Only return if score is good
                if score > 0.6:
                    return plaintext

        except:
            pass

        return ""


class CribDraggerDecoder(BaseDecoder):
    """Use probable-plaintext (crib) attacks to break XOR"""

    def __init__(self, config=None):
        super().__init__(config)
        self.breaker = XORBreaker(max_key_len=12)

    def get_name(self) -> str:
        return "xor_crib"

    def decode(self, text: str) -> str:
        try:
            # Convert to bytes
            ciphertext = text.encode('latin-1')

            # Skip if too short
            if len(ciphertext) < 15:
                return ""

            # Try crib-dragging
            results = self.breaker.crib_drag(ciphertext)

            if results:
                # Return first match
                key, plaintext, crib = results[0]
                return plaintext

        except:
            pass

        return ""


class CommonSingleByteXORDecoder(BaseDecoder):
    """Try common single-byte XOR keys (fast path)"""

    def __init__(self, config=None):
        super().__init__(config)
        self.breaker = XORBreaker()

    def get_name(self) -> str:
        return "xor_single_common"

    def decode(self, text: str) -> str:
        try:
            # Convert to bytes
            ciphertext = text.encode('latin-1')

            # Try common single-byte keys
            results = self.breaker.try_common_single_byte_xor(ciphertext)

            if results:
                key_byte, plaintext, score = results[0]
                if score > 0.6:
                    return plaintext

        except:
            pass

        return ""


class CommonKeyXORDecoder(BaseDecoder):
    """Try common multibyte XOR keys"""

    def __init__(self, config=None):
        super().__init__(config)
        self.breaker = XORBreaker()

    def get_name(self) -> str:
        return "xor_common"

    def decode(self, text: str) -> str:
        try:
            # Convert to bytes
            ciphertext = text.encode('latin-1')

            # Try common keys
            results = self.breaker.try_common_keys(ciphertext)

            if results:
                key, plaintext, score = results[0]
                if score > 0.6:
                    return plaintext

        except:
            pass

        return ""
