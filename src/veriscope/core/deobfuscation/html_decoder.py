"""
HTML Entity Decoder
Handles HTML entity decoding (&lt; → <, &gt; → >, etc.)
"""

import html
from .base import BaseDecoder


class HTMLEntityDecoder(BaseDecoder):
    """Decode HTML entities like &lt;div&gt; → <div>"""

    def get_name(self) -> str:
        return "html_entity"

    def decode(self, text: str) -> str:
        """
        Decode HTML entities

        Args:
            text: Input string potentially containing HTML entities

        Returns:
            Decoded string, or empty string if no entities found
        """
        try:
            # Check if text contains HTML entities
            if '&' not in text or ';' not in text:
                return ""

            # Decode HTML entities
            decoded = html.unescape(text)

            # Only return if something changed
            if decoded != text:
                return decoded

        except Exception:
            pass

        return ""
