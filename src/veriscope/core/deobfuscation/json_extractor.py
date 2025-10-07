"""
JSON Field Extractor
Extracts values from JSON payloads
"""

import json
import re
from .base import BaseDecoder


class JSONExtractorDecoder(BaseDecoder):
    """Extract fields from JSON payloads like {" payload":"VEVTVCBKUw=="} → VEVTVCBKUw=="""

    def get_name(self) -> str:
        return "json_extract"

    def decode(self, text: str) -> str:
        """
        Extract payload field from JSON

        Args:
            text: Input string potentially containing JSON

        Returns:
            Extracted payload value, or empty string if no JSON
        """
        try:
            # Check if looks like JSON
            text_strip = text.strip()
            if not (text_strip.startswith('{') and text_strip.endswith('}')):
                return ""

            # Parse JSON
            data = json.loads(text_strip)

            # Try common payload field names
            for field in ['payload', 'data', 'content', 'value', 'message']:
                if field in data:
                    value = data[field]
                    if isinstance(value, str) and value:
                        return value

        except Exception:
            pass

        return ""


class JSAtobExtractorDecoder(BaseDecoder):
    """Extract base64 from atob() calls like eval(atob('VEVTVCBKUw==')) → VEVTVCBKUw=="""

    def get_name(self) -> str:
        return "js_atob"

    def decode(self, text: str) -> str:
        """
        Extract base64 from JavaScript atob() calls

        Args:
            text: Input string potentially containing atob()

        Returns:
            Extracted base64 string, or empty string if no atob() found
        """
        try:
            # Match atob('...') or atob("...")
            pattern = r"atob\s*\(\s*['\"]([A-Za-z0-9+/=_-]+)['\"]\s*\)"
            match = re.search(pattern, text)

            if match:
                return match.group(1)

        except Exception:
            pass

        return ""
