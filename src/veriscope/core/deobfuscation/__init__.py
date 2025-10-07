"""
Deobfuscation Package
Modular deobfuscation methods for malware analysis

Each module contains specialized decoders:
- base.py: Base classes and interfaces
- compression.py: GZIP, zlib, bzip2
- base64_hex.py: Base64, Hex, PowerShell Base64
- rot13_url.py: ROT13, URL encoding, char codes
- xor_encoding.py: XOR (single/multi-byte), UTF-16LE
- Extended decoders (added for improved detection):
  - decoders_extended: ASCII85, Base32, URL-percent, UTF-16, compression
  - xor_advanced: Repeating-key XOR breaker, crib-dragging, common keys
"""

# Base classes
from .base import BaseDecoder, CompressionDecoder

# Compression decoders
from .compression import GzipDecoder, ZlibDecoder, Bzip2Decoder, get_compression_decoders

# Base64 and Hex
from .base64_hex import Base64Decoder, HexDecoder, PowerShellBase64Decoder, Base64URLDecoder

# ROT13 and URL
from .rot13_url import ROT13Decoder, URLDecoder, CharCodesDecoder

# XOR and Encoding
from .xor_encoding import XORDecoder, MultiByteXORDecoder, UTF16LEDecoder

# String transforms
from .string_transforms import (
    BinaryStringDecoder, UnicodeEscapeDecoder, StringReversalDecoder, HexEscapeDecoder
)

# HTML and JSON extractors
from .html_decoder import HTMLEntityDecoder
from .json_extractor import JSONExtractorDecoder, JSAtobExtractorDecoder

# Extended decoders (import with error handling in case modules don't exist yet)
EXTENDED_DECODERS_AVAILABLE = False
try:
    from ..decoders_extended import (
        ASCII85Decoder, Base32Decoder, Base32HexDecoder,
        URLPercentDecoder, UTF16Decoder, GzipDecoder as GzipDecoderExt,
        ZlibDecoder as ZlibDecoderExt, NoiseNormalizer
    )
    from .xor_advanced import (
        RepeatingKeyXORDecoder, CribDraggerDecoder, CommonSingleByteXORDecoder, CommonKeyXORDecoder
    )
    EXTENDED_DECODERS_AVAILABLE = True
except ImportError as e:
    pass  # Extended decoders not available


__all__ = [
    # Base
    'BaseDecoder',
    'CompressionDecoder',

    # Compression
    'GzipDecoder',
    'ZlibDecoder',
    'Bzip2Decoder',
    'get_compression_decoders',

    # Base64/Hex
    'Base64Decoder',
    'HexDecoder',
    'PowerShellBase64Decoder',

    # ROT13/URL
    'ROT13Decoder',
    'URLDecoder',
    'CharCodesDecoder',

    # XOR/Encoding
    'XORDecoder',
    'MultiByteXORDecoder',
    'UTF16LEDecoder',
]


def get_all_decoders(config=None):
    """
    Get all decoders in the default execution order

    Args:
        config: DeobfuscationConfig object

    Returns:
        List of initialized decoder instances in execution order
    """
    decoders = [
        # Preprocessors (extract from JSON/JS)
        JSONExtractorDecoder(config),
        JSAtobExtractorDecoder(config),

        # String transforms
        BinaryStringDecoder(config),
        HexEscapeDecoder(config),
        UnicodeEscapeDecoder(config),
        HTMLEntityDecoder(config),

        # Standard decoders
        HexDecoder(config),
        UTF16LEDecoder(config),
        ROT13Decoder(config),
        Base64Decoder(config),
        Base64URLDecoder(config),
        PowerShellBase64Decoder(config),
        URLDecoder(config),
        CharCodesDecoder(config),
    ]

    # Add compression decoders (CRITICAL: must come early for magic byte detection)
    decoders.extend(get_compression_decoders())

    # Add extended decoders if available
    if EXTENDED_DECODERS_AVAILABLE:
        decoders.extend([
            ASCII85Decoder(config),
            Base32Decoder(config),
            Base32HexDecoder(config),
            URLPercentDecoder(config),
        ])

    # Add XOR decoders if enabled
    if config and config.xor_enabled:
        decoders.extend([
            XORDecoder(config),
            MultiByteXORDecoder(config),
        ])

        # Add advanced XOR decoders if available
        if EXTENDED_DECODERS_AVAILABLE:
            decoders.extend([
                RepeatingKeyXORDecoder(config),
                CribDraggerDecoder(config),
                CommonKeyXORDecoder(config),
            ])

    return decoders
