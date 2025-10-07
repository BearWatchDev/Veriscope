"""
Deobfuscation Presets
Predefined configuration sets for different malware analysis scenarios

Instead of manually tuning thresholds for each test pack, use presets that
automatically adapt to different obfuscation patterns.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ValidationThresholds:
    """Quality validation thresholds for result filtering"""
    # Final result checks
    final_min_quality: float = 0.45          # Minimum quality for final result
    final_max_null_ratio: float = 0.3        # Maximum null bytes in final result
    final_max_nonascii_ratio: float = 0.3    # Maximum non-ASCII in final result
    min_output_length: int = 4               # Minimum output length

    # Intermediate result checks (for over-decoding detection)
    intermediate_trigger_quality: float = 0.47   # If final < this, check intermediates
    intermediate_min_quality: float = 0.50       # Minimum quality for intermediate
    intermediate_min_improvement: float = 0.05   # Required improvement over final
    intermediate_max_null_ratio: float = 0.03    # Maximum null bytes in intermediate
    intermediate_max_nonascii_ratio: float = 0.05  # Maximum non-ASCII in intermediate
    intermediate_max_hex_ratio: float = 0.9      # Maximum hex digit ratio

    # Plaintext detection (no decoding needed)
    plaintext_min_quality: float = 0.3       # If input quality > this, might be plaintext


@dataclass
class DeobfuscationPreset:
    """Complete deobfuscation configuration preset"""
    name: str
    description: str

    # Core engine settings
    max_depth: int = 6
    per_string_timeout_secs: float = 2.0
    max_input_bytes: int = 1_048_576  # 1 MiB
    min_output_length: int = 2

    # XOR settings
    xor_enabled: bool = True
    xor_common_keys: List[int] = field(default_factory=lambda: [
        0x5A, 0x20, 0xFF, 0xAA, 0x01, 0x42, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAB, 0xCD, 0xEF
    ])
    xor_aggressive_bruteforce: bool = False

    # Experimental features
    speculative_rot13: bool = False

    # Validation thresholds
    thresholds: ValidationThresholds = field(default_factory=ValidationThresholds)


class PresetLibrary:
    """Library of predefined deobfuscation presets"""

    @staticmethod
    def get_preset(name: str) -> Optional[DeobfuscationPreset]:
        """Get preset by name"""
        presets = {
            "conservative": PresetLibrary.conservative(),
            "balanced": PresetLibrary.balanced(),
            "aggressive": PresetLibrary.aggressive(),
            "malware_analysis": PresetLibrary.malware_analysis(),
            "deepseek_optimized": PresetLibrary.deepseek_optimized(),
        }
        return presets.get(name.lower())

    @staticmethod
    def list_presets() -> List[str]:
        """List all available preset names"""
        return ["conservative", "balanced", "aggressive", "malware_analysis", "deepseek_optimized"]

    @staticmethod
    def conservative() -> DeobfuscationPreset:
        """
        Conservative preset: Strict validation, fewer false positives

        Use when:
        - High confidence required in results
        - Processing production threat intelligence
        - Low tolerance for false positives
        """
        thresholds = ValidationThresholds(
            final_min_quality=0.50,              # Stricter final quality
            final_max_null_ratio=0.2,            # Less tolerant of null bytes
            final_max_nonascii_ratio=0.2,        # Less tolerant of non-ASCII
            min_output_length=6,                 # Longer minimum output

            intermediate_trigger_quality=0.50,   # Only check intermediates if final is poor
            intermediate_min_quality=0.55,       # High bar for intermediates
            intermediate_min_improvement=0.10,   # Significant improvement required
            intermediate_max_null_ratio=0.01,    # Very strict on null bytes
            intermediate_max_nonascii_ratio=0.03,  # Very strict on non-ASCII
            intermediate_max_hex_ratio=0.85,     # Strict hex pattern detection

            plaintext_min_quality=0.35,
        )

        return DeobfuscationPreset(
            name="conservative",
            description="Strict validation, fewer false positives, high confidence results",
            max_depth=5,                         # Fewer layers to reduce false positives
            per_string_timeout_secs=1.5,         # Faster timeout
            xor_aggressive_bruteforce=False,     # No bruteforce
            speculative_rot13=False,             # No speculation
            thresholds=thresholds
        )

    @staticmethod
    def balanced() -> DeobfuscationPreset:
        """
        Balanced preset: Current production defaults

        Use when:
        - General malware analysis
        - Typical obfuscation patterns
        - Balanced accuracy vs coverage
        """
        thresholds = ValidationThresholds(
            final_min_quality=0.45,
            final_max_null_ratio=0.3,
            final_max_nonascii_ratio=0.3,
            min_output_length=4,

            intermediate_trigger_quality=0.47,
            intermediate_min_quality=0.50,
            intermediate_min_improvement=0.05,
            intermediate_max_null_ratio=0.03,
            intermediate_max_nonascii_ratio=0.05,
            intermediate_max_hex_ratio=0.9,

            plaintext_min_quality=0.3,
        )

        return DeobfuscationPreset(
            name="balanced",
            description="Production defaults, balanced accuracy and coverage",
            max_depth=6,
            per_string_timeout_secs=2.0,
            xor_aggressive_bruteforce=False,
            speculative_rot13=False,
            thresholds=thresholds
        )

    @staticmethod
    def aggressive() -> DeobfuscationPreset:
        """
        Aggressive preset: Loose validation, maximum coverage

        Use when:
        - Exploring unknown obfuscation patterns
        - Research and experimentation
        - Accept more false positives for better recall
        """
        thresholds = ValidationThresholds(
            final_min_quality=0.35,              # More permissive
            final_max_null_ratio=0.4,            # More tolerant of null bytes
            final_max_nonascii_ratio=0.4,        # More tolerant of non-ASCII
            min_output_length=2,                 # Shorter minimum

            intermediate_trigger_quality=0.40,   # Check intermediates more often
            intermediate_min_quality=0.45,       # Lower bar for intermediates
            intermediate_min_improvement=0.03,   # Smaller improvement needed
            intermediate_max_null_ratio=0.05,    # More permissive
            intermediate_max_nonascii_ratio=0.08,  # More permissive
            intermediate_max_hex_ratio=0.92,     # Less strict hex detection

            plaintext_min_quality=0.25,
        )

        return DeobfuscationPreset(
            name="aggressive",
            description="Loose validation, maximum coverage, more false positives",
            max_depth=8,                         # More layers
            per_string_timeout_secs=3.0,         # Longer timeout
            xor_aggressive_bruteforce=True,      # Try all XOR keys
            speculative_rot13=True,              # Try ROT13 speculatively
            thresholds=thresholds
        )

    @staticmethod
    def malware_analysis() -> DeobfuscationPreset:
        """
        Malware Analysis preset: Optimized for real-world malware samples

        Use when:
        - Analyzing actual malware specimens
        - Dealing with PowerShell/JavaScript obfuscation
        - Need comprehensive IOC extraction
        """
        thresholds = ValidationThresholds(
            final_min_quality=0.43,              # Slightly more permissive than balanced
            final_max_null_ratio=0.35,
            final_max_nonascii_ratio=0.35,
            min_output_length=3,

            intermediate_trigger_quality=0.45,
            intermediate_min_quality=0.48,
            intermediate_min_improvement=0.05,
            intermediate_max_null_ratio=0.04,
            intermediate_max_nonascii_ratio=0.06,
            intermediate_max_hex_ratio=0.88,

            plaintext_min_quality=0.28,
        )

        return DeobfuscationPreset(
            name="malware_analysis",
            description="Optimized for real-world malware with PowerShell/JS obfuscation",
            max_depth=7,                         # Deeper for complex malware
            per_string_timeout_secs=2.5,
            xor_aggressive_bruteforce=False,
            speculative_rot13=True,              # Common in malware
            thresholds=thresholds
        )

    @staticmethod
    def deepseek_optimized() -> DeobfuscationPreset:
        """
        DeepSeek Optimized preset: Tuned for DeepSeek test patterns

        Use when:
        - Testing against DeepSeek malware test pack
        - Academic/research malware samples
        - Benchmark testing
        """
        thresholds = ValidationThresholds(
            final_min_quality=0.38,              # Very permissive for test samples
            final_max_null_ratio=0.40,
            final_max_nonascii_ratio=0.40,
            min_output_length=3,

            intermediate_trigger_quality=0.42,   # Check intermediates more aggressively
            intermediate_min_quality=0.45,
            intermediate_min_improvement=0.03,   # Smaller delta to catch more cases
            intermediate_max_null_ratio=0.05,
            intermediate_max_nonascii_ratio=0.08,
            intermediate_max_hex_ratio=0.85,     # More permissive hex detection

            plaintext_min_quality=0.25,          # Very permissive for already-decoded inputs
        )

        return DeobfuscationPreset(
            name="deepseek_optimized",
            description="Tuned for DeepSeek test pack patterns and benchmarks",
            max_depth=8,                         # Deeper for complex chains
            per_string_timeout_secs=3.0,         # Longer timeout for complex patterns
            xor_aggressive_bruteforce=True,      # Try all XOR keys
            speculative_rot13=True,              # DeepSeek has ROT13/Caesar tests
            thresholds=thresholds
        )
