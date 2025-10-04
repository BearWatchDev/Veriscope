"""
Entropy Scoring and Keyword Analysis Module
Identifies obfuscated/encoded strings and suspicious keywords
"""

import math
import re
from typing import List, Dict, Tuple, Set
from dataclasses import dataclass, field


@dataclass
class AnalysisResult:
    """Container for entropy and keyword analysis results"""
    high_entropy_strings: List[Tuple[str, float]] = field(default_factory=list)
    suspicious_keywords: List[str] = field(default_factory=list)
    base64_candidates: List[str] = field(default_factory=list)
    hex_strings: List[str] = field(default_factory=list)
    powershell_indicators: List[str] = field(default_factory=list)
    script_indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert results to dictionary"""
        return {
            'high_entropy_strings': [
                {'string': s, 'entropy': e} for s, e in self.high_entropy_strings
            ],
            'suspicious_keywords': self.suspicious_keywords,
            'base64_candidates': self.base64_candidates,
            'hex_strings': self.hex_strings,
            'powershell_indicators': self.powershell_indicators,
            'script_indicators': self.script_indicators
        }


class EntropyAnalyzer:
    """
    Analyzes strings for entropy and suspicious patterns

    High entropy may indicate:
    - Base64 encoded data
    - Encrypted/obfuscated content
    - Random strings (keys, tokens)
    - Compressed data
    """

    def __init__(self, entropy_threshold: float = 4.5):
        """
        Initialize entropy analyzer

        Args:
            entropy_threshold: Minimum entropy score (0-8) to flag (default: 4.5)
        """
        self.entropy_threshold = entropy_threshold

        # Suspicious keywords commonly found in malware
        # Categorized by threat type
        self.suspicious_keywords = {
            # Process/command execution
            'execution': {
                'powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta',
                'rundll32', 'regsvr32', 'certutil', 'bitsadmin',
                'invoke-expression', 'iex', 'downloadstring', 'downloadfile',
                'start-process', 'shell', 'exec', 'system', 'popen'
            },
            # Network/download
            'network': {
                'urldownloadtofile', 'webclient', 'httpwebrequest',
                'wget', 'curl', 'socket', 'connect', 'send', 'recv',
                'internetopen', 'internetreadfile'
            },
            # Persistence
            'persistence': {
                'schtasks', 'at.exe', 'startup', 'run', 'runonce',
                'userinit', 'winlogon', 'scheduled', 'task', 'service'
            },
            # Privilege escalation
            'privilege': {
                'uac', 'bypass', 'admin', 'elevate', 'impersonate',
                'token', 'privilege', 'sedebugging'
            },
            # Defense evasion
            'evasion': {
                'amsi', 'antivirus', 'defender', 'firewall', 'disable',
                'hidden', 'obfuscate', 'encode', 'decrypt', 'xor',
                'unhook', 'patch', 'virtualprotect'
            },
            # Credential access
            'credentials': {
                'password', 'credential', 'mimikatz', 'lsass', 'sam',
                'keylog', 'clipboard', 'browser', 'cookie'
            },
            # Discovery
            'discovery': {
                'whoami', 'ipconfig', 'netstat', 'tasklist', 'systeminfo',
                'query', 'wmi', 'get-process', 'get-service'
            },
            # Impact
            'impact': {
                'encrypt', 'ransom', 'delete', 'wipe', 'destroy',
                'format', 'cipher', 'vssadmin', 'bcdedit'
            }
        }

        # Base64 pattern (long alphanumeric strings with +/= chars)
        self.base64_pattern = re.compile(
            r'\b[A-Za-z0-9+/]{20,}={0,2}\b'
        )

        # Hex string pattern (long hex sequences)
        self.hex_pattern = re.compile(
            r'\b(?:0x)?[A-Fa-f0-9]{32,}\b'
        )

        # PowerShell specific indicators
        self.powershell_patterns = [
            re.compile(r'-(?:enc|e|encoded|command|c|w|windowstyle)', re.IGNORECASE),
            re.compile(r'(?:invoke-|iex|downloadstring)', re.IGNORECASE),
            re.compile(r'\$\w+\s*=', re.IGNORECASE),  # Variable assignment
        ]

        # Script language indicators
        self.script_patterns = [
            re.compile(r'<script[^>]*>', re.IGNORECASE),  # JavaScript
            re.compile(r'eval\s*\(', re.IGNORECASE),  # Eval function
            re.compile(r'document\.write', re.IGNORECASE),  # DOM manipulation
            re.compile(r'FromBase64String', re.IGNORECASE),  # Base64 decoding
        ]

    def calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string

        Args:
            string: Input string

        Returns:
            Entropy value (0-8 for byte data)
        """
        if not string:
            return 0.0

        # Count frequency of each character
        freq = {}
        for char in string:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        length = len(string)

        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def analyze(self, strings: List[str]) -> AnalysisResult:
        """
        Perform entropy and keyword analysis on strings

        Args:
            strings: List of strings to analyze

        Returns:
            AnalysisResult containing findings
        """
        result = AnalysisResult()

        # Sets to avoid duplicates
        high_entropy_set: Set[Tuple[str, float]] = set()
        suspicious_set: Set[str] = set()
        base64_set: Set[str] = set()
        hex_set: Set[str] = set()
        ps_set: Set[str] = set()
        script_set: Set[str] = set()

        for string in strings:
            string_lower = string.lower()

            # Calculate entropy
            entropy = self.calculate_entropy(string)
            if entropy >= self.entropy_threshold:
                high_entropy_set.add((string, round(entropy, 2)))

            # Check for suspicious keywords
            for category, keywords in self.suspicious_keywords.items():
                for keyword in keywords:
                    if keyword in string_lower:
                        suspicious_set.add(string)
                        break

            # Check for Base64 patterns
            if self.base64_pattern.search(string):
                base64_set.add(string)

            # Check for hex strings
            if self.hex_pattern.search(string):
                hex_set.add(string)

            # Check for PowerShell indicators
            for pattern in self.powershell_patterns:
                if pattern.search(string):
                    ps_set.add(string)
                    break

            # Check for script indicators
            for pattern in self.script_patterns:
                if pattern.search(string):
                    script_set.add(string)
                    break

        # Convert sets to sorted lists
        result.high_entropy_strings = sorted(
            list(high_entropy_set),
            key=lambda x: x[1],
            reverse=True  # Highest entropy first
        )
        result.suspicious_keywords = sorted(list(suspicious_set))
        result.base64_candidates = sorted(list(base64_set))
        result.hex_strings = sorted(list(hex_set))
        result.powershell_indicators = sorted(list(ps_set))
        result.script_indicators = sorted(list(script_set))

        return result

    def get_keyword_category(self, keyword: str) -> List[str]:
        """
        Get category/categories for a suspicious keyword

        Args:
            keyword: Keyword to categorize

        Returns:
            List of matching categories
        """
        keyword_lower = keyword.lower()
        categories = []

        for category, keywords in self.suspicious_keywords.items():
            if any(kw in keyword_lower for kw in keywords):
                categories.append(category)

        return categories
