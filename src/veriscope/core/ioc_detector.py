"""
IOC (Indicator of Compromise) Detection Module
Identifies URLs, IPs, emails, registry keys, mutexes, and file paths
"""

import re
from typing import List, Dict, Set
from dataclasses import dataclass, field


@dataclass
class IOCResult:
    """Container for detected IOCs"""
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    mutexes: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    crypto_addresses: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, List[str]]:
        """Convert IOC results to dictionary"""
        return {
            'urls': self.urls,
            'ips': self.ips,
            'emails': self.emails,
            'domains': self.domains,
            'registry_keys': self.registry_keys,
            'mutexes': self.mutexes,
            'file_paths': self.file_paths,
            'crypto_addresses': self.crypto_addresses
        }

    def total_count(self) -> int:
        """Get total number of IOCs detected"""
        return (len(self.urls) + len(self.ips) + len(self.emails) +
                len(self.domains) + len(self.registry_keys) +
                len(self.mutexes) + len(self.file_paths) +
                len(self.crypto_addresses))


class IOCDetector:
    """
    Detects various indicators of compromise from extracted strings

    Uses regex patterns to identify:
    - URLs (http/https/ftp)
    - IP addresses (IPv4)
    - Email addresses
    - Domain names
    - Windows registry keys
    - Mutex names
    - File paths (Windows and Unix)
    - Cryptocurrency addresses (Bitcoin, Ethereum)
    """

    def __init__(self):
        """Initialize IOC detector with regex patterns"""

        # IPv4 pattern (basic, not strict validation)
        self.ip_pattern = re.compile(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        )

        # Email pattern
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )

        # URL pattern (http, https, ftp)
        self.url_pattern = re.compile(
            r'(?:https?|ftp)://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )

        # Domain pattern (must have TLD)
        self.domain_pattern = re.compile(
            r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            re.IGNORECASE
        )

        # Windows registry key pattern
        self.registry_pattern = re.compile(
            r'\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s<>"]+',
            re.IGNORECASE
        )

        # Windows file path pattern
        self.win_path_pattern = re.compile(
            r'\b[A-Za-z]:\\(?:[^\s<>"|?*]+\\)*[^\s<>"|?*]+',
        )

        # Unix file path pattern (absolute paths)
        self.unix_path_pattern = re.compile(
            r'(?:^|[\s])(/[^\s<>"|?*]+(?:/[^\s<>"|?*]+)+)',
        )

        # Mutex pattern (common naming conventions)
        # Often contains "Mutex", "Global\", "Local\", or GUID-like strings
        self.mutex_pattern = re.compile(
            r'(?:Global\\|Local\\)[^\s\\]+|'
            r'\b[A-Za-z0-9_-]*(?:Mutex|mutex|MUTEX)[A-Za-z0-9_-]*\b',
        )

        # Bitcoin address pattern (simplified)
        self.bitcoin_pattern = re.compile(
            r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|'
            r'\bbc1[a-z0-9]{39,59}\b'
        )

        # Ethereum address pattern
        self.ethereum_pattern = re.compile(
            r'\b0x[a-fA-F0-9]{40}\b'
        )

    def detect(self, strings: List[str]) -> IOCResult:
        """
        Detect IOCs from list of strings

        Args:
            strings: List of extracted strings to analyze

        Returns:
            IOCResult object containing categorized IOCs
        """
        result = IOCResult()

        # Use sets to avoid duplicates
        urls_set: Set[str] = set()
        ips_set: Set[str] = set()
        emails_set: Set[str] = set()
        domains_set: Set[str] = set()
        registry_set: Set[str] = set()
        mutexes_set: Set[str] = set()
        file_paths_set: Set[str] = set()
        crypto_set: Set[str] = set()

        for string in strings:
            # URLs (check first, as they may contain IPs/domains)
            url_matches = self.url_pattern.findall(string)
            urls_set.update(url_matches)

            # IP addresses
            ip_matches = self.ip_pattern.findall(string)
            # Filter out invalid IPs (e.g., 999.999.999.999)
            for ip in ip_matches:
                octets = ip.split('.')
                if all(0 <= int(octet) <= 255 for octet in octets):
                    ips_set.add(ip)

            # Emails
            email_matches = self.email_pattern.findall(string)
            emails_set.update(email_matches)

            # Domains (exclude IPs and emails)
            domain_matches = self.domain_pattern.findall(string)
            for domain in domain_matches:
                # Skip if it's part of an email or IP
                if domain not in string.split('@')[-1]:  # Not part of email
                    # Skip common non-domain patterns
                    if not re.match(r'^\d+\.\d+$', domain):  # Not version number
                        domains_set.add(domain)

            # Windows registry keys
            registry_matches = self.registry_pattern.findall(string)
            registry_set.update(registry_matches)

            # Mutex names
            mutex_matches = self.mutex_pattern.findall(string)
            mutexes_set.update(mutex_matches)

            # Windows file paths
            win_path_matches = self.win_path_pattern.findall(string)
            file_paths_set.update(win_path_matches)

            # Unix file paths
            unix_path_matches = self.unix_path_pattern.findall(string)
            file_paths_set.update(unix_path_matches)

            # Cryptocurrency addresses
            btc_matches = self.bitcoin_pattern.findall(string)
            crypto_set.update(btc_matches)

            eth_matches = self.ethereum_pattern.findall(string)
            crypto_set.update(eth_matches)

        # Convert sets to sorted lists for consistent output
        result.urls = sorted(list(urls_set))
        result.ips = sorted(list(ips_set))
        result.emails = sorted(list(emails_set))
        result.domains = sorted(list(domains_set))
        result.registry_keys = sorted(list(registry_set))
        result.mutexes = sorted(list(mutexes_set))
        result.file_paths = sorted(list(file_paths_set))
        result.crypto_addresses = sorted(list(crypto_set))

        return result

    def filter_false_positives(self, iocs: IOCResult,
                               exclude_private_ips: bool = False) -> IOCResult:
        """
        Filter common false positives from IOC results

        Args:
            iocs: IOCResult object to filter
            exclude_private_ips: Remove private/local IP addresses

        Returns:
            Filtered IOCResult object
        """
        filtered = IOCResult()

        # Filter IPs
        if exclude_private_ips:
            # Remove private IP ranges
            filtered.ips = [
                ip for ip in iocs.ips
                if not self._is_private_ip(ip)
            ]
        else:
            filtered.ips = iocs.ips

        # Filter domains - remove common legitimate domains
        common_legitimate = {
            'microsoft.com', 'windows.com', 'apple.com',
            'google.com', 'mozilla.org', 'example.com'
        }
        filtered.domains = [
            d for d in iocs.domains
            if d.lower() not in common_legitimate
        ]

        # Copy other fields as-is
        filtered.urls = iocs.urls
        filtered.emails = iocs.emails
        filtered.registry_keys = iocs.registry_keys
        filtered.mutexes = iocs.mutexes
        filtered.file_paths = iocs.file_paths
        filtered.crypto_addresses = iocs.crypto_addresses

        return filtered

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        octets = [int(x) for x in ip.split('.')]

        # Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        # Loopback: 127.0.0.0/8
        if octets[0] == 10:
            return True
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        if octets[0] == 192 and octets[1] == 168:
            return True
        if octets[0] == 127:
            return True

        return False
