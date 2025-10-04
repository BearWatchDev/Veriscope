"""
YARA Rule Generation Module
Automatically generates YARA rule templates from analysis results
"""

from typing import List, Dict, Set
from datetime import datetime
import hashlib
import re


class YaraGenerator:
    """
    Generates YARA detection rules from analysis results

    Creates rule templates with:
    - String-based signatures
    - Metadata (author, date, description)
    - Condition logic

    NOTE: Generated rules are TEMPLATES requiring human review
    """

    def __init__(self, author: str = "Veriscope", description: str = ""):
        """
        Initialize YARA generator

        Args:
            author: Rule author name
            description: Rule description
        """
        self.author = author
        self.description = description

    def generate(self, rule_name: str, strings: List[str],
                iocs: Dict = None, analysis: Dict = None,
                attack_map: Dict = None) -> str:
        """
        Generate YARA rule from analysis results

        Args:
            rule_name: Name for the YARA rule
            strings: Extracted strings
            iocs: IOC detection results
            analysis: Entropy/keyword analysis results
            attack_map: ATT&CK mapping results

        Returns:
            YARA rule as string
        """
        # Sanitize rule name (alphanumeric and underscores only)
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)

        # Build metadata section
        metadata = self._build_metadata(attack_map)

        # Build strings section
        strings_section = self._build_strings(strings, iocs, analysis)

        # Build condition section
        condition = self._build_condition(iocs, analysis)

        # Assemble complete rule
        yara_rule = f'''rule {rule_name} {{
    meta:
{metadata}

    strings:
{strings_section}

    condition:
        {condition}
}}
'''
        return yara_rule

    def _build_metadata(self, attack_map: Dict = None) -> str:
        """Build metadata section"""
        lines = []
        lines.append(f'        author = "{self.author}"')
        lines.append(f'        date = "{datetime.now().strftime("%Y-%m-%d")}"')

        if self.description:
            lines.append(f'        description = "{self.description}"')

        # Add ATT&CK techniques if available
        if attack_map and attack_map.get('techniques'):
            techniques = ', '.join([
                t['id'] for t in attack_map['techniques'][:5]  # Top 5
            ])
            lines.append(f'        mitre_attack = "{techniques}"')

        lines.append('        tlp = "AMBER"')
        lines.append('        confidence = "medium"')
        lines.append('        generated_by = "Veriscope v1.0"')

        return '\n'.join(lines)

    def _build_strings(self, strings: List[str],
                      iocs: Dict = None,
                      analysis: Dict = None) -> str:
        """Build strings section with unique signatures"""
        lines = []
        string_counter = 1
        added_strings: Set[str] = set()

        # Helper to add unique string
        def add_string(value: str, string_type: str = ""):
            nonlocal string_counter
            if value and value not in added_strings:
                # Escape special characters for YARA
                escaped = self._escape_yara_string(value)
                if escaped:
                    type_comment = f" // {string_type}" if string_type else ""
                    lines.append(f'        $s{string_counter} = "{escaped}" nocase{type_comment}')
                    added_strings.add(value)
                    string_counter += 1

        # Add IOC-based strings
        if iocs:
            # URLs (top 5)
            for url in iocs.get('urls', [])[:5]:
                add_string(url, "URL")

            # IPs (top 5)
            for ip in iocs.get('ips', [])[:5]:
                add_string(ip, "IP")

            # Domains (top 5)
            for domain in iocs.get('domains', [])[:5]:
                add_string(domain, "Domain")

            # Registry keys (top 5)
            for reg_key in iocs.get('registry_keys', [])[:5]:
                add_string(reg_key, "Registry")

            # Mutexes (top 3)
            for mutex in iocs.get('mutexes', [])[:3]:
                add_string(mutex, "Mutex")

        # Add suspicious keywords from analysis
        if analysis and analysis.get('suspicious_keywords'):
            for keyword in analysis['suspicious_keywords'][:10]:
                if len(keyword) >= 8:  # Only longer keywords
                    add_string(keyword, "Suspicious")

        # Add high-entropy strings (likely obfuscated/encoded)
        if analysis and analysis.get('high_entropy_strings'):
            for item in analysis['high_entropy_strings'][:5]:
                if isinstance(item, dict):
                    string_val = item.get('string', '')
                else:
                    string_val = item[0] if isinstance(item, tuple) else str(item)

                if len(string_val) >= 20:  # Only longer strings
                    add_string(string_val, "High entropy")

        # Add PowerShell indicators
        if analysis and analysis.get('powershell_indicators'):
            for ps_indicator in analysis['powershell_indicators'][:5]:
                if len(ps_indicator) >= 10:
                    add_string(ps_indicator, "PowerShell")

        # If no specific strings found, add some generic suspicious strings
        if not lines:
            suspicious_generics = [
                s for s in strings
                if len(s) >= 10 and any(
                    keyword in s.lower()
                    for keyword in ['http', 'download', 'exec', 'shell', 'cmd']
                )
            ]
            for generic in suspicious_generics[:10]:
                add_string(generic, "Generic")

        # If still empty, add top strings by length
        if not lines:
            sorted_strings = sorted(
                [s for s in strings if len(s) >= 12],
                key=len,
                reverse=True
            )
            for s in sorted_strings[:15]:
                add_string(s)

        return '\n'.join(lines) if lines else '        // No distinctive strings found'

    def _build_condition(self, iocs: Dict = None, analysis: Dict = None) -> str:
        """Build condition logic"""
        conditions = []

        # File size check (reasonable for most malware)
        conditions.append('filesize < 10MB')

        # String matching logic
        # Require multiple string matches for higher confidence
        conditions.append('3 of ($s*)')

        # Additional conditions based on analysis
        if analysis:
            # If PowerShell indicators found, be more strict
            if analysis.get('powershell_indicators'):
                conditions.append('// Consider adding: and pe.imphash() != ""')

        return ' and '.join(conditions)

    def _escape_yara_string(self, s: str) -> str:
        """
        Escape string for YARA rule format

        Args:
            s: Input string

        Returns:
            Escaped string safe for YARA
        """
        # Skip very short strings
        if len(s) < 4:
            return ""

        # Skip strings with too many special characters
        special_count = sum(1 for c in s if not c.isprintable())
        if special_count > len(s) * 0.3:  # More than 30% non-printable
            return ""

        # Escape special YARA characters
        s = s.replace('\\', '\\\\')  # Backslash
        s = s.replace('"', '\\"')     # Quote
        s = s.replace('\n', '\\n')    # Newline
        s = s.replace('\r', '\\r')    # Carriage return
        s = s.replace('\t', '\\t')    # Tab

        # Remove any remaining non-printable characters
        s = ''.join(c if c.isprintable() else '.' for c in s)

        # Limit length to avoid overly long rules
        if len(s) > 200:
            s = s[:200]

        return s

    def generate_hash_based_rule(self, rule_name: str,
                                 file_path: str = None,
                                 file_hash: str = None) -> str:
        """
        Generate hash-based YARA rule

        Args:
            rule_name: Rule name
            file_path: Path to file to hash
            file_hash: Pre-computed hash (SHA256)

        Returns:
            Hash-based YARA rule
        """
        # Sanitize rule name
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)

        # Calculate hash if file path provided
        if file_path and not file_hash:
            try:
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                file_hash = "UNKNOWN"

        yara_rule = f'''rule {rule_name}_hash {{
    meta:
        author = "{self.author}"
        date = "{datetime.now().strftime("%Y-%m-%d")}"
        description = "Hash-based detection for {rule_name}"
        hash_sha256 = "{file_hash}"
        tlp = "AMBER"

    condition:
        hash.sha256(0, filesize) == "{file_hash}"
}}
'''
        return yara_rule

    def generate_ioc_specific_rules(self, rule_name: str, iocs: Dict) -> Dict[str, str]:
        """
        Generate individual YARA rules for each IOC category

        Args:
            rule_name: Base rule name
            iocs: IOC detection results

        Returns:
            Dictionary of category -> YARA rule
        """
        rules = {}
        base_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)

        # URLs rule
        if iocs.get('urls'):
            rules['urls'] = self._generate_url_rule(base_name, iocs['urls'])

        # IPs rule
        if iocs.get('ips'):
            rules['ips'] = self._generate_ip_rule(base_name, iocs['ips'])

        # Domains rule
        if iocs.get('domains'):
            rules['domains'] = self._generate_domain_rule(base_name, iocs['domains'])

        # Registry keys rule
        if iocs.get('registry_keys'):
            rules['registry'] = self._generate_registry_rule(base_name, iocs['registry_keys'])

        # Mutexes rule
        if iocs.get('mutexes'):
            rules['mutexes'] = self._generate_mutex_rule(base_name, iocs['mutexes'])

        # File paths rule
        if iocs.get('file_paths'):
            rules['file_paths'] = self._generate_filepath_rule(base_name, iocs['file_paths'])

        # Crypto addresses rule
        if iocs.get('crypto_addresses'):
            rules['crypto'] = self._generate_crypto_rule(base_name, iocs['crypto_addresses'])

        return rules

    def _generate_url_rule(self, base_name: str, urls: List[str]) -> str:
        """Generate YARA rule for URLs"""
        strings = '\n'.join([
            f'        $url{i+1} = "{self._escape_yara_string(url)}" nocase'
            for i, url in enumerate(urls[:10])
        ])

        return f'''rule {base_name}_URLs {{
    meta:
        author = "{self.author}"
        date = "{datetime.now().strftime("%Y-%m-%d")}"
        description = "Detects URLs associated with {base_name}"
        ioc_type = "URL"
        tlp = "AMBER"

    strings:
{strings}

    condition:
        any of ($url*)
}}'''

    def _generate_ip_rule(self, base_name: str, ips: List[str]) -> str:
        """Generate YARA rule for IP addresses"""
        strings = '\n'.join([
            f'        $ip{i+1} = "{ip}" ascii wide'
            for i, ip in enumerate(ips[:10])
        ])

        return f'''rule {base_name}_IPs {{
    meta:
        author = "{self.author}"
        date = "{datetime.now().strftime("%Y-%m-%d")}"
        description = "Detects IP addresses associated with {base_name}"
        ioc_type = "IP"
        tlp = "AMBER"

    strings:
{strings}

    condition:
        any of ($ip*)
}}'''

    def _generate_domain_rule(self, base_name: str, domains: List[str]) -> str:
        """Generate YARA rule for domains"""
        strings = '\n'.join([
            f'        $domain{i+1} = "{domain}" nocase ascii wide'
            for i, domain in enumerate(domains[:10])
        ])

        return f'''rule {base_name}_Domains {{
    meta:
        author = "{self.author}"
        date = "{datetime.now().strftime("%Y-%m-%d")}"
        description = "Detects domains associated with {base_name}"
        ioc_type = "Domain"
        tlp = "AMBER"

    strings:
{strings}

    condition:
        any of ($domain*)
}}'''

    def _generate_registry_rule(self, base_name: str, reg_keys: List[str]) -> str:
        """Generate YARA rule for registry keys"""
        strings = '\n'.join([
            f'        $reg{i+1} = "{self._escape_yara_string(key)}" nocase'
            for i, key in enumerate(reg_keys[:10])
        ])

        return f'''rule {base_name}_Registry {{
    meta:
        author = "{self.author}"
        date = "{datetime.now().strftime("%Y-%m-%d")}"
        description = "Detects registry keys associated with {base_name}"
        ioc_type = "Registry"
        tlp = "AMBER"
        platform = "windows"

    strings:
{strings}

    condition:
        any of ($reg*)
}}'''

    def _generate_mutex_rule(self, base_name: str, mutexes: List[str]) -> str:
        """Generate YARA rule for mutexes"""
        strings = '\n'.join([
            f'        $mutex{i+1} = "{self._escape_yara_string(mutex)}" nocase'
            for i, mutex in enumerate(mutexes[:10])
        ])

        return f'''rule {base_name}_Mutexes {{
    meta:
        author = "{self.author}"
        date = "{datetime.now().strftime("%Y-%m-%d")}"
        description = "Detects mutexes associated with {base_name}"
        ioc_type = "Mutex"
        tlp = "AMBER"
        platform = "windows"

    strings:
{strings}

    condition:
        any of ($mutex*)
}}'''

    def _generate_filepath_rule(self, base_name: str, paths: List[str]) -> str:
        """Generate YARA rule for file paths"""
        strings = '\n'.join([
            f'        $path{i+1} = "{self._escape_yara_string(path)}" nocase'
            for i, path in enumerate(paths[:10])
        ])

        return f'''rule {base_name}_FilePaths {{
    meta:
        author = "{self.author}"
        date = "{datetime.now().strftime("%Y-%m-%d")}"
        description = "Detects file paths associated with {base_name}"
        ioc_type = "FilePath"
        tlp = "AMBER"

    strings:
{strings}

    condition:
        any of ($path*)
}}'''

    def _generate_crypto_rule(self, base_name: str, addresses: List[str]) -> str:
        """Generate YARA rule for crypto addresses"""
        strings = '\n'.join([
            f'        $crypto{i+1} = "{addr}" ascii wide'
            for i, addr in enumerate(addresses[:10])
        ])

        return f'''rule {base_name}_CryptoAddresses {{
    meta:
        author = "{self.author}"
        date = "{datetime.now().strftime("%Y-%m-%d")}"
        description = "Detects cryptocurrency addresses associated with {base_name}"
        ioc_type = "CryptoAddress"
        tlp = "AMBER"

    strings:
{strings}

    condition:
        any of ($crypto*)
}}'''
