"""
Sigma Rule Generation Module
Automatically generates Sigma detection rule templates for SIEM systems
"""

from typing import List, Dict
from datetime import datetime
import yaml
import re


class SigmaGenerator:
    """
    Generates Sigma detection rules from analysis results

    Sigma rules are log-based detection patterns compatible with:
    - Splunk
    - Elasticsearch
    - QRadar
    - ArcSight
    - And other SIEM platforms

    NOTE: Generated rules are TEMPLATES requiring human review
    """

    def __init__(self, author: str = "Veriscope"):
        """
        Initialize Sigma generator

        Args:
            author: Rule author name
        """
        self.author = author

    def generate(self, rule_name: str, strings: List[str],
                iocs: Dict = None, analysis: Dict = None,
                attack_map: Dict = None) -> str:
        """
        Generate Sigma rule from analysis results

        Args:
            rule_name: Name for the Sigma rule
            strings: Extracted strings
            iocs: IOC detection results
            analysis: Entropy/keyword analysis results
            attack_map: ATT&CK mapping results

        Returns:
            Sigma rule as YAML string
        """
        # Build rule structure
        rule = {
            'title': self._sanitize_title(rule_name),
            'id': self._generate_uuid(),
            'status': 'experimental',
            'description': self._build_description(attack_map),
            'author': self.author,
            'date': datetime.now().strftime('%Y/%m/%d'),
            'modified': datetime.now().strftime('%Y/%m/%d'),
            'tags': self._build_tags(attack_map),
            'logsource': self._build_logsource(analysis),
            'detection': self._build_detection(strings, iocs, analysis),
            'falsepositives': ['Unknown'],
            'level': self._determine_severity(iocs, analysis, attack_map)
        }

        # Add references if ATT&CK techniques found
        if attack_map and attack_map.get('techniques'):
            rule['references'] = self._build_references(attack_map)

        # Convert to YAML
        return yaml.dump(rule, sort_keys=False, default_flow_style=False)

    def _sanitize_title(self, title: str) -> str:
        """Create clean title for Sigma rule"""
        # Remove special characters but keep spaces
        title = re.sub(r'[^a-zA-Z0-9\s-]', '', title)
        return title.strip() or "Suspicious Activity Detected"

    def _generate_uuid(self) -> str:
        """Generate UUID for Sigma rule"""
        import uuid
        return str(uuid.uuid4())

    def _build_description(self, attack_map: Dict = None) -> str:
        """Build rule description"""
        desc = "Detects suspicious activity based on Veriscope analysis"

        if attack_map and attack_map.get('techniques'):
            tactics = attack_map.get('tactics', [])
            if tactics:
                desc += f". Associated tactics: {', '.join(tactics[:3])}"

        return desc

    def _build_tags(self, attack_map: Dict = None) -> List[str]:
        """Build MITRE ATT&CK tags"""
        tags = []

        if attack_map and attack_map.get('techniques'):
            for technique in attack_map['techniques'][:5]:  # Top 5
                # Sigma tag format: attack.t1234
                tech_id = technique['id'].lower()
                tags.append(f'attack.{tech_id}')

                # Add tactic tag
                tactic = technique.get('tactic', '').lower().replace(' ', '_')
                if tactic:
                    tags.append(f'attack.{tactic}')

        # Remove duplicates and sort
        return sorted(list(set(tags)))

    def _build_logsource(self, analysis: Dict = None) -> Dict:
        """Determine appropriate log source"""
        # Default to Windows process creation logs
        logsource = {
            'category': 'process_creation',
            'product': 'windows'
        }

        # Adjust based on analysis
        if analysis:
            # PowerShell indicators suggest PowerShell logs
            if analysis.get('powershell_indicators'):
                logsource = {
                    'product': 'windows',
                    'service': 'powershell'
                }
            # Script indicators suggest web server logs
            elif analysis.get('script_indicators'):
                logsource = {
                    'category': 'webserver'
                }

        return logsource

    def _build_detection(self, strings: List[str],
                        iocs: Dict = None,
                        analysis: Dict = None) -> Dict:
        """Build detection logic"""
        detection = {
            'selection': {},
            'condition': 'selection'
        }

        selection_items = {}

        # Add command line patterns for PowerShell
        if analysis and analysis.get('powershell_indicators'):
            cmdline_patterns = []
            for ps in analysis['powershell_indicators'][:5]:
                if len(ps) >= 10:
                    cmdline_patterns.append(f'*{ps}*')

            if cmdline_patterns:
                selection_items['CommandLine|contains'] = cmdline_patterns

        # Add process names from file paths
        if iocs and iocs.get('file_paths'):
            image_patterns = []
            for path in iocs['file_paths'][:5]:
                # Extract executable names
                if any(ext in path.lower() for ext in ['.exe', '.dll', '.sys']):
                    image_patterns.append(f'*{path}*')

            if image_patterns:
                selection_items['Image|contains'] = image_patterns

        # Add network indicators
        if iocs and (iocs.get('urls') or iocs.get('ips') or iocs.get('domains')):
            network_patterns = []

            for url in iocs.get('urls', [])[:3]:
                network_patterns.append(f'*{url}*')

            for ip in iocs.get('ips', [])[:3]:
                network_patterns.append(f'*{ip}*')

            for domain in iocs.get('domains', [])[:3]:
                network_patterns.append(f'*{domain}*')

            if network_patterns:
                # Use CommandLine for process_creation, or TargetObject for registry
                selection_items['CommandLine|contains'] = \
                    selection_items.get('CommandLine|contains', []) + network_patterns

        # Add registry indicators
        if iocs and iocs.get('registry_keys'):
            reg_patterns = []
            for reg in iocs['registry_keys'][:5]:
                reg_patterns.append(f'*{reg}*')

            if reg_patterns:
                # For registry events
                selection_items['TargetObject|contains'] = reg_patterns

                # Adjust logsource to registry
                detection['logsource_override'] = {
                    'category': 'registry_event',
                    'product': 'windows'
                }

        # Add suspicious keywords
        if analysis and analysis.get('suspicious_keywords'):
            keyword_patterns = []
            for keyword in analysis['suspicious_keywords'][:10]:
                if len(keyword) >= 8:
                    keyword_patterns.append(f'*{keyword}*')

            if keyword_patterns:
                selection_items['CommandLine|contains'] = \
                    selection_items.get('CommandLine|contains', []) + keyword_patterns

        # If we have multiple selection criteria, create multiple selection blocks
        if len(selection_items) > 1:
            # Split into multiple selections for OR logic
            for i, (key, value) in enumerate(selection_items.items()):
                detection[f'selection_{i+1}'] = {key: value}

            # Update condition to OR all selections
            selections = [f'selection_{i+1}' for i in range(len(selection_items))]
            detection['condition'] = ' or '.join(selections)
            del detection['selection']
        else:
            detection['selection'] = selection_items or {'CommandLine|contains': ['*suspicious*']}

        return detection

    def _build_references(self, attack_map: Dict) -> List[str]:
        """Build references to MITRE ATT&CK"""
        refs = []

        for technique in attack_map.get('techniques', [])[:5]:
            tech_id = technique['id'].replace('.', '/')
            refs.append(f'https://attack.mitre.org/techniques/{tech_id}')

        return refs

    def _determine_severity(self, iocs: Dict = None,
                           analysis: Dict = None,
                           attack_map: Dict = None) -> str:
        """
        Determine severity level based on findings

        Levels: informational, low, medium, high, critical
        """
        score = 0

        # IOC-based scoring
        if iocs:
            if iocs.get('urls'):
                score += len(iocs['urls'])
            if iocs.get('ips'):
                score += len(iocs['ips']) * 2
            if iocs.get('registry_keys'):
                score += len(iocs['registry_keys']) * 2
            if iocs.get('crypto_addresses'):
                score += len(iocs['crypto_addresses']) * 3

        # Analysis-based scoring
        if analysis:
            if analysis.get('high_entropy_strings'):
                score += len(analysis['high_entropy_strings'])
            if analysis.get('powershell_indicators'):
                score += len(analysis['powershell_indicators']) * 2
            if analysis.get('base64_candidates'):
                score += len(analysis['base64_candidates'])

        # ATT&CK-based scoring
        if attack_map:
            techniques = attack_map.get('techniques', [])
            score += len(techniques) * 2

            # High-risk tactics increase severity
            high_risk_tactics = {'Impact', 'Credential Access', 'Exfiltration'}
            if any(tactic in high_risk_tactics for tactic in attack_map.get('tactics', [])):
                score += 10

        # Map score to severity
        if score >= 30:
            return 'critical'
        elif score >= 20:
            return 'high'
        elif score >= 10:
            return 'medium'
        elif score >= 5:
            return 'low'
        else:
            return 'informational'

    def generate_network_rule(self, rule_name: str, iocs: Dict) -> str:
        """
        Generate network-focused Sigma rule

        Args:
            rule_name: Rule name
            iocs: IOC detection results (focused on network indicators)

        Returns:
            Network-focused Sigma rule as YAML string
        """
        rule = {
            'title': f'{self._sanitize_title(rule_name)} - Network Activity',
            'id': self._generate_uuid(),
            'status': 'experimental',
            'description': 'Detects network connections to suspicious destinations',
            'author': self.author,
            'date': datetime.now().strftime('%Y/%m/%d'),
            'logsource': {
                'category': 'network_connection',
                'product': 'windows'
            },
            'detection': {
                'selection': {},
                'condition': 'selection'
            },
            'falsepositives': ['Legitimate business applications'],
            'level': 'medium'
        }

        # Add network IOCs
        network_items = {}

        if iocs.get('ips'):
            network_items['DestinationIp'] = iocs['ips'][:10]

        if iocs.get('domains'):
            network_items['DestinationHostname|contains'] = \
                [f'*{d}*' for d in iocs['domains'][:10]]

        rule['detection']['selection'] = network_items or {'DestinationPort': [4444, 8080]}

        return yaml.dump(rule, sort_keys=False, default_flow_style=False)

    def generate_ioc_specific_rules(self, rule_name: str, iocs: Dict) -> Dict[str, str]:
        """
        Generate individual Sigma rules for each IOC category

        Args:
            rule_name: Base rule name
            iocs: IOC detection results

        Returns:
            Dictionary of category -> Sigma rule (YAML string)
        """
        rules = {}
        base_name = self._sanitize_title(rule_name)

        # Network-based rules
        if iocs.get('urls'):
            rules['urls'] = self._generate_url_sigma(base_name, iocs['urls'])

        if iocs.get('ips'):
            rules['ips'] = self._generate_ip_sigma(base_name, iocs['ips'])

        if iocs.get('domains'):
            rules['domains'] = self._generate_domain_sigma(base_name, iocs['domains'])

        # Windows-specific rules
        if iocs.get('registry_keys'):
            rules['registry'] = self._generate_registry_sigma(base_name, iocs['registry_keys'])

        if iocs.get('mutexes'):
            rules['mutexes'] = self._generate_mutex_sigma(base_name, iocs['mutexes'])

        if iocs.get('file_paths'):
            rules['file_paths'] = self._generate_filepath_sigma(base_name, iocs['file_paths'])

        return rules

    def _generate_url_sigma(self, base_name: str, urls: List[str]) -> str:
        """Generate Sigma rule for URL detection"""
        rule = {
            'title': f'{base_name} - URL Activity',
            'id': self._generate_uuid(),
            'status': 'experimental',
            'description': f'Detects network activity to URLs associated with {base_name}',
            'author': self.author,
            'date': datetime.now().strftime('%Y/%m/%d'),
            'logsource': {
                'category': 'proxy',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'c-uri|contains': [url for url in urls[:10]]
                },
                'condition': 'selection'
            },
            'falsepositives': ['Legitimate business traffic'],
            'level': 'high'
        }
        return yaml.dump(rule, sort_keys=False, default_flow_style=False)

    def _generate_ip_sigma(self, base_name: str, ips: List[str]) -> str:
        """Generate Sigma rule for IP detection"""
        rule = {
            'title': f'{base_name} - IP Communication',
            'id': self._generate_uuid(),
            'status': 'experimental',
            'description': f'Detects network communication to IP addresses associated with {base_name}',
            'author': self.author,
            'date': datetime.now().strftime('%Y/%m/%d'),
            'logsource': {
                'category': 'firewall',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'DestinationIp': ips[:10]
                },
                'condition': 'selection'
            },
            'falsepositives': ['Internal network communication'],
            'level': 'high'
        }
        return yaml.dump(rule, sort_keys=False, default_flow_style=False)

    def _generate_domain_sigma(self, base_name: str, domains: List[str]) -> str:
        """Generate Sigma rule for domain detection"""
        rule = {
            'title': f'{base_name} - Domain Activity',
            'id': self._generate_uuid(),
            'status': 'experimental',
            'description': f'Detects DNS queries to domains associated with {base_name}',
            'author': self.author,
            'date': datetime.now().strftime('%Y/%m/%d'),
            'logsource': {
                'category': 'dns',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'query|endswith': domains[:10]
                },
                'condition': 'selection'
            },
            'falsepositives': ['Legitimate domain access'],
            'level': 'high'
        }
        return yaml.dump(rule, sort_keys=False, default_flow_style=False)

    def _generate_registry_sigma(self, base_name: str, reg_keys: List[str]) -> str:
        """Generate Sigma rule for registry key detection"""
        rule = {
            'title': f'{base_name} - Registry Modification',
            'id': self._generate_uuid(),
            'status': 'experimental',
            'description': f'Detects registry modifications associated with {base_name}',
            'author': self.author,
            'date': datetime.now().strftime('%Y/%m/%d'),
            'logsource': {
                'category': 'registry_event',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'TargetObject|contains': reg_keys[:10]
                },
                'condition': 'selection'
            },
            'falsepositives': ['System maintenance', 'Software installation'],
            'level': 'medium'
        }
        return yaml.dump(rule, sort_keys=False, default_flow_style=False)

    def _generate_mutex_sigma(self, base_name: str, mutexes: List[str]) -> str:
        """Generate Sigma rule for mutex detection"""
        # Mutexes are typically detected via process creation events
        rule = {
            'title': f'{base_name} - Mutex Activity',
            'id': self._generate_uuid(),
            'status': 'experimental',
            'description': f'Detects mutex creation associated with {base_name}',
            'author': self.author,
            'date': datetime.now().strftime('%Y/%m/%d'),
            'logsource': {
                'category': 'process_creation',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'CommandLine|contains': mutexes[:10]
                },
                'condition': 'selection'
            },
            'falsepositives': ['Legitimate application behavior'],
            'level': 'medium'
        }
        return yaml.dump(rule, sort_keys=False, default_flow_style=False)

    def _generate_filepath_sigma(self, base_name: str, paths: List[str]) -> str:
        """Generate Sigma rule for file path detection"""
        rule = {
            'title': f'{base_name} - File Activity',
            'id': self._generate_uuid(),
            'status': 'experimental',
            'description': f'Detects file activity in paths associated with {base_name}',
            'author': self.author,
            'date': datetime.now().strftime('%Y/%m/%d'),
            'logsource': {
                'category': 'file_event',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'TargetFilename|contains': paths[:10]
                },
                'condition': 'selection'
            },
            'falsepositives': ['Legitimate software operation'],
            'level': 'medium'
        }
        return yaml.dump(rule, sort_keys=False, default_flow_style=False)
