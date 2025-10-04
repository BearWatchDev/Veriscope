"""
MITRE ATT&CK Mapping Module
Maps keywords and IOCs to MITRE ATT&CK techniques using heuristics
"""

from typing import List, Dict, Set, Tuple
from dataclasses import dataclass, field


@dataclass
class AttackMapping:
    """Container for MITRE ATT&CK mapping results"""
    techniques: List[Dict[str, str]] = field(default_factory=list)
    tactics: Set[str] = field(default_factory=set)
    confidence_scores: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'techniques': self.techniques,
            'tactics': sorted(list(self.tactics)),
            'confidence_scores': self.confidence_scores
        }


class AttackMapper:
    """
    Maps indicators to MITRE ATT&CK framework techniques

    Uses keyword-based heuristics to identify likely techniques.
    This is NOT definitive - human analysis required for confirmation.

    Mapping structure:
    - Keywords -> Technique ID -> Tactic
    """

    def __init__(self):
        """Initialize ATT&CK mapper with keyword-to-technique mappings"""

        # Comprehensive keyword-to-technique mapping
        # Format: technique_id: (name, tactic, [keywords])
        self.technique_db = {
            # Initial Access
            'T1566': ('Phishing', 'Initial Access', [
                'phish', 'email', 'attachment', 'malicious link', 'spear'
            ]),
            'T1189': ('Drive-by Compromise', 'Initial Access', [
                'exploit kit', 'browser exploit', 'watering hole'
            ]),
            'T1190': ('Exploit Public-Facing Application', 'Initial Access', [
                'web shell', 'sql injection', 'rce', 'remote code execution'
            ]),

            # Execution
            'T1059.001': ('PowerShell', 'Execution', [
                'powershell', 'ps1', 'invoke-expression', 'iex', 'encodedcommand'
            ]),
            'T1059.003': ('Windows Command Shell', 'Execution', [
                'cmd.exe', 'command prompt', 'batch', '.bat', 'shell'
            ]),
            'T1059.005': ('Visual Basic', 'Execution', [
                'vbscript', 'vbs', 'wscript', 'cscript', 'visual basic'
            ]),
            'T1059.007': ('JavaScript', 'Execution', [
                'javascript', 'jscript', 'js', 'wscript', 'mshta'
            ]),
            'T1047': ('Windows Management Instrumentation', 'Execution', [
                'wmi', 'wmic', 'win32', 'ciminstance'
            ]),
            'T1053': ('Scheduled Task/Job', 'Execution', [
                'schtasks', 'scheduled task', 'cron', 'at.exe', 'task scheduler'
            ]),
            'T1106': ('Native API', 'Execution', [
                'createprocess', 'virtualalloc', 'writeprocessmemory', 'ntdll'
            ]),

            # Persistence
            'T1547': ('Boot or Logon Autostart Execution', 'Persistence', [
                'startup', 'run', 'runonce', 'userinit', 'winlogon', 'autorun'
            ]),
            'T1543': ('Create or Modify System Process', 'Persistence', [
                'service', 'sc.exe', 'new-service', 'driver'
            ]),
            'T1053': ('Scheduled Task/Job', 'Persistence', [
                'schtasks', 'scheduled task', 'cron'
            ]),
            'T1574': ('Hijack Execution Flow', 'Persistence', [
                'dll hijack', 'dll search order', 'dll sideload'
            ]),

            # Privilege Escalation
            'T1055': ('Process Injection', 'Privilege Escalation', [
                'inject', 'virtualalloc', 'writeprocessmemory', 'createremotethread'
            ]),
            'T1134': ('Access Token Manipulation', 'Privilege Escalation', [
                'token', 'impersonate', 'duplicatetoken', 'sedebugging'
            ]),
            'T1548': ('Abuse Elevation Control Mechanism', 'Privilege Escalation', [
                'uac bypass', 'elevate', 'admin', 'fodhelper', 'eventvwr'
            ]),

            # Defense Evasion
            'T1027': ('Obfuscated Files or Information', 'Defense Evasion', [
                'obfuscate', 'encode', 'base64', 'xor', 'encrypt', 'pack'
            ]),
            'T1070': ('Indicator Removal', 'Defense Evasion', [
                'delete log', 'clear event', 'wevtutil', 'timestomp'
            ]),
            'T1140': ('Deobfuscate/Decode Files or Information', 'Defense Evasion', [
                'decode', 'decrypt', 'frombase64', 'decompress'
            ]),
            'T1562': ('Impair Defenses', 'Defense Evasion', [
                'disable antivirus', 'defender', 'firewall', 'amsi', 'etw'
            ]),
            'T1218': ('System Binary Proxy Execution', 'Defense Evasion', [
                'rundll32', 'regsvr32', 'mshta', 'certutil', 'bitsadmin'
            ]),
            'T1497': ('Virtualization/Sandbox Evasion', 'Defense Evasion', [
                'virtual', 'vmware', 'sandbox', 'sleep', 'delay'
            ]),

            # Credential Access
            'T1003': ('OS Credential Dumping', 'Credential Access', [
                'mimikatz', 'lsass', 'sam', 'ntds', 'credential dump', 'procdump'
            ]),
            'T1056': ('Input Capture', 'Credential Access', [
                'keylog', 'keyboard', 'clipboard', 'getasynckeystate'
            ]),
            'T1555': ('Credentials from Password Stores', 'Credential Access', [
                'browser password', 'cookie', 'credential manager', 'vault'
            ]),

            # Discovery
            'T1082': ('System Information Discovery', 'Discovery', [
                'systeminfo', 'hostname', 'get-computerinfo', 'uname'
            ]),
            'T1083': ('File and Directory Discovery', 'Discovery', [
                'dir', 'ls', 'tree', 'get-childitem', 'find'
            ]),
            'T1057': ('Process Discovery', 'Discovery', [
                'tasklist', 'ps', 'get-process', 'wmi', 'process'
            ]),
            'T1018': ('Remote System Discovery', 'Discovery', [
                'net view', 'ping', 'arp', 'nslookup', 'network scan'
            ]),
            'T1033': ('System Owner/User Discovery', 'Discovery', [
                'whoami', 'query user', 'get-localuser', 'username'
            ]),
            'T1016': ('System Network Configuration Discovery', 'Discovery', [
                'ipconfig', 'ifconfig', 'netstat', 'route', 'dns'
            ]),

            # Lateral Movement
            'T1021': ('Remote Services', 'Lateral Movement', [
                'psexec', 'rdp', 'ssh', 'smb', 'wmi', 'remote desktop'
            ]),
            'T1570': ('Lateral Tool Transfer', 'Lateral Movement', [
                'copy', 'xcopy', 'robocopy', 'scp', 'ftp'
            ]),

            # Collection
            'T1560': ('Archive Collected Data', 'Collection', [
                'zip', 'rar', '7z', 'compress', 'archive', 'tar'
            ]),
            'T1113': ('Screen Capture', 'Collection', [
                'screenshot', 'printscreen', 'capture screen'
            ]),
            'T1005': ('Data from Local System', 'Collection', [
                'collect', 'gather', 'exfil', 'steal'
            ]),

            # Command and Control
            'T1071': ('Application Layer Protocol', 'Command and Control', [
                'http', 'https', 'dns', 'web request', 'beacon'
            ]),
            'T1090': ('Proxy', 'Command and Control', [
                'proxy', 'socks', 'tor', 'vpn'
            ]),
            'T1573': ('Encrypted Channel', 'Command and Control', [
                'ssl', 'tls', 'encrypt', 'aes', 'rsa'
            ]),
            'T1105': ('Ingress Tool Transfer', 'Command and Control', [
                'download', 'wget', 'curl', 'bitsadmin', 'certutil'
            ]),

            # Exfiltration
            'T1041': ('Exfiltration Over C2 Channel', 'Exfiltration', [
                'exfiltrate', 'upload', 'send data', 'post'
            ]),
            'T1048': ('Exfiltration Over Alternative Protocol', 'Exfiltration', [
                'ftp', 'dns exfil', 'icmp tunnel'
            ]),

            # Impact
            'T1486': ('Data Encrypted for Impact', 'Impact', [
                'ransomware', 'encrypt', 'ransom', 'crypto', 'cipher'
            ]),
            'T1490': ('Inhibit System Recovery', 'Impact', [
                'vssadmin', 'shadow copy', 'bcdedit', 'backup delete'
            ]),
            'T1485': ('Data Destruction', 'Impact', [
                'delete', 'wipe', 'destroy', 'format', 'erase'
            ]),
            'T1489': ('Service Stop', 'Impact', [
                'stop service', 'net stop', 'kill process'
            ]),
        }

    def map_strings(self, strings: List[str],
                   iocs: Dict = None,
                   analysis: Dict = None) -> AttackMapping:
        """
        Map strings and indicators to ATT&CK techniques

        Args:
            strings: List of extracted strings
            iocs: Optional IOC detection results
            analysis: Optional entropy/keyword analysis results

        Returns:
            AttackMapping object with identified techniques
        """
        result = AttackMapping()
        technique_matches: Dict[str, int] = {}  # technique_id -> match_count

        # Combine all text for analysis
        all_text = ' '.join(strings).lower()

        # Map based on keywords
        for technique_id, (name, tactic, keywords) in self.technique_db.items():
            match_count = 0

            for keyword in keywords:
                # Count occurrences of each keyword
                match_count += all_text.count(keyword.lower())

            if match_count > 0:
                technique_matches[technique_id] = match_count
                result.tactics.add(tactic)

        # Include additional mappings from IOCs if provided
        if iocs:
            self._map_from_iocs(iocs, technique_matches, result)

        # Include mappings from analysis if provided
        if analysis:
            self._map_from_analysis(analysis, technique_matches, result)

        # Build technique list sorted by confidence
        for technique_id, count in sorted(
            technique_matches.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            name, tactic, _ = self.technique_db[technique_id]

            result.techniques.append({
                'id': technique_id,
                'name': name,
                'tactic': tactic,
                'match_count': count
            })

            # Store confidence score (match count as proxy for confidence)
            result.confidence_scores[technique_id] = min(count * 10, 100)

        return result

    def _map_from_iocs(self, iocs: Dict, technique_matches: Dict, result: AttackMapping):
        """Map IOCs to techniques"""
        # URLs/domains suggest C2 communication
        if iocs.get('urls') or iocs.get('domains'):
            technique_matches['T1071'] = technique_matches.get('T1071', 0) + 5
            result.tactics.add('Command and Control')

        # Registry keys suggest persistence
        if iocs.get('registry_keys'):
            technique_matches['T1547'] = technique_matches.get('T1547', 0) + 3
            result.tactics.add('Persistence')

        # Mutexes suggest process synchronization (potential injection)
        if iocs.get('mutexes'):
            technique_matches['T1055'] = technique_matches.get('T1055', 0) + 2
            result.tactics.add('Privilege Escalation')

    def _map_from_analysis(self, analysis: Dict,
                          technique_matches: Dict,
                          result: AttackMapping):
        """Map analysis results to techniques"""
        # High entropy strings suggest obfuscation
        if analysis.get('high_entropy_strings'):
            technique_matches['T1027'] = technique_matches.get('T1027', 0) + 3
            result.tactics.add('Defense Evasion')

        # Base64 candidates suggest encoding
        if analysis.get('base64_candidates'):
            technique_matches['T1027'] = technique_matches.get('T1027', 0) + 2
            technique_matches['T1140'] = technique_matches.get('T1140', 0) + 2
            result.tactics.add('Defense Evasion')

        # PowerShell indicators
        if analysis.get('powershell_indicators'):
            technique_matches['T1059.001'] = technique_matches.get('T1059.001', 0) + 5
            result.tactics.add('Execution')

    def get_technique_details(self, technique_id: str) -> Dict[str, str]:
        """
        Get details for a specific technique

        Args:
            technique_id: MITRE ATT&CK technique ID

        Returns:
            Dictionary with technique details
        """
        if technique_id in self.technique_db:
            name, tactic, keywords = self.technique_db[technique_id]
            return {
                'id': technique_id,
                'name': name,
                'tactic': tactic,
                'keywords': keywords,
                'url': f'https://attack.mitre.org/techniques/{technique_id.replace(".", "/")}'
            }
        return {}
