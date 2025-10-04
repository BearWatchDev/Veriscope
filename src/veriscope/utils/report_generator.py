"""
Report Generation Module
Creates human-readable Markdown reports from analysis results
"""

from datetime import datetime
from typing import Dict
from pathlib import Path


class ReportGenerator:
    """
    Generates Markdown reports from Veriscope analysis results

    Creates comprehensive, human-readable summaries including:
    - Executive summary
    - IOC lists
    - ATT&CK technique mappings
    - Suspicious indicators
    - Detection rule snippets
    """

    def __init__(self):
        """Initialize report generator"""
        pass

    def generate_markdown(self, result, rule_name: str = "Analysis") -> str:
        """
        Generate comprehensive Markdown report

        Args:
            result: VeriscopeResult object
            rule_name: Name for the analysis/campaign

        Returns:
            Markdown formatted report as string
        """
        sections = []

        # Header
        sections.append(self._generate_header(rule_name, result))

        # Executive Summary
        sections.append(self._generate_summary(result))

        # Deobfuscation Section
        if result.deobfuscation_stats.get('successfully_decoded', 0) > 0:
            sections.append(self._generate_deobfuscation_section(result))

        # IOC Section
        sections.append(self._generate_ioc_section(result.iocs))

        # Analysis Section
        sections.append(self._generate_analysis_section(result.analysis))

        # ATT&CK Mapping Section
        sections.append(self._generate_attack_section(result.attack_mapping))

        # Detection Rules Section
        sections.append(self._generate_rules_section(result))

        # String Extraction Stats
        sections.append(self._generate_stats_section(result))

        # Footer
        sections.append(self._generate_footer())

        return '\n\n'.join(sections)

    def _generate_header(self, rule_name: str, result) -> str:
        """Generate report header"""
        return f"""# Veriscope Analysis Report: {rule_name}

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Input File**: `{result.input_file}`
**File Size**: {self._format_bytes(result.file_size)}
**Analysis Tool**: Veriscope v1.0
"""

    def _generate_summary(self, result) -> str:
        """Generate executive summary"""
        ioc_count = result.iocs.total_count() if result.iocs else 0
        technique_count = len(result.attack_mapping.techniques) if result.attack_mapping else 0
        high_entropy_count = len(result.analysis.high_entropy_strings) if result.analysis else 0

        # Determine threat level
        threat_level = self._assess_threat_level(result)

        summary = f"""## Executive Summary

**Threat Level**: {threat_level}

This analysis identified:
- **{ioc_count}** Indicators of Compromise (IOCs)
- **{technique_count}** potential MITRE ATT&CK techniques
- **{high_entropy_count}** high-entropy strings (possible obfuscation)
- **{len(result.strings)}** total unique strings extracted
"""
        return summary

    def _generate_deobfuscation_section(self, result) -> str:
        """Generate deobfuscation section"""
        stats = result.deobfuscation_stats
        sections = ["## Deobfuscation Results\n"]

        sections.append(f"**Successfully Decoded**: {stats.get('successfully_decoded', 0)} strings")
        sections.append(f"**Maximum Depth**: {stats.get('max_depth', 0)} layers")
        sections.append(f"**Methods Used**: {', '.join(stats.get('methods_used', []))}")
        sections.append(f"**Suspicious Decoded Content**: {stats.get('suspicious_count', 0)} strings\n")

        # Show decoded samples
        if result.deobfuscation_results:
            sections.append("### Decoded Samples\n")

            for i, deobf in enumerate(result.deobfuscation_results[:10], 1):  # Show top 10
                sections.append(f"#### Sample {i}")
                sections.append(f"**Layers Decoded**: {deobf.layers_decoded}")
                sections.append(f"**Methods**: {', '.join(deobf.methods_used)}")

                if deobf.suspicious_patterns:
                    sections.append(f"**⚠️ Suspicious Patterns**: {', '.join(deobf.suspicious_patterns)}")

                # Show original (truncated)
                orig_display = deobf.original[:80] + '...' if len(deobf.original) > 80 else deobf.original
                sections.append(f"**Original**: `{orig_display}`")

                # Show decoded layers
                for j, decoded in enumerate(deobf.deobfuscated, 1):
                    decoded_display = decoded[:80] + '...' if len(decoded) > 80 else decoded
                    sections.append(f"**Layer {j}**: `{decoded_display}`")

                sections.append("")  # Blank line

        return '\n'.join(sections)

    def _generate_ioc_section(self, iocs) -> str:
        """Generate IOC section"""
        if not iocs:
            return "## Indicators of Compromise (IOCs)\n\nNo IOCs detected."

        sections = ["## Indicators of Compromise (IOCs)\n"]

        # URLs
        if iocs.urls:
            sections.append(f"### URLs ({len(iocs.urls)})\n")
            for url in iocs.urls[:20]:  # Limit to top 20
                sections.append(f"- `{url}`")
            if len(iocs.urls) > 20:
                sections.append(f"\n*...and {len(iocs.urls) - 20} more*")

        # IP Addresses
        if iocs.ips:
            sections.append(f"\n### IP Addresses ({len(iocs.ips)})\n")
            for ip in iocs.ips[:20]:
                sections.append(f"- `{ip}`")
            if len(iocs.ips) > 20:
                sections.append(f"\n*...and {len(iocs.ips) - 20} more*")

        # Domains
        if iocs.domains:
            sections.append(f"\n### Domains ({len(iocs.domains)})\n")
            for domain in iocs.domains[:20]:
                sections.append(f"- `{domain}`")
            if len(iocs.domains) > 20:
                sections.append(f"\n*...and {len(iocs.domains) - 20} more*")

        # Email Addresses
        if iocs.emails:
            sections.append(f"\n### Email Addresses ({len(iocs.emails)})\n")
            for email in iocs.emails:
                sections.append(f"- `{email}`")

        # Registry Keys
        if iocs.registry_keys:
            sections.append(f"\n### Registry Keys ({len(iocs.registry_keys)})\n")
            for reg_key in iocs.registry_keys[:15]:
                sections.append(f"- `{reg_key}`")
            if len(iocs.registry_keys) > 15:
                sections.append(f"\n*...and {len(iocs.registry_keys) - 15} more*")

        # Mutexes
        if iocs.mutexes:
            sections.append(f"\n### Mutexes ({len(iocs.mutexes)})\n")
            for mutex in iocs.mutexes:
                sections.append(f"- `{mutex}`")

        # File Paths
        if iocs.file_paths:
            sections.append(f"\n### File Paths ({len(iocs.file_paths)})\n")
            for path in iocs.file_paths[:15]:
                sections.append(f"- `{path}`")
            if len(iocs.file_paths) > 15:
                sections.append(f"\n*...and {len(iocs.file_paths) - 15} more*")

        # Cryptocurrency Addresses
        if iocs.crypto_addresses:
            sections.append(f"\n### Cryptocurrency Addresses ({len(iocs.crypto_addresses)})\n")
            for addr in iocs.crypto_addresses:
                sections.append(f"- `{addr}`")

        return '\n'.join(sections)

    def _generate_analysis_section(self, analysis) -> str:
        """Generate analysis section"""
        if not analysis:
            return "## Analysis Findings\n\nNo analysis performed."

        sections = ["## Analysis Findings\n"]

        # High Entropy Strings
        if analysis.high_entropy_strings:
            sections.append(f"### High-Entropy Strings ({len(analysis.high_entropy_strings)})\n")
            sections.append("*Possible obfuscation, encoding, or encryption*\n")
            for item in analysis.high_entropy_strings[:10]:
                if isinstance(item, dict):
                    string_val = item.get('string', '')
                    entropy = item.get('entropy', 0)
                else:
                    string_val, entropy = item

                # Truncate long strings
                display_str = string_val[:80] + '...' if len(string_val) > 80 else string_val
                sections.append(f"- Entropy: **{entropy}** - `{display_str}`")

        # Suspicious Keywords
        if analysis.suspicious_keywords:
            sections.append(f"\n### Suspicious Keywords ({len(analysis.suspicious_keywords)})\n")
            for keyword in analysis.suspicious_keywords[:15]:
                sections.append(f"- `{keyword}`")
            if len(analysis.suspicious_keywords) > 15:
                sections.append(f"\n*...and {len(analysis.suspicious_keywords) - 15} more*")

        # Base64 Candidates
        if analysis.base64_candidates:
            sections.append(f"\n### Possible Base64 Encoding ({len(analysis.base64_candidates)})\n")
            for b64 in analysis.base64_candidates[:5]:
                display_str = b64[:60] + '...' if len(b64) > 60 else b64
                sections.append(f"- `{display_str}`")

        # PowerShell Indicators
        if analysis.powershell_indicators:
            sections.append(f"\n### PowerShell Indicators ({len(analysis.powershell_indicators)})\n")
            for ps in analysis.powershell_indicators[:10]:
                sections.append(f"- `{ps}`")

        # Script Indicators
        if analysis.script_indicators:
            sections.append(f"\n### Script Indicators ({len(analysis.script_indicators)})\n")
            for script in analysis.script_indicators[:10]:
                sections.append(f"- `{script}`")

        return '\n'.join(sections)

    def _generate_attack_section(self, attack_map) -> str:
        """Generate MITRE ATT&CK mapping section"""
        if not attack_map or not attack_map.techniques:
            return "## MITRE ATT&CK Mapping\n\nNo ATT&CK techniques identified."

        sections = ["## MITRE ATT&CK Mapping\n"]

        # Tactics overview
        if attack_map.tactics:
            sections.append(f"**Identified Tactics**: {', '.join(sorted(attack_map.tactics))}\n")

        # Techniques table
        sections.append("### Identified Techniques\n")
        sections.append("| Technique ID | Name | Tactic | Confidence |")
        sections.append("|-------------|------|--------|------------|")

        for tech in attack_map.techniques[:15]:  # Top 15
            tech_id = tech.get('id', 'Unknown')
            name = tech.get('name', 'Unknown')
            tactic = tech.get('tactic', 'Unknown')
            confidence = attack_map.confidence_scores.get(tech_id, 0)

            # Create link to MITRE ATT&CK
            tech_link = f"[{tech_id}](https://attack.mitre.org/techniques/{tech_id.replace('.', '/')})"

            sections.append(f"| {tech_link} | {name} | {tactic} | {confidence}% |")

        if len(attack_map.techniques) > 15:
            sections.append(f"\n*...and {len(attack_map.techniques) - 15} more techniques*")

        return '\n'.join(sections)

    def _generate_rules_section(self, result) -> str:
        """Generate detection rules section"""
        sections = ["## Generated Detection Rules\n"]

        # YARA Rule snippet
        sections.append("### YARA Rule\n")
        sections.append("```yara")
        # Show first 30 lines of YARA rule
        yara_lines = result.yara_rule.split('\n')[:30]
        sections.append('\n'.join(yara_lines))
        if len(result.yara_rule.split('\n')) > 30:
            sections.append("// ... (truncated)")
        sections.append("```\n")

        # Sigma Rule snippet
        sections.append("### Sigma Rule\n")
        sections.append("```yaml")
        # Show first 30 lines of Sigma rule
        sigma_lines = result.sigma_rule.split('\n')[:30]
        sections.append('\n'.join(sigma_lines))
        if len(result.sigma_rule.split('\n')) > 30:
            sections.append("# ... (truncated)")
        sections.append("```")

        return '\n'.join(sections)

    def _generate_stats_section(self, result) -> str:
        """Generate statistics section"""
        stats = result.string_stats

        return f"""## Extraction Statistics

- **Total Strings**: {stats.get('total_count', 0)}
- **Unique Strings**: {stats.get('unique_count', 0)}
- **Average Length**: {stats.get('avg_length', 0):.1f} characters
- **Min Length**: {stats.get('min_length', 0)}
- **Max Length**: {stats.get('max_length', 0)}
"""

    def _generate_footer(self) -> str:
        """Generate report footer"""
        return f"""---

## Analysis Notes

- **YARA/Sigma Rules**: Templates requiring human review before deployment
- **ATT&CK Mappings**: Heuristic-based; not definitive
- **Confidence Scores**: Based on keyword frequency and pattern matching
- **Static Analysis**: No code execution performed

**Generated by**: Veriscope v1.0
**License**: MIT
**Purpose**: Defensive Security Operations Only

---
"""

    def _assess_threat_level(self, result) -> str:
        """Assess overall threat level"""
        score = 0

        # IOCs
        if result.iocs:
            score += result.iocs.total_count()

        # High entropy
        if result.analysis:
            score += len(result.analysis.high_entropy_strings)
            score += len(result.analysis.suspicious_keywords) * 2

        # ATT&CK techniques
        if result.attack_mapping:
            score += len(result.attack_mapping.techniques) * 3

        # Classify
        if score >= 50:
            return "🔴 **CRITICAL**"
        elif score >= 30:
            return "🟠 **HIGH**"
        elif score >= 15:
            return "🟡 **MEDIUM**"
        elif score >= 5:
            return "🔵 **LOW**"
        else:
            return "⚪ **INFORMATIONAL**"

    def _format_bytes(self, size: int) -> str:
        """Format byte size to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
