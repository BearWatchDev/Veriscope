"""
Core Analysis Engine
Orchestrates all analysis modules and coordinates workflow
"""

from typing import Dict, Optional
from pathlib import Path
from dataclasses import dataclass, field
import json

from .extractor import StringExtractor
from .ioc_detector import IOCDetector, IOCResult
from .analyzer import EntropyAnalyzer, AnalysisResult
from .attack_mapper import AttackMapper, AttackMapping
from .yara_generator import YaraGenerator
from .sigma_generator import SigmaGenerator
from .deobfuscator import Deobfuscator, DeobfuscationResult, DeobfuscationConfig


@dataclass
class VeriscopeResult:
    """
    Complete analysis results from Veriscope engine

    Contains results from all analysis modules
    """
    # Input metadata
    input_file: str = ""
    file_size: int = 0

    # Extraction results
    strings: list = field(default_factory=list)
    string_stats: Dict = field(default_factory=dict)

    # Deobfuscation results
    deobfuscation_results: list = field(default_factory=list)
    deobfuscation_stats: Dict = field(default_factory=dict)

    # Detection results
    iocs: Optional[IOCResult] = None
    analysis: Optional[AnalysisResult] = None
    attack_mapping: Optional[AttackMapping] = None

    # Generated rules
    yara_rule: str = ""
    sigma_rule: str = ""

    # Individual IOC-specific rules
    yara_ioc_rules: Dict[str, str] = field(default_factory=dict)
    sigma_ioc_rules: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert all results to dictionary for JSON export"""
        return {
            'metadata': {
                'input_file': self.input_file,
                'file_size': self.file_size
            },
            'extraction': {
                'strings_count': len(self.strings),
                'stats': self.string_stats,
                'strings': self.strings[:100]  # Limit for JSON size
            },
            'deobfuscation': {
                'stats': self.deobfuscation_stats,
                'decoded_strings': [
                    {
                        'original': r.original[:100],
                        'decoded': r.deobfuscated,
                        'layers': r.layers_decoded,
                        'methods': r.methods_used,
                        'suspicious_patterns': r.suspicious_patterns,
                        'trace': r.trace,
                        'timed_out': r.timed_out
                    }
                    for r in self.deobfuscation_results[:20]  # Limit for JSON size
                ]
            },
            'iocs': self.iocs.to_dict() if self.iocs else {},
            'analysis': self.analysis.to_dict() if self.analysis else {},
            'attack_mapping': self.attack_mapping.to_dict() if self.attack_mapping else {},
            'rules': {
                'yara': self.yara_rule,
                'sigma': self.sigma_rule
            }
        }


class VeriscopeEngine:
    """
    Main analysis engine that coordinates all modules

    Workflow:
    1. Extract strings from input file
    2. Deobfuscate encoded strings (Base64, hex, URL encoding, etc.)
    3. Detect IOCs (URLs, IPs, registry keys, etc.) - using original + decoded strings
    4. Analyze entropy and keywords - using original + decoded strings
    5. Map to MITRE ATT&CK techniques - using original + decoded strings
    6. Generate YARA and Sigma detection rules
    7. Produce reports (including deobfuscation results)
    """

    def __init__(self,
                 min_string_length: int = 6,
                 entropy_threshold: float = 4.5,
                 author: str = "Veriscope",
                 auto_deobfuscate: bool = True,
                 deobfuscation_config: DeobfuscationConfig = None):
        """
        Initialize Veriscope engine with all modules

        Args:
            min_string_length: Minimum string length to extract
            entropy_threshold: Entropy threshold for flagging
            author: Author name for generated rules
            auto_deobfuscate: Automatically attempt to deobfuscate encoded strings
            deobfuscation_config: Configuration for deobfuscation (optional)
        """
        # Initialize all analysis modules
        self.extractor = StringExtractor(min_length=min_string_length)
        self.ioc_detector = IOCDetector()
        self.entropy_analyzer = EntropyAnalyzer(entropy_threshold=entropy_threshold)
        self.attack_mapper = AttackMapper()
        self.yara_generator = YaraGenerator(author=author)
        self.sigma_generator = SigmaGenerator(author=author)

        # Initialize deobfuscator with config
        if deobfuscation_config is None:
            deobfuscation_config = DeobfuscationConfig()
        self.deobfuscator = Deobfuscator(config=deobfuscation_config)
        self.auto_deobfuscate = auto_deobfuscate

    def analyze_file(self, file_path: str, rule_name: str = "Suspicious_Activity") -> VeriscopeResult:
        """
        Perform complete analysis on a file

        Args:
            file_path: Path to file to analyze
            rule_name: Name for generated detection rules

        Returns:
            VeriscopeResult with complete analysis
        """
        file_path = Path(file_path)
        result = VeriscopeResult()

        # Store metadata
        result.input_file = str(file_path.name)
        result.file_size = file_path.stat().st_size if file_path.exists() else 0

        # Step 1: Extract strings
        print(f"[*] Extracting strings from {file_path.name}...")
        result.strings = self.extractor.extract_from_file(file_path)
        result.string_stats = self.extractor.get_stats(result.strings)
        print(f"    Found {len(result.strings)} unique strings")

        # Step 1.5: Deobfuscate encoded strings (if enabled)
        # This step automatically decodes Base64, hex, URL encoding, PowerShell encoding, GZIP, XOR, etc.
        # Supports multi-layer decoding (e.g., XOR -> Base64 -> GZIP) up to configurable max depth
        # Decoded strings are added to the analysis pool for enhanced IOC/ATT&CK detection
        all_strings = result.strings.copy()
        if self.auto_deobfuscate:
            print(f"[*] Attempting to deobfuscate encoded strings...")

            result.deobfuscation_results = []
            seen_originals = set()  # Track original strings to avoid duplicates

            # Also try deobfuscating the entire raw file content (handles whole-file obfuscation)
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    raw_content = f.read()
                    # Only try if file isn't too large and looks potentially encoded
                    if len(raw_content) > 50 and len(raw_content) < self.deobfuscator.config.max_input_bytes:
                        raw_result = self.deobfuscator.deobfuscate_string(raw_content)
                        if raw_result.layers_decoded > 0:
                            result.deobfuscation_results.append(raw_result)
                            seen_originals.add(raw_result.original)  # Track this original
            except:
                pass

            # Batch deobfuscate all extracted strings (skip duplicates)
            for deobf_result in self.deobfuscator.deobfuscate_batch(result.strings):
                if deobf_result.original not in seen_originals:
                    result.deobfuscation_results.append(deobf_result)
                    seen_originals.add(deobf_result.original)
            result.deobfuscation_stats = self.deobfuscator.get_deobfuscation_stats(result.deobfuscation_results)

            # Add all decoded layers to the analysis pool
            # This ensures IOCs/patterns hidden in encoding are detected
            for deobf_result in result.deobfuscation_results:
                all_strings.extend(deobf_result.deobfuscated)

            # Remove duplicates while preserving unique decoded strings
            all_strings = list(set(all_strings))

            print(f"    Decoded {result.deobfuscation_stats['successfully_decoded']} encoded strings")
            print(f"    Maximum decoding depth: {result.deobfuscation_stats['max_depth']} layers")
            if result.deobfuscation_stats['suspicious_count'] > 0:
                print(f"    ⚠️  {result.deobfuscation_stats['suspicious_count']} decoded strings contain suspicious patterns")

        # Step 2: Detect IOCs (using all strings including deobfuscated)
        print(f"[*] Detecting IOCs...")
        result.iocs = self.ioc_detector.detect(all_strings)
        ioc_count = result.iocs.total_count()
        print(f"    Detected {ioc_count} indicators of compromise")

        # Step 3: Analyze entropy and keywords (using all strings)
        print(f"[*] Analyzing entropy and suspicious keywords...")
        result.analysis = self.entropy_analyzer.analyze(all_strings)
        print(f"    Found {len(result.analysis.high_entropy_strings)} high-entropy strings")
        print(f"    Found {len(result.analysis.suspicious_keywords)} suspicious keywords")

        # Step 4: Map to MITRE ATT&CK (using all strings)
        print(f"[*] Mapping to MITRE ATT&CK framework...")
        result.attack_mapping = self.attack_mapper.map_strings(
            all_strings,
            iocs=result.iocs.to_dict(),
            analysis=result.analysis.to_dict()
        )
        print(f"    Identified {len(result.attack_mapping.techniques)} potential techniques")

        # Step 5: Generate YARA rule (using all strings)
        print(f"[*] Generating YARA detection rule...")
        result.yara_rule = self.yara_generator.generate(
            rule_name=rule_name,
            strings=all_strings,
            iocs=result.iocs.to_dict(),
            analysis=result.analysis.to_dict(),
            attack_map=result.attack_mapping.to_dict()
        )

        # Step 6: Generate Sigma rule (using all strings)
        print(f"[*] Generating Sigma detection rule...")
        result.sigma_rule = self.sigma_generator.generate(
            rule_name=rule_name,
            strings=all_strings,
            iocs=result.iocs.to_dict(),
            analysis=result.analysis.to_dict(),
            attack_map=result.attack_mapping.to_dict()
        )

        # Step 7: Generate individual IOC-specific rules
        print(f"[*] Generating IOC-specific detection rules...")
        result.yara_ioc_rules = self.yara_generator.generate_ioc_specific_rules(
            rule_name=rule_name,
            iocs=result.iocs.to_dict()
        )
        result.sigma_ioc_rules = self.sigma_generator.generate_ioc_specific_rules(
            rule_name=rule_name,
            iocs=result.iocs.to_dict()
        )
        total_ioc_rules = len(result.yara_ioc_rules) + len(result.sigma_ioc_rules)
        if total_ioc_rules > 0:
            print(f"    Generated {len(result.yara_ioc_rules)} YARA and {len(result.sigma_ioc_rules)} Sigma IOC-specific rules")

        print(f"[+] Analysis complete!")
        return result

    def analyze_text(self, text: str, rule_name: str = "Suspicious_Activity") -> VeriscopeResult:
        """
        Perform analysis on plain text (deobfuscated scripts, logs, etc.)

        Args:
            text: Plain text to analyze
            rule_name: Name for generated detection rules

        Returns:
            VeriscopeResult with complete analysis
        """
        result = VeriscopeResult()
        result.input_file = "text_input"
        result.file_size = len(text)

        # Extract strings from text
        print(f"[*] Extracting strings from text...")
        result.strings = self.extractor.extract_from_text(text)
        result.string_stats = self.extractor.get_stats(result.strings)
        print(f"    Found {len(result.strings)} unique strings")

        # Detect IOCs
        print(f"[*] Detecting IOCs...")
        result.iocs = self.ioc_detector.detect(result.strings)
        print(f"    Detected {result.iocs.total_count()} indicators")

        # Analyze
        print(f"[*] Analyzing entropy and keywords...")
        result.analysis = self.entropy_analyzer.analyze(result.strings)

        # Map to ATT&CK
        print(f"[*] Mapping to MITRE ATT&CK...")
        result.attack_mapping = self.attack_mapper.map_strings(
            result.strings,
            iocs=result.iocs.to_dict(),
            analysis=result.analysis.to_dict()
        )

        # Generate rules
        print(f"[*] Generating detection rules...")
        result.yara_rule = self.yara_generator.generate(
            rule_name=rule_name,
            strings=result.strings,
            iocs=result.iocs.to_dict(),
            analysis=result.analysis.to_dict(),
            attack_map=result.attack_mapping.to_dict()
        )

        result.sigma_rule = self.sigma_generator.generate(
            rule_name=rule_name,
            strings=result.strings,
            iocs=result.iocs.to_dict(),
            analysis=result.analysis.to_dict(),
            attack_map=result.attack_mapping.to_dict()
        )

        # Generate individual IOC-specific rules
        result.yara_ioc_rules = self.yara_generator.generate_ioc_specific_rules(
            rule_name=rule_name,
            iocs=result.iocs.to_dict()
        )
        result.sigma_ioc_rules = self.sigma_generator.generate_ioc_specific_rules(
            rule_name=rule_name,
            iocs=result.iocs.to_dict()
        )

        print(f"[+] Analysis complete!")
        return result

    def export_results(self, result: VeriscopeResult, output_dir: str, base_name: str):
        """
        Export all results to files

        Args:
            result: VeriscopeResult to export
            output_dir: Directory to write output files
            base_name: Base name for output files
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Export YARA rule
        yara_file = output_path / f"{base_name}.yar"
        with open(yara_file, 'w') as f:
            f.write(result.yara_rule)
        print(f"[+] YARA rule: {yara_file}")

        # Export Sigma rule
        sigma_file = output_path / f"{base_name}.yml"
        with open(sigma_file, 'w') as f:
            f.write(result.sigma_rule)
        print(f"[+] Sigma rule: {sigma_file}")

        # Export JSON summary
        json_file = output_path / f"{base_name}.json"
        with open(json_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        print(f"[+] JSON summary: {json_file}")

    def quick_scan(self, file_path: str) -> Dict:
        """
        Quick scan for triage - returns minimal info

        Args:
            file_path: Path to file

        Returns:
            Dictionary with quick scan results
        """
        strings = self.extractor.extract_from_file(file_path)
        iocs = self.ioc_detector.detect(strings)

        return {
            'file': Path(file_path).name,
            'string_count': len(strings),
            'ioc_count': iocs.total_count(),
            'has_urls': len(iocs.urls) > 0,
            'has_ips': len(iocs.ips) > 0,
            'has_registry': len(iocs.registry_keys) > 0
        }
