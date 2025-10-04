"""
Command-Line Interface (CLI) for Veriscope
Primary interface for analysts working in terminals
"""

import argparse
import sys
from pathlib import Path

from .core.engine import VeriscopeEngine
from .utils.report_generator import ReportGenerator


def main():
    """
    Main CLI entry point

    Handles argument parsing and coordinates analysis workflow
    """
    # Create argument parser
    parser = argparse.ArgumentParser(
        prog='veriscope',
        description='Veriscope - Unified IOC + ATT&CK + YARA + Sigma Detection Engine',
        epilog='For defensive security operations only. MIT License.'
    )

    # Required arguments
    parser.add_argument(
        'input',
        type=str,
        help='Input file to analyze (binary or text)'
    )

    # Optional arguments
    parser.add_argument(
        '--name',
        type=str,
        default='Suspicious_Activity',
        help='Name for generated detection rules (default: Suspicious_Activity)'
    )

    parser.add_argument(
        '--out',
        '--output',
        type=str,
        default='veriscope_output',
        help='Output directory or base name for results (default: veriscope_output)'
    )

    parser.add_argument(
        '--author',
        type=str,
        default='Veriscope',
        help='Author name for generated rules (default: Veriscope)'
    )

    parser.add_argument(
        '--min-length',
        type=int,
        default=6,
        metavar='N',
        help='Minimum string length to extract (default: 6)'
    )

    parser.add_argument(
        '--entropy-threshold',
        type=float,
        default=4.5,
        metavar='N.N',
        help='Entropy threshold for flagging (0-8, default: 4.5)'
    )

    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick scan mode (minimal output for triage)'
    )

    parser.add_argument(
        '--no-report',
        action='store_true',
        help='Skip markdown report generation'
    )

    parser.add_argument(
        '--json-only',
        action='store_true',
        help='Output JSON only (machine-readable)'
    )

    parser.add_argument(
        '-v', '--version',
        action='version',
        version='Veriscope v1.0.0'
    )

    # Parse arguments
    args = parser.parse_args()

    # Validate input file
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Print banner
    if not args.json_only:
        print_banner()

    try:
        # Initialize engine
        engine = VeriscopeEngine(
            min_string_length=args.min_length,
            entropy_threshold=args.entropy_threshold,
            author=args.author
        )

        # Quick scan mode
        if args.quick:
            print(f"\n[*] Quick scanning: {input_path.name}")
            result = engine.quick_scan(str(input_path))

            print(f"\n[+] Quick Scan Results:")
            print(f"    Strings: {result['string_count']}")
            print(f"    IOCs: {result['ioc_count']}")
            print(f"    URLs: {'Yes' if result['has_urls'] else 'No'}")
            print(f"    IPs: {'Yes' if result['has_ips'] else 'No'}")
            print(f"    Registry: {'Yes' if result['has_registry'] else 'No'}")
            sys.exit(0)

        # Full analysis
        print(f"\n[*] Starting analysis of: {input_path.name}")
        print("=" * 60)

        result = engine.analyze_file(
            file_path=str(input_path),
            rule_name=args.name
        )

        print("=" * 60)

        # Determine output directory and base name
        output_path = Path(args.out)

        # If output is a directory, use it with the rule name
        if output_path.suffix == '':
            output_dir = output_path
            base_name = args.name
        else:
            # Output is a file path - use parent dir and stem as base name
            output_dir = output_path.parent
            base_name = output_path.stem

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        # JSON output mode
        if args.json_only:
            import json
            json_output = result.to_dict()
            print(json.dumps(json_output, indent=2))
            sys.exit(0)

        # Export detection rules and JSON
        print(f"\n[*] Exporting results...")
        engine.export_results(result, str(output_dir), base_name)

        # Generate and export Markdown report
        if not args.no_report:
            report_gen = ReportGenerator()
            markdown_report = report_gen.generate_markdown(result, args.name)

            report_file = output_dir / f"{base_name}_report.md"
            with open(report_file, 'w') as f:
                f.write(markdown_report)
            print(f"[+] Markdown report: {report_file}")

        # Print summary
        print(f"\n[+] Analysis complete!")
        print(f"\n📊 Summary:")
        print(f"   Strings: {len(result.strings)}")
        print(f"   IOCs: {result.iocs.total_count()}")
        print(f"   ATT&CK Techniques: {len(result.attack_mapping.techniques)}")
        print(f"\n📁 Output directory: {output_dir.absolute()}")
        print(f"\n✅ Done! Review the generated files for actionable intelligence.")

    except KeyboardInterrupt:
        print(f"\n\n[!] Analysis interrupted by user", file=sys.stderr)
        sys.exit(130)

    except Exception as e:
        print(f"\n[!] Error during analysis: {e}", file=sys.stderr)
        if '--debug' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def print_banner():
    """Print ASCII banner"""
    banner = """
╦  ╦┌─┐┬─┐┬┌─┐┌─┐┌─┐┌─┐┌─┐
╚╗╔╝├┤ ├┬┘│└─┐│  │ │├─┘├┤
 ╚╝ └─┘┴└─┴└─┘└─┘└─┘┴  └─┘

Unified IOC + ATT&CK + YARA + Sigma Engine
Version 1.0.0 | MIT License
"""
    print(banner)


if __name__ == '__main__':
    main()
