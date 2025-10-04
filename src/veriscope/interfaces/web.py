"""
Flask Web GUI Interface (Phase 3)
Lightweight local dashboard for drag-and-drop file analysis
"""

from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
import tempfile
import json
from pathlib import Path
import sys
import signal
import atexit
import os

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from veriscope.core.engine import VeriscopeEngine
from veriscope.utils.report_generator import ReportGenerator


# Initialize Flask app
app = Flask(__name__,
            template_folder='../../../templates',
            static_folder='../../../static')
app.secret_key = 'veriscope_dev_key_change_in_production'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'log', 'ps1', 'bat', 'sh', 'js', 'vbs', 'exe', 'dll', 'bin', 'dat'}

# Initialize engine
engine = VeriscopeEngine()


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    """
    Main page with file upload interface
    """
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Handle file upload and analysis
    """
    # Check if file was uploaded
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Get form parameters
    rule_name = request.form.get('rule_name', 'Suspicious_Activity')
    author = request.form.get('author', 'Veriscope')

    # Save to temporary file
    temp_file = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as tmp:
            temp_file = Path(tmp.name)
            file.save(str(temp_file))

        # Perform analysis
        result = engine.analyze_file(
            file_path=str(temp_file),
            rule_name=rule_name
        )

        # Generate markdown report
        report_gen = ReportGenerator()
        markdown_report = report_gen.generate_markdown(result, rule_name)

        # Prepare response data
        response = {
            'success': True,
            'filename': file.filename,
            'rule_name': rule_name,
            'summary': {
                'strings': len(result.strings),
                'decoded': result.deobfuscation_stats.get('successfully_decoded', 0),
                'iocs': result.iocs.total_count(),
                'techniques': len(result.attack_mapping.techniques),
                'high_entropy': len(result.analysis.high_entropy_strings)
            },
            'deobfuscation_stats': result.deobfuscation_stats,
            'deobfuscation_results': [
                {
                    'original': r.original[:100],
                    'decoded': r.deobfuscated,
                    'layers': r.layers_decoded,
                    'methods': r.methods_used,
                    'suspicious_patterns': r.suspicious_patterns
                }
                for r in result.deobfuscation_results[:20]
            ],
            'iocs': result.iocs.to_dict(),
            'analysis': result.analysis.to_dict(),
            'attack_mapping': result.attack_mapping.to_dict(),
            'yara_rule': result.yara_rule,
            'sigma_rule': result.sigma_rule,
            'yara_ioc_rules': result.yara_ioc_rules,
            'sigma_ioc_rules': result.sigma_ioc_rules,
            'markdown_report': markdown_report
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

    finally:
        # Cleanup
        if temp_file and temp_file.exists():
            temp_file.unlink()


@app.route('/quick-scan', methods=['POST'])
def quick_scan():
    """
    Quick scan endpoint for rapid triage
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    temp_file = None

    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            temp_file = Path(tmp.name)
            file.save(str(temp_file))

        # Quick scan
        result = engine.quick_scan(str(temp_file))
        result['filename'] = file.filename

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

    finally:
        if temp_file and temp_file.exists():
            temp_file.unlink()


@app.route('/techniques')
def list_techniques():
    """
    Display MITRE ATT&CK techniques reference
    """
    from veriscope.core.attack_mapper import AttackMapper

    mapper = AttackMapper()
    techniques = []

    for tech_id, (name, tactic, keywords) in mapper.technique_db.items():
        techniques.append({
            'id': tech_id,
            'name': name,
            'tactic': tactic,
            'keywords': ', '.join(keywords[:5])  # First 5 keywords
        })

    return render_template('techniques.html', techniques=sorted(techniques, key=lambda x: x['id']))


@app.route('/about')
def about():
    """
    About page with project information
    """
    return render_template('about.html')


@app.route('/generate-custom-rules', methods=['POST'])
def generate_custom_rules():
    """
    Generate YARA/Sigma rules from user-selected strings
    """
    try:
        data = request.json
        strings = data.get('strings', [])
        rule_name = data.get('rule_name', 'Custom_Selection')

        if not strings:
            return jsonify({'error': 'No strings provided'}), 400

        # Generate rules using selected strings
        yara_rule = engine.yara_generator.generate(
            rule_name=rule_name,
            strings=strings,
            iocs={},
            analysis={},
            attack_map={}
        )

        sigma_rule = engine.sigma_generator.generate(
            rule_name=rule_name,
            strings=strings,
            iocs={},
            analysis={},
            attack_map={}
        )

        return jsonify({
            'yara_rule': yara_rule,
            'sigma_rule': sigma_rule
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/generate-ioc-rules', methods=['POST'])
def generate_ioc_rules():
    """
    Generate YARA/Sigma rules from user-selected IOCs
    """
    try:
        data = request.json
        iocs = data.get('iocs', {})
        rule_name = data.get('rule_name', 'Custom_IOC')

        # Filter out empty categories
        filtered_iocs = {k: v for k, v in iocs.items() if v}

        if not filtered_iocs:
            return jsonify({'error': 'No IOCs selected'}), 400

        # Generate IOC-specific rules
        yara_rules = engine.yara_generator.generate_ioc_specific_rules(
            rule_name=rule_name,
            iocs=filtered_iocs
        )

        sigma_rules = engine.sigma_generator.generate_ioc_specific_rules(
            rule_name=rule_name,
            iocs=filtered_iocs
        )

        return jsonify({
            'yara_rules': yara_rules,
            'sigma_rules': sigma_rules
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error"""
    return jsonify({'error': 'File too large. Maximum size: 100MB'}), 413


@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    return jsonify({'error': 'Internal server error'}), 500


# Cleanup functions
def cleanup():
    """Cleanup function to run on exit"""
    print("\n[*] Shutting down Veriscope Web GUI...")
    print("[*] Cleaning up temporary files...")

    # Clean up any temporary files in /tmp
    try:
        import glob
        temp_files = glob.glob('/tmp/tmp*')
        for f in temp_files:
            try:
                if os.path.isfile(f):
                    # Only remove files older than current session
                    if os.path.getmtime(f) < os.path.getmtime(__file__):
                        continue
                    os.remove(f)
            except:
                pass
    except:
        pass

    print("[+] Cleanup complete. Goodbye!")

def signal_handler(signum, frame):
    """Handle termination signals gracefully"""
    print("\n[!] Received termination signal")
    cleanup()
    sys.exit(0)

# Register cleanup handlers
atexit.register(cleanup)
signal.signal(signal.SIGINT, signal_handler)   # Handle Ctrl+C
signal.signal(signal.SIGTERM, signal_handler)  # Handle kill command

# Run server
if __name__ == '__main__':
    print("[*] Starting Veriscope Web GUI...")
    print(f"[*] PID: {os.getpid()}")
    print("[*] Press Ctrl+C to stop")

    try:
        app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()
