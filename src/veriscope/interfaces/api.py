"""
FastAPI REST API Interface (Phase 2)
Programmatic access to Veriscope for automation and integration
"""

from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import tempfile
import shutil
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from veriscope.core.engine import VeriscopeEngine
from veriscope.utils.report_generator import ReportGenerator


# Initialize FastAPI app
app = FastAPI(
    title="Veriscope API",
    description="Unified IOC + ATT&CK + YARA + Sigma Detection Engine",
    version="1.4.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Veriscope engine (singleton)
engine = VeriscopeEngine()


@app.get("/")
async def root():
    """
    API root endpoint - health check and info
    """
    return {
        "service": "Veriscope API",
        "version": "1.4.0",
        "status": "operational",
        "endpoints": {
            "analyze": "/analyze",
            "quick_scan": "/quick-scan",
            "health": "/health",
            "docs": "/docs"
        }
    }


@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring
    """
    return {
        "status": "healthy",
        "service": "veriscope-api",
        "version": "1.4.0"
    }


@app.post("/analyze")
async def analyze_file(
    file: UploadFile = File(..., description="File to analyze"),
    rule_name: Optional[str] = Form("Suspicious_Activity", description="Name for generated rules"),
    author: Optional[str] = Form("Veriscope", description="Author name for rules"),
    min_string_length: Optional[int] = Form(6, description="Minimum string length"),
    entropy_threshold: Optional[float] = Form(4.5, description="Entropy threshold (0-8)"),
    include_report: Optional[bool] = Form(True, description="Include markdown report")
):
    """
    Analyze uploaded file and return comprehensive results

    Returns:
    - IOCs (URLs, IPs, domains, registry keys, etc.)
    - MITRE ATT&CK technique mappings
    - YARA detection rule
    - Sigma detection rule
    - Optional: Markdown report

    Example:
    ```bash
    curl -X POST "http://localhost:8000/analyze" \
         -F "file=@sample.txt" \
         -F "rule_name=MalwareCampaign"
    ```
    """
    # Validate file size (max 100MB)
    max_size = 100 * 1024 * 1024  # 100MB
    file_size = 0
    temp_file = None

    try:
        # Save uploaded file to temporary location
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as tmp:
            temp_file = Path(tmp.name)

            # Stream file and check size
            chunk_size = 1024 * 1024  # 1MB chunks
            while chunk := await file.read(chunk_size):
                file_size += len(chunk)
                if file_size > max_size:
                    raise HTTPException(
                        status_code=413,
                        detail="File too large. Maximum size: 100MB"
                    )
                tmp.write(chunk)

        # Initialize engine with custom parameters
        custom_engine = VeriscopeEngine(
            min_string_length=min_string_length,
            entropy_threshold=entropy_threshold,
            author=author
        )

        # Perform analysis
        result = custom_engine.analyze_file(
            file_path=str(temp_file),
            rule_name=rule_name
        )

        # Build response
        response_data = result.to_dict()

        # Add markdown report if requested
        if include_report:
            report_gen = ReportGenerator()
            markdown_report = report_gen.generate_markdown(result, rule_name)
            response_data['markdown_report'] = markdown_report

        # Add file metadata
        response_data['metadata']['original_filename'] = file.filename
        response_data['metadata']['analyzed_size'] = file_size

        return JSONResponse(content=response_data)

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )

    finally:
        # Cleanup temporary file
        if temp_file and temp_file.exists():
            temp_file.unlink()


@app.post("/quick-scan")
async def quick_scan(
    file: UploadFile = File(..., description="File to scan")
):
    """
    Quick triage scan - fast, minimal output

    Returns basic indicators for rapid assessment:
    - String count
    - IOC count
    - Presence of URLs, IPs, registry keys

    Example:
    ```bash
    curl -X POST "http://localhost:8000/quick-scan" \
         -F "file=@sample.txt"
    ```
    """
    temp_file = None

    try:
        # Save to temp file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            temp_file = Path(tmp.name)
            content = await file.read()
            tmp.write(content)

        # Quick scan
        scan_result = engine.quick_scan(str(temp_file))
        scan_result['filename'] = file.filename

        return JSONResponse(content=scan_result)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Quick scan failed: {str(e)}"
        )

    finally:
        if temp_file and temp_file.exists():
            temp_file.unlink()


@app.post("/analyze-text")
async def analyze_text(
    text: str = Form(..., description="Text content to analyze"),
    rule_name: Optional[str] = Form("Suspicious_Activity", description="Name for generated rules"),
    author: Optional[str] = Form("Veriscope", description="Author name")
):
    """
    Analyze plain text input (deobfuscated scripts, logs, etc.)

    Useful for:
    - Analyzing clipboard content
    - Processing deobfuscated code
    - Analyzing log excerpts

    Example:
    ```bash
    curl -X POST "http://localhost:8000/analyze-text" \
         -F "text=powershell -enc ..." \
         -F "rule_name=PowerShellMalware"
    ```
    """
    try:
        # Analyze text
        result = engine.analyze_text(text=text, rule_name=rule_name)

        # Build response
        response_data = result.to_dict()
        response_data['metadata']['input_type'] = 'text'
        response_data['metadata']['input_length'] = len(text)

        return JSONResponse(content=response_data)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Text analysis failed: {str(e)}"
        )


@app.get("/techniques")
async def list_techniques():
    """
    List all MITRE ATT&CK techniques in the mapping database

    Returns technique IDs, names, and tactics
    """
    from veriscope.core.attack_mapper import AttackMapper

    mapper = AttackMapper()
    techniques_list = []

    for tech_id, (name, tactic, keywords) in mapper.technique_db.items():
        techniques_list.append({
            'id': tech_id,
            'name': name,
            'tactic': tactic,
            'keyword_count': len(keywords),
            'url': f'https://attack.mitre.org/techniques/{tech_id.replace(".", "/")}'
        })

    return {
        'total_techniques': len(techniques_list),
        'techniques': sorted(techniques_list, key=lambda x: x['id'])
    }


@app.get("/technique/{technique_id}")
async def get_technique_details(technique_id: str):
    """
    Get details for a specific MITRE ATT&CK technique

    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., T1059.001)
    """
    from veriscope.core.attack_mapper import AttackMapper

    mapper = AttackMapper()
    details = mapper.get_technique_details(technique_id.upper())

    if not details:
        raise HTTPException(
            status_code=404,
            detail=f"Technique {technique_id} not found in database"
        )

    return details


# Run server with: uvicorn api:app --reload --host 0.0.0.0 --port 8000
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
