#!/bin/bash
# Run Veriscope Web GUI
# Access at: http://localhost:5000

echo "🔍 Starting Veriscope Web GUI..."
echo "📍 Access at: http://localhost:5000"
echo "📊 Features: File upload, deobfuscation, IOC detection, ATT&CK mapping"
echo ""

cd "$(dirname "$0")"
python3 src/veriscope/interfaces/web.py
