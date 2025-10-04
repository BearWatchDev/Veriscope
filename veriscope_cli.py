#!/usr/bin/env python3
"""
Veriscope CLI Entry Point
Wrapper script to run Veriscope from command line without installation
"""

import sys
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

# Import and run CLI
from veriscope.cli import main

if __name__ == '__main__':
    main()
