#!/bin/bash

# Veriscope Quick Start
# Simple one-command deployment for Ubuntu/Debian systems

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

clear

echo -e "${CYAN}"
cat << "EOF"
╦  ╦┌─┐┬─┐┬┌─┐┌─┐┌─┐┌─┐┌─┐
╚╗╔╝├┤ ├┬┘│└─┐│  │ │├─┘├┤
 ╚╝ └─┘┴└─┴└─┘└─┘└─┘┴  └─┘
EOF
echo -e "${NC}"
echo -e "${BOLD}${MAGENTA}Malware Analysis & Detection Intelligence${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if Flask is installed
python3 -c "import flask" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[!]${NC} Flask not installed"
    echo -e "${CYAN}[*]${NC} Installing system packages..."
    echo ""

    sudo apt-get update -qq 2>/dev/null
    sudo apt-get install -y python3-flask python3-yaml

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓]${NC} Dependencies installed successfully"
    else
        echo -e "${RED}[✗]${NC} Installation failed"
        echo ""
        echo -e "${YELLOW}Please run manually:${NC}"
        echo -e "  sudo apt-get install python3-flask python3-yaml"
        exit 1
    fi
else
    echo -e "${GREEN}[✓]${NC} Flask is installed"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${GREEN}🚀 Starting Veriscope Web GUI${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}[*]${NC} Server: ${BOLD}${GREEN}http://localhost:5000${NC}"
echo -e "${CYAN}[*]${NC} Press ${BOLD}Ctrl+C${NC} to stop"
echo ""
echo -e "${MAGENTA}Features:${NC}"
echo -e "  ${GREEN}✓${NC} File upload & analysis"
echo -e "  ${GREEN}✓${NC} Automatic deobfuscation (Base64, hex, PowerShell, multi-layer)"
echo -e "  ${GREEN}✓${NC} IOC detection (URLs, IPs, domains, registry keys, crypto)"
echo -e "  ${GREEN}✓${NC} MITRE ATT&CK mapping (60+ techniques)"
echo -e "  ${GREEN}✓${NC} YARA & Sigma rule generation"
echo -e "  ${GREEN}✓${NC} Markdown reports"
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Change to script directory
cd "$(dirname "$0")"

# Cleanup function
cleanup() {
    echo ""
    echo -e "${CYAN}[*]${NC} Stopping Veriscope..."

    # Kill any remaining Flask processes
    pkill -f "python3.*web.py" 2>/dev/null

    # Kill child processes
    jobs -p | xargs -r kill 2>/dev/null

    echo -e "${GREEN}[✓]${NC} Cleanup complete"
    exit 0
}

# Trap signals
trap cleanup SIGINT SIGTERM EXIT

# Launch GUI
python3 src/veriscope/interfaces/web.py

# Ensure cleanup runs
cleanup
