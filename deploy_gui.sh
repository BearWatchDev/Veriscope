#!/bin/bash

# Veriscope Web GUI Deployment Script
# Checks dependencies and launches the web interface

# Color codes for pretty output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Clear screen for clean presentation
clear

# Display Veriscope ASCII logo
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

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${CYAN}[*]${NC} Deployment Directory: ${BOLD}$SCRIPT_DIR${NC}"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python_version() {
    if command_exists python3; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 8 ]; then
            echo -e "${GREEN}[✓]${NC} Python $PYTHON_VERSION detected"
            return 0
        else
            echo -e "${RED}[✗]${NC} Python 3.8+ required (found $PYTHON_VERSION)"
            return 1
        fi
    else
        echo -e "${RED}[✗]${NC} Python 3 not found"
        return 1
    fi
}

# Function to check if pip is installed
check_pip() {
    if command_exists pip3; then
        echo -e "${GREEN}[✓]${NC} pip3 is installed"
        return 0
    else
        echo -e "${YELLOW}[!]${NC} pip3 not found, attempting to install..."
        return 1
    fi
}

# Function to install pip
install_pip() {
    echo -e "${CYAN}[*]${NC} Installing pip3..."
    if command_exists apt-get; then
        # Try apt without update first (in case of broken repos)
        sudo apt-get install -y python3-pip 2>/dev/null
        if [ $? -ne 0 ]; then
            # If that fails, try with update but ignore errors
            sudo apt-get update 2>/dev/null
            sudo apt-get install -y python3-pip 2>/dev/null
        fi
        if [ $? -ne 0 ]; then
            # Final fallback: use ensurepip
            echo -e "${YELLOW}[!]${NC} apt-get failed, trying Python ensurepip..."
            python3 -m ensurepip --default-pip 2>/dev/null || python3 -m ensurepip --user 2>/dev/null
        fi
    elif command_exists yum; then
        sudo yum install -y python3-pip
    elif command_exists dnf; then
        sudo dnf install -y python3-pip
    else
        # Try Python's ensurepip as fallback
        echo -e "${YELLOW}[!]${NC} No package manager found, trying Python ensurepip..."
        python3 -m ensurepip --default-pip 2>/dev/null || python3 -m ensurepip --user 2>/dev/null
    fi
}

# Function to check if Flask is installed
check_flask() {
    # Check in venv first if it exists
    if [ -f "venv/bin/python3" ]; then
        ./venv/bin/python3 -c "import flask" 2>/dev/null
        return $?
    fi

    # Check in system Python
    python3 -c "import flask" 2>/dev/null
    return $?
}

# Function to create virtual environment
create_venv() {
    echo -e "${CYAN}[*]${NC} Creating virtual environment..."

    # Check if venv directory already exists
    if [ -d "venv" ]; then
        echo -e "${GREEN}[✓]${NC} Virtual environment already exists"
        return 0
    fi

    # Try to create virtual environment
    python3 -m venv venv 2>&1 | grep -q "ensurepip is not available"
    if [ $? -eq 0 ]; then
        # ensurepip not available, install python3-venv
        echo -e "${YELLOW}[!]${NC} python3-venv package required"
        echo -e "${CYAN}[*]${NC} Installing python3-venv..."

        if command_exists apt-get; then
            sudo apt-get install -y python3-venv 2>/dev/null
        fi

        # Try creating venv again
        python3 -m venv venv 2>/dev/null
    fi

    if [ -d "venv" ] && [ -f "venv/bin/python3" ]; then
        echo -e "${GREEN}[✓]${NC} Virtual environment created"
        return 0
    else
        echo -e "${RED}[✗]${NC} Failed to create virtual environment"
        return 1
    fi
}

# Function to install Python dependencies
install_dependencies() {
    echo ""
    echo -e "${CYAN}[*]${NC} Installing Python dependencies..."
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Check for PEP 668 externally managed environment
    python3 -m pip install --help >/dev/null 2>&1
    local pip_available=$?

    if [ $pip_available -eq 0 ]; then
        # Try installing with pip, detect PEP 668 error
        local pip_output=$(python3 -m pip install flask 2>&1)
        if echo "$pip_output" | grep -q "externally-managed-environment"; then
            echo -e "${YELLOW}[!]${NC} System uses PEP 668 (externally managed environment)"
            echo -e "${CYAN}[*]${NC} Creating isolated virtual environment..."

            if ! create_venv; then
                return 1
            fi

            # Install in venv
            echo -e "${CYAN}[*]${NC} Installing packages in virtual environment..."
            ./venv/bin/pip install -q -r requirements.txt 2>/dev/null
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}[✓]${NC} Dependencies installed in virtual environment"
                return 0
            fi
        fi
    fi

    # Fallback: Try standard installation methods
    local install_success=0

    if [ -f "requirements.txt" ]; then
        # Try various methods
        pip3 install -q -r requirements.txt 2>/dev/null && install_success=1

        if [ $install_success -eq 0 ]; then
            pip3 install --user -q -r requirements.txt 2>/dev/null && install_success=1
        fi

        if [ $install_success -eq 0 ]; then
            # Last resort: create venv
            if create_venv; then
                ./venv/bin/pip install -q -r requirements.txt 2>/dev/null && install_success=1
            fi
        fi

        if [ $install_success -eq 1 ]; then
            echo -e "${GREEN}[✓]${NC} Dependencies installed successfully"
            return 0
        else
            return 1
        fi
    fi

    return 1
}

# Main deployment flow
echo -e "${BOLD}${CYAN}Step 1: Checking System Requirements${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check Python
if ! check_python_version; then
    echo -e "${RED}[✗]${NC} Python 3.8+ is required. Please install and try again."
    exit 1
fi

# Check pip
if ! check_pip; then
    install_pip
    if ! check_pip; then
        echo -e "${YELLOW}[!]${NC} pip3 installation had issues, but we can try user-level install..."
        echo -e "${CYAN}[*]${NC} Will attempt to install dependencies using alternative methods"
    else
        echo -e "${GREEN}[✓]${NC} pip3 installed successfully"
    fi
else
    # pip3 already exists, no message needed
    :
fi

echo ""
echo -e "${BOLD}${CYAN}Step 2: Checking Python Dependencies${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check Flask
if check_flask; then
    echo -e "${GREEN}[✓]${NC} Flask is already installed"
else
    echo -e "${YELLOW}[!]${NC} Flask not found, installing dependencies..."

    if ! install_dependencies; then
        echo ""
        echo -e "${RED}[✗]${NC} Automatic installation failed"
        echo ""
        echo -e "${BOLD}${YELLOW}Please install dependencies manually:${NC}"
        echo ""
        echo -e "  ${BOLD}${GREEN}✓ Recommended (system packages - easiest):${NC}"
        echo -e "    ${CYAN}sudo apt-get install python3-flask python3-yaml${NC}"
        echo ""
        echo -e "  ${BOLD}Alternative methods:${NC}"
        echo ""
        echo -e "  ${CYAN}1. Using venv (isolated):${NC}"
        echo -e "    sudo apt-get install python3-venv"
        echo -e "    python3 -m venv venv"
        echo -e "    ./venv/bin/pip install flask pyyaml"
        echo ""
        echo -e "  ${CYAN}2. With --break-system-packages flag (not recommended):${NC}"
        echo -e "    python3 -m pip install --break-system-packages flask pyyaml"
        echo ""
        echo -e "Then run: ${BOLD}${GREEN}./deploy_gui.sh${NC}"
        echo ""
        exit 1
    fi
fi

# Final check
echo ""
echo -e "${BOLD}${CYAN}Step 3: Final Verification${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if check_flask; then
    echo -e "${GREEN}[✓]${NC} All dependencies are ready"
else
    echo -e "${RED}[✗]${NC} Flask still not available. Please install manually."
    exit 1
fi

# Launch GUI
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${GREEN}🚀 Launching Veriscope Web GUI${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}[*]${NC} Server will start on: ${BOLD}${GREEN}http://localhost:5000${NC}"
echo -e "${CYAN}[*]${NC} Press ${BOLD}Ctrl+C${NC} to stop the server"
echo ""
echo -e "${MAGENTA}Features:${NC}"
echo -e "  ${GREEN}✓${NC} File upload & analysis"
echo -e "  ${GREEN}✓${NC} Automatic deobfuscation (Base64, hex, PowerShell, multi-layer)"
echo -e "  ${GREEN}✓${NC} IOC detection (URLs, IPs, domains, registry keys, crypto addresses)"
echo -e "  ${GREEN}✓${NC} MITRE ATT&CK technique mapping"
echo -e "  ${GREEN}✓${NC} YARA & Sigma rule generation"
echo -e "  ${GREEN}✓${NC} Markdown reports"
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Small delay for dramatic effect
sleep 1

# Launch the GUI (use venv if available)
if [ -f "venv/bin/python3" ]; then
    echo -e "${CYAN}[*]${NC} Using virtual environment"
    ./venv/bin/python3 src/veriscope/interfaces/web.py
else
    python3 src/veriscope/interfaces/web.py
fi
