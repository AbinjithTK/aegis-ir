#!/bin/bash
# SIFT Defender — Setup Script
# Run on SIFT Workstation (Ubuntu 22.04) or WSL with SIFT installed

set -e

echo "=================================================="
echo "  SIFT DEFENDER — Setup"
echo "=================================================="

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "ERROR: This script must be run on Linux (SIFT Workstation or WSL)"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>/dev/null | cut -d' ' -f2 | cut -d'.' -f1,2)
if [[ -z "$PYTHON_VERSION" ]]; then
    echo "ERROR: Python 3 not found. Install Python 3.10+"
    exit 1
fi
echo "✓ Python $PYTHON_VERSION found"

# Check for key SIFT tools
check_tool() {
    if command -v "$1" &> /dev/null; then
        echo "✓ $1 found"
    else
        echo "⚠ $1 not found (install SIFT Workstation tools)"
    fi
}

echo ""
echo "Checking SIFT tools..."
check_tool fls
check_tool icat
check_tool mmls
check_tool vol.py
check_tool rip.pl
check_tool evtx_dump
check_tool log2timeline.py

# Create virtual environment
echo ""
echo "Setting up Python environment..."
if [[ ! -d ".venv" ]]; then
    python3 -m venv .venv
    echo "✓ Virtual environment created"
fi

source .venv/bin/activate

# Install package
echo "Installing sift-defender..."
pip install -e ".[dev]" --quiet

# Create case directory
echo ""
echo "Setting up case directory..."
mkdir -p /cases/active/audit
mkdir -p /mnt/evidence
echo "✓ Case directory created at /cases/active"

# Copy .env if not exists
if [[ ! -f ".env" ]]; then
    cp .env.example .env
    echo ""
    echo "⚠ Created .env from template. Edit it with your API keys:"
    echo "   GEMINI_API_KEY — from https://aistudio.google.com/"
    echo "   ARIZE_SPACE_ID — from https://app.arize.com/ (Settings > API Keys)"
    echo "   ARIZE_API_KEY  — from https://app.arize.com/ (Settings > API Keys)"
fi

echo ""
echo "=================================================="
echo "  Setup complete!"
echo ""
echo "  Next steps:"
echo "    1. Edit .env with your API keys"
echo "    2. Mount evidence: sudo mount -o ro,loop /path/to/image.E01 /mnt/evidence"
echo "    3. Start: ./scripts/start.sh"
echo "=================================================="
