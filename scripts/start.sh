#!/bin/bash
# SIFT Defender — Start the application

set -e

# Activate virtual environment
if [[ -f ".venv/bin/activate" ]]; then
    source .venv/bin/activate
fi

# Load environment variables
if [[ -f ".env" ]]; then
    export $(grep -v '^#' .env | xargs)
fi

echo ""
echo "=================================================="
echo "  SIFT DEFENDER"
echo "  Autonomous Self-Correcting Forensic Investigation Agent"
echo "=================================================="
echo ""

# Check evidence mount
if [[ -d "/mnt/evidence" ]] && [[ "$(ls -A /mnt/evidence 2>/dev/null)" ]]; then
    echo "✓ Evidence mounted at /mnt/evidence"
else
    echo "⚠ No evidence mounted at /mnt/evidence"
    echo "  Mount evidence: sudo mount -o ro,loop /path/to/image /mnt/evidence"
fi

echo ""

# Start the application
python -m sift_defender.main
