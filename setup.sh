#!/bin/bash
# Quick setup script for SecureGuard

set -e

echo "🚀 Setting up SecureGuard..."

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "✓ Found Python $PYTHON_VERSION"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1

# Install package in development mode
echo "📥 Installing SecureGuard with all dependencies..."
pip install -e ".[dev,sensor]" > /dev/null 2>&1

echo ""
echo "✅ Setup complete!"
echo ""
echo "Quick start:"
echo "  1. Activate environment: source venv/bin/activate"
echo "  2. Run example scan: secureguard scan deps --file examples/vulnerable_requirements.txt"
echo "  3. Run tests: pytest"
echo ""
echo "📚 Read GETTING_STARTED.md for detailed instructions"
echo ""
