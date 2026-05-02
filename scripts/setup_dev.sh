#!/bin/bash
# setup_dev.sh - Development environment setup script

set -e

echo "🔧 Setting up secure-term-chat development environment..."

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "Python version: $PYTHON_VERSION"

if [[ $(echo "$PYTHON_VERSION" | cut -d. -f1) -lt 3 || $(echo "$PYTHON_VERSION" | cut -d. -f2) -lt 12 ]]; then
    echo "❌ Python 3.12+ is required. Current version: $PYTHON_VERSION"
    exit 1
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📦 Installing dependencies..."
pip install -e .

# Install development dependencies
echo "📦 Installing development dependencies..."
pip install pytest pytest-asyncio black flake8 mypy

# Create development directories
echo "📁 Creating development directories..."
mkdir -p logs
mkdir -p data
mkdir -p temp

# Run basic crypto tests
echo "🧪 Running crypto tests..."
python utils.py > /dev/null 2>&1 && echo "✅ Crypto tests passed" || echo "❌ Crypto tests failed"

echo "✅ Development environment setup complete!"
echo ""
echo "Next steps:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Start server: python server.py --tls"
echo "  3. Start client: python client.py localhost:12345 --room crypto --tls"
echo "  4. Run tests: python utils.py"
