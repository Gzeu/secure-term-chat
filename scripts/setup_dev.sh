#!/bin/bash
# setup_dev.sh - Development environment setup script

set -e

echo "🔧 Setting up secure-term-chat development environment..."

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "Python version: $PYTHON_VERSION"

if [[ $(echo "$PYTHON_VERSION" | cut -d. -f1) -lt 3 || $(echo "$PYTHON_VERSION" | cut -d. -f2) -lt 8 ]]; then
    echo "❌ Python 3.8+ is required. Current version: $PYTHON_VERSION"
    exit 1
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install development dependencies
echo "📦 Installing development dependencies..."
pip install -e ".[dev]"

# Install pre-commit hooks
echo "🪝 Installing pre-commit hooks..."
pre-commit install

# Create development directories
echo "📁 Creating development directories..."
mkdir -p logs
mkdir -p data
mkdir -p temp

# Set up git hooks (if in git repo)
if [ -d ".git" ]; then
    echo "🔗 Setting up git hooks..."
    cp scripts/pre-commit .git/hooks/pre-commit 2>/dev/null || true
    chmod +x .git/hooks/pre-commit 2>/dev/null || true
fi

# Create example keystore for testing
echo "🔐 Creating example keystore..."
python -c "
from keystore import AnonymousKeystore
ks = AnonymousKeystore()
if ks.create_keystore('dev_password'):
    print('✓ Example keystore created')
    identity = ks.create_identity('dev_identity')
    if identity:
        print(f'✓ Example identity created: {identity.fingerprint()[:16]}...')
    ks.lock()
else:
    print('✗ Keystore already exists')
"

# Run initial tests
echo "🧪 Running initial tests..."
python -m pytest tests/ -v --tb=short

echo "✅ Development environment setup complete!"
echo ""
echo "Next steps:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run tests: pytest"
echo " 3. Run linting: black . && isort . && flake8 ."
echo " 4. Run security checks: bandit -r . && safety check"
echo " 5. Start server: python server.py"
echo " 6. Start client: python client.py localhost:12345 --room testroom"
