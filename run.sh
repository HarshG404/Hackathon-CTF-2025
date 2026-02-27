#!/bin/bash

echo "=========================================="
echo "  ICSS India - CTF Web Application"
echo "=========================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"

# Check if dependencies are installed
if ! python3 -c "import flask" &> /dev/null; then
    echo ""
    echo "📦 Installing dependencies..."
    pip install -r requirements.txt
    echo ""
fi

# Create necessary directories
mkdir -p uploads backup logs

# Check if database exists
if [ ! -f icss_ctf.db ]; then
    echo "🗄️  Database not found. It will be created on first run."
fi

echo ""
echo "🚀 Starting ICSS India CTF Application..."
echo ""
echo "📍 Access the application at: http://localhost:5000"
echo "📖 Read CTF_EXPLOITATION_GUIDE.md for challenge details"
echo ""
echo "⚠️  WARNING: This application is intentionally vulnerable!"
echo "   Use only in isolated lab environments."
echo ""
echo "Press Ctrl+C to stop the server"
echo ""
echo "=========================================="
echo ""

# Run the application
python3 app.py
