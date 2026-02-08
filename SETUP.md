# Development Setup Guide

This guide will help you set up the development environment for AI Threat Model.

## Prerequisites

- Python 3.9 or higher
- pip (usually comes with Python)

## Quick Setup

### Option 1: Automated Setup (Recommended)

Run the setup script:

```bash
./setup_dev.sh
```

This will:
1. Check Python version
2. Create a virtual environment (`venv`)
3. Install all dependencies
4. Install the package in development mode

### Option 2: Manual Setup

```bash
# 1. Create virtual environment
python3 -m venv venv

# 2. Activate virtual environment
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate  # On Windows

# 3. Upgrade pip
pip install --upgrade pip setuptools wheel

# 4. Install dependencies
pip install -r requirements-dev.txt

# 5. Install package in development mode
pip install -e .
```

## Activating the Virtual Environment

After setup, activate the virtual environment:

```bash
source venv/bin/activate  # On macOS/Linux
```

You should see `(venv)` in your terminal prompt.

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=ai_threat_model --cov-report=html

# Run specific test file
pytest tests/test_core/test_models.py

# Run specific test
pytest tests/test_plugins/test_llm_plugin.py::TestLLMPlugin::test_detect_threats_with_llm_component
```

## Using the CLI

After installation, you can use the CLI:

```bash
# Initialize a new threat model
ai-threat-model init my-app --type llm-app

# Analyze a threat model
ai-threat-model analyze my-app.tm.json

# Generate a report
ai-threat-model report my-app.tm.json --format markdown

# Validate a threat model
ai-threat-model validate my-app.tm.json
```

## Development Tools

### Code Formatting

```bash
black src/ tests/
```

### Type Checking

```bash
mypy src/
```

### Linting

```bash
pylint src/
# or
ruff check src/
```

## Troubleshooting

### "pip: command not found"

Make sure Python 3 is installed and in your PATH:
```bash
python3 --version
python3 -m pip --version
```

If pip is not available, install it:
```bash
python3 -m ensurepip --upgrade
```

### "pytest: command not found"

Make sure the virtual environment is activated and dependencies are installed:
```bash
source venv/bin/activate
pip install -r requirements-dev.txt
```

### Virtual Environment Issues

If you encounter issues with the virtual environment:

```bash
# Remove and recreate
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .
```

## Next Steps

- Read [tests/README.md](tests/README.md) for testing guidelines
- Check [MR_DATA.md](MR_DATA.md) for project context
- See [README.md](README.md) for project overview
