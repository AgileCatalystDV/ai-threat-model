# Test Suite

This directory contains the test suite for AI Threat Model.

## Structure

```
tests/
├── conftest.py              # Pytest configuration and fixtures
├── test_core/               # Tests for core models
│   └── test_models.py
├── test_plugins/            # Tests for plugins
│   ├── test_llm_plugin.py
│   ├── test_agentic_plugin.py
│   └── test_registry.py
├── test_cli/                # Tests for CLI commands
│   └── test_main.py
└── test_integration/        # Integration tests
    └── test_examples.py
```

## Running Tests

### Run all tests

```bash
pytest
```

### Run with coverage

```bash
pytest --cov=ai_threat_model --cov-report=html
```

### Run specific test file

```bash
pytest tests/test_core/test_models.py
```

### Run specific test class

```bash
pytest tests/test_plugins/test_llm_plugin.py::TestLLMPlugin
```

### Run specific test

```bash
pytest tests/test_core/test_models.py::TestComponent::test_component_creation
```

### Run with verbose output

```bash
pytest -v
```

### Run with output capture disabled

```bash
pytest -s
```

## Test Categories

### Unit Tests

- **Core Models** (`test_core/`): Tests for data models, validation, serialization
- **Plugins** (`test_plugins/`): Tests for plugin functionality, threat detection
- **CLI** (`test_cli/`): Tests for command-line interface commands

### Integration Tests

- **Examples** (`test_integration/`): Tests using example threat model files

## Writing Tests

### Test Naming

- Test files: `test_*.py`
- Test classes: `Test*`
- Test functions: `test_*`

### Fixtures

Shared fixtures are defined in `conftest.py`:
- `reset_plugin_registry`: Automatically resets plugin registry before each test

### Example Test

```python
def test_component_creation():
    """Test creating a component."""
    component = Component(
        id="test",
        name="Test Component",
        type=ComponentType.LLM,
    )
    assert component.id == "test"
    assert component.name == "Test Component"
```

## Coverage Goals

- Core models: 100%
- Plugins: >90%
- CLI: >80%
- Overall: >85%

## Continuous Integration

Tests should pass before merging PRs. Run tests locally before committing:

```bash
pytest
black src/ tests/
mypy src/
```
