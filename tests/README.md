# Test Suite

This directory contains the test suite for AI Threat Model.

## Structure

```
tests/
├── conftest.py                      # Pytest configuration and fixtures
├── test_core/                       # Tests for core models
│   └── test_models.py               # Component, DataFlow, SystemModel, Threat, ThreatModel
├── test_plugins/                    # Tests for plugins and threat detection
│   ├── test_llm_plugin.py          # LLM plugin tests
│   ├── test_agentic_plugin.py      # Agentic plugin tests
│   ├── test_multi_agent_plugin.py  # Multi-agent plugin tests
│   ├── test_registry.py            # Plugin registry tests
│   ├── test_threat_detection.py    # Enhanced threat detection utilities
│   └── test_pattern_registry.py    # Pattern registry and versioning
├── test_utils/                      # Tests for utility modules
│   └── test_logging.py             # Logging utilities and debug mode
├── test_cli/                        # Tests for CLI commands
│   ├── test_main.py                # CLI commands (init, analyze, report, validate, visualize)
│   └── test_view.py                # CLI view command tests
└── test_integration/                # Integration tests
    └── test_examples.py            # Example threat model integration tests
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

#### Core Models (`test_core/`)
- **test_models.py**: Tests for data models, validation, serialization
  - Component creation and validation
  - DataFlow validation
  - SystemModel operations
  - Threat model loading and saving
  - Risk score calculations
  - Mitigation handling

#### Plugins (`test_plugins/`)
- **test_llm_plugin.py**: LLM plugin functionality
  - Pattern loading (LLM01-LLM10)
  - Threat detection for LLM components
  - Insecure data flow detection
  - Capabilities-based threat detection
  - Untrusted component handling
  
- **test_agentic_plugin.py**: Agentic plugin functionality
  - Pattern loading (AGENTIC01-AGENTIC10)
  - Agent component threat detection
  - Tool misuse detection
  - Excessive agency detection
  - Insecure communication detection
  
- **test_multi_agent_plugin.py**: Multi-agent plugin functionality
  - Multi-agent threat patterns
  - Inter-agent communication threats
  - Agent isolation concerns

- **test_registry.py**: Plugin registry system
  - Plugin registration and discovery
  - Plugin loading and initialization

- **test_threat_detection.py**: Enhanced threat detection utilities ⭐ NEW
  - Capabilities-based pattern matching
  - Context-aware detection (trust levels, data flows)
  - Regex pattern matching
  - Data flow security analysis
  - Component matching strategies
  - Sensitive data detection

- **test_pattern_registry.py**: Pattern registry and versioning ⭐ NEW
  - Pattern registration with metadata
  - Version management
  - Dependency validation
  - Conflict detection
  - Deprecation handling
  - Directory-based pattern loading

#### Utilities (`test_utils/`)
- **test_logging.py**: Logging utilities ⭐ NEW
  - Logging setup (default, debug, custom levels)
  - Pattern load error logging
  - Threat detection activity logging
  - Debug mode functionality
  - Logger singleton pattern

#### CLI (`test_cli/`)
- **test_main.py**: CLI command tests
  - `init` command
  - `analyze` command
  - `report` command
  - `validate` command
  - `visualize` command
  
- **test_view.py**: CLI view command tests
  - Human-readable threat model display
  - Component and data flow visualization
  - Threat details display

### Integration Tests

- **test_examples.py**: Example threat model integration tests
  - Simple LLM app example
  - Agentic system example
  - Healthcare agentic system ⭐ NEW
  - Financial agentic system ⭐ NEW
  - Privacy-focused LLM app ⭐ NEW
  - Multi-agent privacy system ⭐ NEW
  - Threat detection on real examples
  - Validation of example models

## Writing Tests

### Test Naming

- Test files: `test_*.py`
- Test classes: `Test*`
- Test functions: `test_*`

### Fixtures

Shared fixtures are defined in `conftest.py`:
- `reset_plugin_registry`: Automatically resets plugin registry before each test

### Example Tests

#### Basic Component Test

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

#### Enhanced Threat Detection Test ⭐ NEW

```python
def test_pattern_matches_component_capabilities():
    """Test capabilities-based pattern matching."""
    pattern = ThreatPattern(
        id="LLM07",
        category="LLM07",
        framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
        title="Insecure Plugin Design",
        description="Test",
        detection_patterns=["execute arbitrary code", "plugin execution"],
        attack_vectors=[],
        mitigations=[],
    )
    
    component = Component(
        id="plugin1",
        name="Plugin Component",
        type=ComponentType.TOOL,
        capabilities=["execute", "plugin", "code-execution"],
    )
    
    # Should match based on capabilities
    assert pattern_matches_component(pattern, component, [], system) is True
```

#### Context-Aware Detection Test ⭐ NEW

```python
def test_matches_context_sensitive_data():
    """Test context matching for sensitive data flows."""
    pattern = ThreatPattern(
        id="LLM06",
        category="LLM06",
        framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
        title="Sensitive Information Disclosure",
        description="Test",
        detection_patterns=["sensitive information", "confidential data"],
        attack_vectors=[],
        mitigations=[],
    )
    
    component = Component(
        id="comp1",
        name="Data Processor",
        type=ComponentType.LLM,
    )
    
    system = SystemModel(
        name="Test System",
        type=SystemType.LLM_APP,
        threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
        components=[component],
        data_flows=[
            DataFlow(
                from_component="comp1",
                to_component="comp2",
                data_type="pii",
                classification=DataClassification.CONFIDENTIAL,
                encrypted=True,
            )
        ],
    )
    
    # Should match based on sensitive data flow context
    assert _matches_context(pattern, component, system) is True
```

#### Pattern Registry Test ⭐ NEW

```python
def test_register_pattern_with_metadata():
    """Test registering pattern with metadata."""
    pattern = ThreatPattern(
        id="TEST01",
        category="TEST01",
        framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
        title="Test Pattern",
        description="Test",
        detection_patterns=["test"],
        attack_vectors=["test"],
        mitigations=[],
    )
    
    metadata = PatternMetadata(
        version="1.0.0",
        author="Test Author",
        dependencies=["DEP01"],
    )
    
    registry = PatternRegistry()
    registry.register_pattern(pattern, metadata)
    
    assert registry.get_pattern("TEST01") == pattern
    assert registry.get_pattern_metadata("TEST01") == metadata
```

#### Integration Test Example ⭐ NEW

```python
def test_healthcare_system_detects_privacy_threats(examples_dir):
    """Test that healthcare system detects privacy-related threats."""
    from ai_threat_model.plugins import load_plugins
    from ai_threat_model.plugins.registry import PluginRegistry
    
    load_plugins()
    
    example_file = examples_dir / "healthcare-agentic-system.tm.json"
    threat_model = ThreatModel.load(str(example_file))
    plugin = PluginRegistry.get_plugin(threat_model.system.type)
    
    threats = plugin.detect_threats(threat_model.system)
    assert len(threats) > 0
    
    # Should detect insecure data flows (unencrypted database connections)
    insecure_flows = [
        t for t in threats
        if t.affected_data_flows and "patient-database" in str(t.affected_data_flows)
    ]
    assert len(insecure_flows) > 0
```

## Coverage Goals

- Core models: 100%
- Plugins: >90%
  - Threat detection utilities: >95% ⭐ NEW
  - Pattern registry: >90% ⭐ NEW
- Utilities: >85% ⭐ NEW
- CLI: >80%
- Integration tests: >75% ⭐ NEW
- Overall: >85% (target: 90%+)

## Test Statistics

### Test Files
- **Total test files**: 12
- **Test classes**: 20+
- **Test functions**: 150+

### Coverage by Module
- **Core models**: ~100% (Component, DataFlow, SystemModel, Threat, ThreatModel)
- **LLM Plugin**: ~95% (all patterns, detection logic)
- **Agentic Plugin**: ~95% (all patterns, detection logic)
- **Multi-Agent Plugin**: ~90%
- **Threat Detection**: ~95% ⭐ NEW (capabilities, context-aware, regex matching)
- **Pattern Registry**: ~90% ⭐ NEW (registration, versioning, validation)
- **Logging**: ~85% ⭐ NEW (setup, error logging, debug mode)
- **CLI**: ~85% (all commands covered)
- **Integration**: ~80% ⭐ NEW (all example models tested)

## Running Specific Test Suites

### Run Enhanced Threat Detection Tests ⭐ NEW

```bash
# All threat detection tests
pytest tests/test_plugins/test_threat_detection.py -v

# Specific test class
pytest tests/test_plugins/test_threat_detection.py::TestThreatDetectionUtilities -v

# Test capabilities matching
pytest tests/test_plugins/test_threat_detection.py::TestThreatDetectionUtilities::test_pattern_matches_component_capabilities -v
```

### Run Pattern Registry Tests ⭐ NEW

```bash
# All pattern registry tests
pytest tests/test_plugins/test_pattern_registry.py -v

# Test pattern registration
pytest tests/test_plugins/test_pattern_registry.py::TestPatternRegistry::test_register_pattern -v

# Test dependency validation
pytest tests/test_plugins/test_pattern_registry.py::TestPatternRegistry::test_validate_dependencies -v
```

### Run Logging Tests ⭐ NEW

```bash
# All logging tests
pytest tests/test_utils/test_logging.py -v

# Test debug mode
pytest tests/test_utils/test_logging.py::TestLoggingSetup::test_setup_logging_debug -v
```

### Run Integration Tests for Examples ⭐ NEW

```bash
# All example tests
pytest tests/test_integration/test_examples.py -v

# Test specific example
pytest tests/test_integration/test_examples.py::TestExampleThreatModels::test_healthcare_agentic_system_loads -v

# Test threat detection on examples
pytest tests/test_integration/test_examples.py::TestExampleThreatModels::test_healthcare_system_detects_privacy_threats -v
```

### Run Plugin Tests with Enhanced Detection

```bash
# LLM plugin with enhanced detection
pytest tests/test_plugins/test_llm_plugin.py::TestLLMPlugin::test_detect_threats_with_capabilities -v

# Agentic plugin with tool misuse
pytest tests/test_plugins/test_agentic_plugin.py::TestAgenticPlugin::test_detect_threats_with_tool_component -v
```

## Test Features

### Enhanced Threat Detection ⭐ NEW

The test suite now includes comprehensive tests for:

- **Capabilities-based matching**: Tests that verify threat detection based on component capabilities
- **Context-aware detection**: Tests for trust level and data flow context matching
- **Regex pattern matching**: Tests for advanced pattern matching using regex
- **Data flow analysis**: Tests for detecting insecure data flows
- **Sensitive data detection**: Tests for identifying sensitive data handling

### Pattern Registry ⭐ NEW

Tests cover:

- Pattern registration with metadata
- Version management and tracking
- Dependency validation
- Conflict detection (duplicate IDs, deprecated patterns)
- Directory-based pattern loading
- Metadata retrieval and deprecation checks

### Logging System ⭐ NEW

Tests verify:

- Logging setup with different modes (default, debug, custom levels)
- Error logging for pattern loading failures
- Debug mode threat detection logging
- Logger singleton pattern
- Log output formatting

### Integration Tests ⭐ NEW

Comprehensive tests for example threat models:

- Healthcare agentic system (privacy concerns)
- Financial agentic system (high-risk operations)
- Privacy-focused LLM app (PLOT4AI framework)
- Multi-agent privacy system (inter-agent communication)
- Threat detection verification on real-world examples

## Debugging Tests

### Run tests with debug output

```bash
# Verbose output
pytest -v

# Show print statements
pytest -s

# Stop on first failure
pytest -x

# Run last failed tests
pytest --lf

# Run with debug logging enabled
pytest --log-cli-level=DEBUG

# Run with debug mode enabled for threat detection logging
pytest --log-cli-level=DEBUG tests/test_plugins/test_threat_detection.py
```

### Test Coverage Report

After running tests with coverage, view the HTML report:

```bash
# Generate coverage report
pytest --cov=ai_threat_model --cov-report=html --cov-report=term

# View HTML report
open htmlcov/index.html  # macOS
# or
xdg-open htmlcov/index.html  # Linux
```

### Coverage by File

To see coverage for specific files:

```bash
# Coverage for threat detection
pytest --cov=ai_threat_model.plugins.ai.threat_detection --cov-report=term tests/test_plugins/test_threat_detection.py

# Coverage for pattern registry
pytest --cov=ai_threat_model.plugins.pattern_registry --cov-report=term tests/test_plugins/test_pattern_registry.py

# Coverage for logging
pytest --cov=ai_threat_model.utils.logging --cov-report=term tests/test_utils/test_logging.py
```

## Known Test Patterns

### Testing Threat Detection

When testing threat detection, use these patterns:

1. **Component-based**: Create components with specific types and capabilities
   ```python
   component = Component(
       id="comp1",
       name="Component",
       type=ComponentType.LLM,
       capabilities=["execute", "plugin"],
   )
   ```

2. **Data flow-based**: Create data flows with different classifications and encryption
   ```python
   data_flow = DataFlow(
       from_component="comp1",
       to_component="comp2",
       classification=DataClassification.CONFIDENTIAL,
       encrypted=False,  # Should trigger threat
   )
   ```

3. **Context-based**: Combine components and data flows to test context-aware detection
   ```python
   system = SystemModel(
       components=[component],
       data_flows=[data_flow],
       ...
   )
   ```

4. **Pattern matching**: Test various detection patterns (name, type, capabilities, context)
   ```python
   pattern = ThreatPattern(
       detection_patterns=["execute", "untrusted"],
       ...
   )
   ```

### Testing Pattern Registry

Pattern registry tests follow these patterns:

1. **Registration**: Register patterns with and without metadata
2. **Retrieval**: Get patterns by ID, framework, or all
3. **Validation**: Validate dependencies and conflicts
4. **Loading**: Load patterns from directories with error handling

### Testing Logging

Logging tests verify:

1. **Setup**: Different logging configurations
2. **Output**: Log messages are correctly formatted
3. **Debug mode**: Debug messages only appear in debug mode
4. **Error handling**: Errors are logged appropriately

## Continuous Integration

Tests should pass before merging PRs. Run tests locally before committing:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=ai_threat_model --cov-report=html --cov-report=term

# Format code
black src/ tests/

# Type checking
mypy src/

# Linting
pylint src/
```

## Test Maintenance

### Adding New Tests

When adding new features, follow these guidelines:

1. **Test file naming**: Use `test_<module_name>.py` format
2. **Test class naming**: Use `Test<ClassName>` format
3. **Test function naming**: Use `test_<feature_name>` format
4. **Documentation**: Add docstrings explaining what is tested
5. **Coverage**: Aim for >90% coverage for new code

### Test Organization

- **Unit tests**: Test individual functions and classes in isolation
- **Integration tests**: Test interactions between components
- **Example tests**: Test with real-world example threat models

### Common Test Patterns

- Use fixtures from `conftest.py` for shared setup
- Use `pytest.mark.parametrize` for testing multiple scenarios
- Use `pytest.skip()` for conditional test execution
- Use `pytest.raises()` for testing exceptions
