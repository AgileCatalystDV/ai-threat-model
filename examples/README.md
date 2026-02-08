# Example Threat Models

This directory contains example threat model files for testing and reference.

## Files

- `simple-llm-app.tm.json` - A simple LLM chat application threat model
- `agentic-system.tm.json` - An agentic research assistant system threat model

## Usage

### Analyze an example threat model

```bash
# Analyze the LLM app example
ai-threat-model analyze examples/simple-llm-app.tm.json

# Analyze the agentic system example
ai-threat-model analyze examples/agentic-system.tm.json
```

### Generate a report

```bash
# Generate markdown report
ai-threat-model report examples/simple-llm-app.tm.json --format markdown --output report.md

# Generate JSON report
ai-threat-model report examples/simple-llm-app.tm.json --format json --output report.json
```

### Visualize

```bash
# Generate Mermaid diagram
ai-threat-model visualize examples/simple-llm-app.tm.json --format mermaid --output diagram.md
```

## Expected Threats

After running `analyze`, you should see threats detected based on:

- **LLM App**: OWASP LLM Top 10 2025 threats (LLM01-LLM10)
- **Agentic System**: OWASP Agentic Top 10 2026 threats (AGENTIC01-AGENTIC10)

The example files include components and data flows that should trigger various threat detections.
