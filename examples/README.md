# Example Threat Models

This directory contains example threat model files for testing and reference.

## Files

### LLM Applications
- `simple-llm-app.tm.json` - A simple LLM chat application threat model
- `privacy-focused-llm-app.tm.json` - Privacy-focused LLM app with GDPR compliance and PLOT4AI framework

### Agentic Systems
- `agentic-system.tm.json` - An agentic research assistant system threat model
- `healthcare-agentic-system.tm.json` - Healthcare agentic system for patient data analysis with HIPAA/GDPR compliance
- `financial-agentic-system.tm.json` - Automated trading agent system with high-security requirements

### Multi-Agent Systems
- `multi-agent-system.tm.json` - Multi-agent system threat model
- `multi-agent-privacy-system.tm.json` - Data governance multi-agent system with privacy compliance and inter-agent communication

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

## Example Use Cases

### Healthcare Agentic System
Demonstrates:
- Agentic system threats (AGENTIC01-AGENTIC10)
- Privacy and data protection concerns
- HIPAA/GDPR compliance requirements
- Sensitive data handling (patient records)
- Unencrypted data flows (should trigger LLM06)

### Financial Agentic System
Demonstrates:
- High-risk agentic operations (automated trading)
- Excessive agency concerns (AGENTIC08)
- Tool misuse risks (AGENTIC02)
- Privilege escalation threats
- Compliance monitoring requirements

### Privacy-Focused LLM App
Demonstrates:
- PLOT4AI framework usage
- Privacy & Data Protection category threats
- Data anonymization and pseudonymization
- Consent management
- GDPR compliance features
- PII detection and redaction

### Multi-Agent Privacy System
Demonstrates:
- Multi-agent communication threats
- Inter-agent data sharing risks
- Privacy compliance across agents
- Data governance and lineage
- Access control between agents
- Audit logging for compliance

## Expected Threats

After running `analyze`, you should see threats detected based on:

- **LLM Apps**: OWASP LLM Top 10 2025 threats (LLM01-LLM10)
- **Agentic Systems**: OWASP Agentic Top 10 2026 threats (AGENTIC01-AGENTIC10)
- **Privacy Systems**: PLOT4AI threats across 8 categories (Privacy, Data Governance, etc.)
- **Multi-Agent Systems**: Multi-agent specific threats + framework-specific threats

The example files include components and data flows that should trigger various threat detections, including:
- Unencrypted sensitive data flows
- Untrusted components
- Excessive permissions
- Privacy violations
- Inter-agent communication risks
