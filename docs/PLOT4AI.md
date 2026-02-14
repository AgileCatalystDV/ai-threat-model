# PLOT4AI Integration Guide

## Overview

PLOT4AI (Practical Library Of Threats 4 Artificial Intelligence) is integrated into AI Threat Model as an additional framework layer, providing a holistic approach to AI threat modeling beyond just security.

## What is PLOT4AI?

PLOT4AI is a threat modeling library created by Isabel Barberá that provides:

- **138 threats** organized into 8 categories
- **6 lifecycle phases** (Design, Input, Model, Output, Deploy, Monitor)
- **Card-based methodology** with elicitation questions
- **Holistic approach** covering security, privacy, ethics, bias, transparency, and more

### PLOT4AI Categories

1. **Data & Data Governance** - Data quality, integrity, lineage, and management
2. **Transparency & Accessibility** - Explainability, accessibility, and user understanding
3. **Privacy & Data Protection** - Personal data protection and privacy compliance
4. **Cybersecurity** - Security threats and vulnerabilities
5. **Safety & Environmental Impact** - Safety hazards and environmental concerns
6. **Bias, Fairness & Discrimination** - Bias detection and fairness issues
7. **Ethics & Human Rights** - Ethical considerations and human rights impact
8. **Accountability & Human Oversight** - Responsibility and oversight mechanisms

## How PLOT4AI Differs from OWASP Frameworks

| Aspect | OWASP LLM Top 10 | PLOT4AI |
|--------|------------------|---------|
| **Focus** | Security vulnerabilities | Holistic risk management |
| **Scope** | Security threats | Security + Privacy + Ethics + Bias + Transparency |
| **Methodology** | Pattern matching | Elicitation questions |
| **Lifecycle** | Not phase-specific | Mapped to 6 lifecycle phases |
| **Regulatory** | Security-focused | EU AI Act, GDPR aligned |

**PLOT4AI complements OWASP frameworks** - they work together:
- Use OWASP for security-focused threat detection
- Use PLOT4AI for comprehensive risk assessment including privacy, ethics, and compliance

## Using PLOT4AI

### Initialize Threat Model with PLOT4AI

```bash
ai-threat-model init my-ai-app --type llm-app --framework plot4ai
```

### Basic Analysis

```bash
# Analyze with all PLOT4AI threats
ai-threat-model analyze my-ai-app.tm.json
```

### Lifecycle Phase Filtering

Filter threats by AI lifecycle phase:

```bash
# Design phase threats
ai-threat-model analyze my-ai-app.tm.json --lifecycle-phase Design

# Input phase threats
ai-threat-model analyze my-ai-app.tm.json --lifecycle-phase Input

# Model phase threats
ai-threat-model analyze my-ai-app.tm.json --lifecycle-phase Model

# Output phase threats
ai-threat-model analyze my-ai-app.tm.json --lifecycle-phase Output

# Deploy phase threats
ai-threat-model analyze my-ai-app.tm.json --lifecycle-phase Deploy

# Monitor phase threats
ai-threat-model analyze my-ai-app.tm.json --lifecycle-phase Monitor
```

### Category Filtering

Focus on specific threat categories:

```bash
# Privacy threats only
ai-threat-model analyze my-ai-app.tm.json --category "Privacy & Data Protection"

# Bias and fairness threats
ai-threat-model analyze my-ai-app.tm.json --category "Bias, Fairness & Discrimination"

# Cybersecurity threats
ai-threat-model analyze my-ai-app.tm.json --category "Cybersecurity"
```

### AI Type Filtering

Filter by AI type (Traditional or Generative):

```bash
# Traditional AI threats
ai-threat-model analyze my-ai-app.tm.json --aitype Traditional

# Generative AI threats
ai-threat-model analyze my-ai-app.tm.json --aitype Generative
```

### Interactive Elicitation Questions

Use interactive mode to answer PLOT4AI elicitation questions:

```bash
ai-threat-model analyze my-ai-app.tm.json --interactive
```

This will:
1. Present each threat as a question
2. Ask you to answer Yes/No/Maybe
3. Only include threats where your answer indicates a risk
4. Save answers for future analysis

**Example interaction:**
```
Question: Is our data complete, up-to-date, and trustworthy?
Label: Data Quality
Threat if: No

Your answer (Yes/No/Maybe/Skip): No
```

### Combining Filters

You can combine multiple filters:

```bash
# Design phase privacy threats for generative AI
ai-threat-model analyze my-ai-app.tm.json \
  --lifecycle-phase Design \
  --category "Privacy & Data Protection" \
  --aitype Generative \
  --interactive
```

## PLOT4AI Threat Structure

Each PLOT4AI threat includes:

- **Question**: Elicitation question to determine if threat applies
- **Threatif**: Condition when threat is applicable (Yes/No)
- **Label**: Short name for the threat
- **Explanation**: Detailed explanation of the threat
- **Recommendation**: Mitigation strategies (markdown formatted)
- **Categories**: One or more PLOT4AI categories
- **Phases**: Applicable lifecycle phases
- **AI Types**: Traditional, Generative, or both
- **Roles**: Provider, Deployer, or both
- **Sources**: Reference links and papers

## Workflow Examples

### Example 1: Design Phase Assessment

```bash
# 1. Initialize threat model
ai-threat-model init my-llm-app --type llm-app --framework plot4ai

# 2. Analyze design phase threats interactively
ai-threat-model analyze my-llm-app.tm.json \
  --lifecycle-phase Design \
  --interactive

# 3. Review detected threats
ai-threat-model report my-llm-app.tm.json --format markdown
```

### Example 2: Privacy-Focused Assessment

```bash
# Focus on privacy and data protection threats
ai-threat-model analyze my-ai-app.tm.json \
  --category "Privacy & Data Protection" \
  --interactive
```

### Example 3: Comprehensive Assessment

```bash
# Assess all threats across all phases
ai-threat-model analyze my-ai-app.tm.json --interactive

# Generate comprehensive report
ai-threat-model report my-ai-app.tm.json --format markdown --output report.md
```

## Data Loading

PLOT4AI deck.json is automatically downloaded on first use and cached locally in `patterns/ai/plot4ai/deck.json`.

To force a fresh download:

```python
from ai_threat_model.utils.plot4ai_loader import load_plot4ai_deck

deck = load_plot4ai_deck(force_download=True)
```

## Programmatic Usage

### Using PLOT4AI Plugin Directly

```python
from ai_threat_model.plugins.ai.plot4ai_plugin import Plot4AIPlugin
from ai_threat_model.core.models import SystemModel, SystemType, ThreatModelingFramework

# Initialize plugin
plugin = Plot4AIPlugin()

# Get elicitation questions
questions = plugin.get_elicitation_questions(
    lifecycle_phase="Design",
    category="Privacy & Data Protection"
)

# Answer questions
answers = {
    "1-0": "No",  # Answer "No" to question 1-0
    "1-1": "Yes",  # Answer "Yes" to question 1-1
}

# Detect threats with answers
system = SystemModel(
    name="My AI App",
    type=SystemType.LLM_APP,
    threat_modeling_framework=ThreatModelingFramework.PLOT4AI
)

threats = plugin.detect_threats(
    system,
    lifecycle_phase="Design",
    category="Privacy & Data Protection",
    answers=answers
)
```

## Best Practices

1. **Start with Design Phase**: Assess threats early in the design phase
2. **Use Interactive Mode**: Answer elicitation questions for accurate threat detection
3. **Combine with OWASP**: Use PLOT4AI for holistic assessment, OWASP for security focus
4. **Filter by Phase**: Focus on relevant lifecycle phases for your current stage
5. **Category Focus**: Use category filters for domain-specific assessments (e.g., privacy compliance)

## Regulatory Compliance

PLOT4AI helps with compliance for:

- **EU AI Act**: Comprehensive risk assessment
- **GDPR**: Privacy and data protection threats
- **Accessibility**: Transparency and accessibility requirements
- **Ethics**: Ethical AI development

## References

- [PLOT4AI Website](https://plot4.ai/)
- [PLOT4AI Library](https://plot4.ai/library)
- [PLOT4AI GitHub](https://github.com/PLOT4ai/plot4ai-library)
- [CNIL AI Assessment Tools](https://www.cnil.fr/en/ai-systems-compliance-other-guides-tools-and-best-practices)
- [OECD Tools Catalogue](https://oecd.ai/en/catalogue/tools/plot4ai)

## Attribution

PLOT4AI is created by Isabel Barberá and licensed under CC-BY-SA-4.0.

See [patterns/ai/plot4ai/README.md](../../patterns/ai/plot4ai/README.md) for full attribution details.
