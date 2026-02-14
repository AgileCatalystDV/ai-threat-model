# PLOT4AI Threat Patterns

This directory contains the PLOT4AI (Practical Library Of Threats 4 Artificial Intelligence) threat deck.

## About PLOT4AI

PLOT4AI is a holistic threat modeling library for AI systems, providing 138 threats across 8 categories:

1. **Data & Data Governance** - Data quality, integrity, and management
2. **Transparency & Accessibility** - Explainability and user accessibility
3. **Privacy & Data Protection** - Personal data protection and privacy
4. **Cybersecurity** - Security threats and vulnerabilities
5. **Safety & Environmental Impact** - Safety hazards and environmental concerns
6. **Bias, Fairness & Discrimination** - Bias and fairness issues
7. **Ethics & Human Rights** - Ethical considerations and human rights
8. **Accountability & Human Oversight** - Responsibility and oversight mechanisms

## Lifecycle Phases

PLOT4AI threats are mapped to 6 AI lifecycle phases:
- **Design** - System design and architecture
- **Input** - Data collection and preparation
- **Model** - Model development and training
- **Output** - Model inference and results
- **Deploy** - Deployment and configuration
- **Monitor** - Monitoring and validation

## Methodology

PLOT4AI uses a **card-based elicitation question** methodology:
- Each threat is presented as a question
- Answer Yes/No/Maybe to determine if threat applies
- Cards indicate when threat is applicable based on answer

## Attribution

**PLOT4AI** - Practical Library Of Threats 4 Artificial Intelligence

- **Website**: https://plot4.ai/
- **GitHub**: https://github.com/PLOT4ai/plot4ai-library
- **License**: CC-BY-SA-4.0 (Creative Commons Attribution-ShareAlike 4.0)
- **Author**: Isabel Barberá
- **Created**: 2020
- **Threats**: 138 threats across 8 categories

### License Terms

This work is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License.
To view a copy of this license, visit http://creativecommons.org/licenses/by-sa/4.0/

**Attribution Requirements:**
- You must give appropriate credit
- You must provide a link to the license
- You must indicate if changes were made
- You may distribute under the same license

## Usage

The `deck.json` file contains the complete PLOT4AI threat deck. This file is automatically downloaded on first use and cached locally.

### Using PLOT4AI in AI Threat Model

```bash
# Initialize threat model with PLOT4AI framework
ai-threat-model init my-app --type llm-app --framework plot4ai

# Analyze with PLOT4AI (all threats)
ai-threat-model analyze my-app.tm.json

# Analyze with lifecycle phase filter
ai-threat-model analyze my-app.tm.json --lifecycle-phase Design

# Analyze with category filter
ai-threat-model analyze my-app.tm.json --category "Privacy & Data Protection"

# Interactive elicitation question mode
ai-threat-model analyze my-app.tm.json --interactive
```

## Differences from OWASP Frameworks

PLOT4AI complements OWASP frameworks by providing:
- **Broader scope**: Privacy, ethics, bias, transparency (not just security)
- **Lifecycle awareness**: Threats mapped to specific AI lifecycle phases
- **Elicitation methodology**: Question-based threat discovery
- **Regulatory alignment**: Aligned with EU AI Act, GDPR requirements

## References

- [PLOT4AI Website](https://plot4.ai/)
- [PLOT4AI Library](https://plot4.ai/library)
- [PLOT4AI GitHub Repository](https://github.com/PLOT4ai/plot4ai-library)
- [CNIL AI Assessment Tools](https://www.cnil.fr/en/ai-systems-compliance-other-guides-tools-and-best-practices)
- [OECD Tools Catalogue](https://oecd.ai/en/catalogue/tools/plot4ai)

## Integration Date

PLOT4AI integrated into AI Threat Model: February 2025
