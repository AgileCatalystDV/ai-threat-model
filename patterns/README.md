# Threat Pattern Library

This directory contains threat patterns organized by system type and framework.

## Structure

```
patterns/
├── ai/
│   ├── llm-top10/          # OWASP LLM Top 10 2025 patterns
│   ├── agentic-top10/      # OWASP Agentic Top 10 2026 patterns
│   └── multi-agent/        # Multi-agent system threats
└── README.md
```

## Pattern Loading Strategy

**Hybrid Approach**: Plugins have all patterns built-in as defaults, and JSON files in this directory can override or supplement them.

- **Defaults (in code)**: All patterns are available even without JSON files
  - LLM: LLM01-LLM10 (10 patterns)
  - Agentic: AGENTIC01-AGENTIC10 (10 patterns)
  - Multi-Agent: MULTI-AGENT-01 to 05 (5 patterns)

- **JSON Files (optional)**: JSON files override defaults when present
  - Useful for customization and community contributions
  - Not required for basic functionality

See [PATTERNS_STRATEGY.md](PATTERNS_STRATEGY.md) for detailed explanation.

## Pattern Format

Each pattern is a JSON file with the following structure:

```json
{
  "id": "LLM01",
  "category": "LLM01",
  "framework": "owasp-llm-top10-2025",
  "title": "Prompt Injection",
  "description": "...",
  "detection_patterns": [...],
  "attack_vectors": [...],
  "mitigations": [
    {
      "id": "mitigation-id",
      "description": "...",
      "implementation": "...",
      "priority": "high|medium|low"
    }
  ],
  "references": [...]
}
```

## Adding New Patterns

1. Create a new JSON file in the appropriate directory
2. Follow the pattern format above
3. Use descriptive IDs and categories
4. Include detection patterns, attack vectors, and mitigations
5. Add references to relevant documentation

## Usage

Patterns are loaded by plugins and used for threat detection. See plugin documentation for details on how patterns are used.
