# Quick Start Guide

## Activeren van de Virtual Environment

Na het uitvoeren van `./setup_dev.sh` moet je de virtual environment activeren:

```bash
source venv/bin/activate
```

Je ziet nu `(venv)` in je terminal prompt, wat betekent dat de virtual environment actief is.

## Tests Uitvoeren

### Alle tests draaien
```bash
pytest
```

### Tests met coverage
```bash
pytest --cov=ai_threat_model --cov-report=html
```

### Specifieke test
```bash
pytest tests/test_core/test_models.py
```

## CLI Gebruiken

### Help bekijken
```bash
ai-threat-model --help
```

### Nieuwe threat model aanmaken
```bash
ai-threat-model init my-app --type llm-app
```

### Threat model bekijken (human-readable)
```bash
ai-threat-model view my-app.tm.json
```

### Threat model analyseren
```bash
ai-threat-model analyze my-app.tm.json
```

### Report genereren
```bash
ai-threat-model report my-app.tm.json --format markdown --output report.md
```

### Example threat models testen
```bash
# Analyseer het LLM app voorbeeld
ai-threat-model analyze examples/simple-llm-app.tm.json

# Analyseer het agentic system voorbeeld
ai-threat-model analyze examples/agentic-system.tm.json
```

## Deactiveren van Virtual Environment

Wanneer je klaar bent:
```bash
deactivate
```

## Troubleshooting

### "pytest: command not found"
Zorg ervoor dat de virtual environment geactiveerd is:
```bash
source venv/bin/activate
```

### "ai-threat-model: command not found"
Zorg ervoor dat:
1. De virtual environment geactiveerd is
2. Het package geïnstalleerd is: `pip install -e .`

### Virtual environment opnieuw activeren
```bash
source venv/bin/activate
```
