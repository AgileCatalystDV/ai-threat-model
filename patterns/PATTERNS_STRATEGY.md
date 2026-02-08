# Threat Patterns Strategy

## Huidige Aanpak

Het project gebruikt een **hybrid approach** voor threat patterns:

1. **Default Patterns (in code)**: Alle patterns zijn ingebouwd in de plugins als fallback
   - LLM Plugin: LLM01-LLM10 (10 patterns)
   - Agentic Plugin: AGENTIC01-AGENTIC10 (10 patterns)
   - Multi-Agent Plugin: MULTI-AGENT-01 tot 05 (5 patterns)

2. **JSON Files (optioneel)**: JSON files in `patterns/` directory kunnen defaults overschrijven
   - Als een JSON file bestaat, wordt die gebruikt in plaats van de default
   - JSON files zijn handig voor customisatie en community contributions

## Waarom deze aanpak?

### Voordelen:
- ✅ **Werkt altijd**: Zelfs zonder JSON files hebben plugins alle patterns beschikbaar
- ✅ **Flexibel**: JSON files kunnen defaults overschrijven voor customisatie
- ✅ **Minder onderhoud**: Niet alle patterns hoeven als JSON files te bestaan
- ✅ **Version control**: Defaults zijn in code, makkelijker te versioneren

### Wanneer JSON files gebruiken?
- Custom patterns toevoegen
- Bestaande patterns aanpassen voor specifieke use cases
- Community contributions
- Pattern library uitbreiden zonder code te wijzigen

## Huidige Status

### Aanwezig als JSON:
- `patterns/ai/llm-top10/`: LLM01.json, LLM02.json (2 van 10)
- `patterns/ai/agentic-top10/`: AGENTIC01.json, AGENTIC02.json (2 van 10)
- `patterns/ai/multi-agent/`: (geen JSON files, alleen defaults)

### In code (defaults):
- ✅ LLM01-LLM10: Alle 10 patterns beschikbaar
- ✅ AGENTIC01-AGENTIC10: Alle 10 patterns beschikbaar
- ✅ MULTI-AGENT-01 tot 05: Alle 5 patterns beschikbaar

## Aanbeveling

**De huidige aanpak is prima!** Je hoeft niet alle patterns als JSON files te hebben omdat:

1. **Functionaliteit werkt**: Plugins hebben alle patterns via defaults
2. **JSON files zijn optioneel**: Ze zijn alleen nodig voor customisatie
3. **Minder onderhoud**: Je hoeft niet 25+ JSON files te onderhouden

### Optionele verbeteringen (niet verplicht):

1. **Pattern export script**: Script om alle defaults naar JSON te exporteren
2. **Meer voorbeeld JSON files**: LLM03-LLM10 en AGENTIC03-AGENTIC10 als voorbeelden
3. **Pattern validation**: Validatie dat JSON files correct zijn

Maar dit is **optioneel** - de huidige setup werkt perfect!

## Toevoegen van nieuwe patterns

### Als JSON file:
```bash
# Maak nieuw pattern bestand
vim patterns/ai/llm-top10/LLM03.json

# Plugin laadt het automatisch bij volgende run
```

### Als default in code:
```python
# Bewerk src/ai_threat_model/plugins/ai/llm_plugin.py
# Voeg toe aan _get_default_patterns()
```

## Conclusie

**De patterns directory is in orde zoals het nu is!** 

- Defaults zorgen dat alles werkt
- JSON files zijn optioneel voor customisatie
- Je kunt altijd meer JSON files toevoegen als je wilt, maar het is niet nodig
