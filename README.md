# AI Threat Model

> Open-source threat modeling tool specifiek voor AI-native systemen, met extensibility voor klassieke web/mobile apps.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Overzicht

AI Threat Model is een open-source threat modeling tool ontworpen voor:
- **AI-native systemen:** LLM apps, agentic systems, multi-agent systems, MCP servers
- **Klassieke systemen:** Web apps, mobile apps, APIs (later toe te voegen)
- **Multiple frameworks:** OWASP LLM Top 10, OWASP Agentic Top 10, OWASP Top 10, STRIDE, DREAD

**Kern Features:**
- 🎯 CLI-first development voor snelle iteratie
- 🔌 Plugin-based architecture voor extensibility
- 📊 Framework-agnostic core engine
- 📝 Code-as-threat-model (JSON format)
- 🎨 UI-ready data structures (toekomstige UI)
- 🔍 Automated threat detection
- 📈 Risk scoring (DREAD methodology)
- 📊 Visualization support (Mermaid diagrams)

## Quick Start

### Installatie

```bash
# Clone repository
git clone <repo-url>
cd ai-threat-model

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements-dev.txt

# Install package in development mode
pip install -e .
```

### Gebruik

```bash
# Initialize new threat model
ai-threat-model init my-llm-app --type llm-app --framework owasp-llm-top10-2025

# View threat model in human-readable format
ai-threat-model view my-llm-app.tm.json

# Analyze system and detect threats
ai-threat-model analyze my-llm-app.tm.json

# Generate report
ai-threat-model report my-llm-app.tm.json --format markdown

# Generate visualization
ai-threat-model visualize my-llm-app.tm.json --format mermaid --output diagram.md

# Validate threat model
ai-threat-model validate my-llm-app.tm.json
```

## Project Status

**Current Phase:** Phase 1 Complete - Core CLI Functionaliteit

- ✅ Project structure
- ✅ MR_DATA.md context file
- ✅ Core engine development
- ✅ Threat pattern library (LLM, Agentic, Multi-Agent)
- ✅ CLI implementation (init, analyze, report, validate, visualize)
- ✅ Plugin system (LLM, Agentic, Multi-Agent)
- ✅ Test suite (89% coverage)
- ✅ Example threat models

## Architectuur

### Plugin-Based Design

```
Core Engine (Framework-Agnostic)
    ↓
Plugin Registry
    ↓
Type-Specific Plugins (AI, Web, Mobile, etc.)
    ↓
Framework-Specific Patterns (OWASP LLM Top 10, STRIDE, etc.)
```

### Supported System Types

**Phase 1 (Complete):**
- ✅ LLM Applications
- ✅ Agentic Systems
- ✅ Multi-Agent Systems
- ⏳ MCP Servers (in progress)

**Phase 2 (Planned):**
- ⏳ Web Applications
- ⏳ Mobile Applications
- ⏳ APIs
- ⏳ Microservices

### Supported Frameworks

- OWASP LLM Top 10 2025
- OWASP Agentic Top 10 2026
- PLOT4AI (138 threats across 8 categories - privacy, ethics, bias, transparency)
- OWASP Top 10 2021 (planned)
- OWASP Mobile Top 10 (planned)
- OWASP API Top 10 (planned)
- STRIDE (planned)
- DREAD (planned)

## Project Structuur

```
ai-threat-model/
├── src/ai_threat_model/     # Source code
│   ├── cli/                  # CLI interface
│   ├── core/                 # Core engine
│   ├── plugins/              # Plugin system
│   ├── api/                  # API layer (future)
│   └── utils/                # Utilities
├── tests/                    # Test suite
├── docs/                     # Documentation
├── patterns/                 # Threat patterns
├── templates/                # Starter templates
├── examples/                 # Example threat models
└── schemas/                  # JSON schemas
```

## Development

Zie [MR_DATA.md](MR_DATA.md) voor volledige development context en [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) voor contribution guidelines.

### Setup Development Environment

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Format code
black src/ tests/

# Type checking
mypy src/

# Linting
pylint src/
```

## Filosofische Achtergrond

Dit project is ontstaan uit reflecties over:
- **Co-Creatie:** Gedeelde agency tussen mens en AI
- **Transparantie:** Open-source, verifieerbare analyses
- **Creativiteit:** "Gewoon omdat het kan" - experimentatie voor experimentatie

Zie `../L4FELESSONS/WILDGOOSE/AI_RESONANCE_OBSERVATIONS.md` voor volledige filosofische reflecties.

## OWASP Contributie

Dit project is bedoeld voor contributie aan OWASP GenAI Security Project. We volgen OWASP best practices en richtlijnen.

## Referenties

- [OWASP GenAI Security Project](https://genai.owasp.org/)
- [OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Multi-Agent Threat Modeling Guide](https://genai.owasp.org/resource/multi-agentic-system-threat-modeling-guide-v1-0/)
- [PLOT4AI](https://plot4.ai/) - Holistic AI threat modeling (privacy, ethics, bias, transparency)

## License

Apache 2.0 License - See [LICENSE](LICENSE) file for details.

## Contributing

Contributions welcome! See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

---

**Status:** Early development - Not yet ready for production use
