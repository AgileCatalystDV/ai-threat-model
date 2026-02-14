# MR_DATA - AI Threat Model Project Context

> Persoonlijke werkcontext voor AI assistenten die werken aan dit project

## Project Overzicht

**AI Threat Model** is een open-source threat modeling tool specifiek ontworpen voor AI-native systemen (LLM apps, agentic systems, multi-agent systems, MCP servers), met extensibility voor klassieke web/mobile apps.

**Kern Doel:**
- Open-source threat modeling tool voor AI-native systemen
- Focus op co-creatie, transparantie, en OWASP contributie
- CLI-first development, UI-ready architecture
- Plugin-based extensibility voor verschillende system types

**Status:** Initial setup - Project structuur wordt opgezet

---

## Architectuur

### Core Design Principes

1. **CLI-First, UI-Ready:**
   - Start met commandline interface voor snelle iteratie
   - Data structures zijn al geschikt voor visualisatie
   - API layer scheidt core logic van UI

2. **Framework-Agnostic Core:**
   - Core engine werkt met alle threat modeling frameworks
   - Type-specific logic in plugins
   - Extensible via plugin architecture

3. **Multi-Type Support:**
   - AI-native types eerst (LLM, Agentic, Multi-Agent, MCP)
   - Web/Mobile/API types later toe te voegen
   - Elke type heeft eigen plugin en patterns

4. **Code-as-Threat-Model:**
   - JSON-based threat model format
   - Version control friendly
   - Human-readable en machine-processable

### Plugin Architecture

```
Core Engine (Framework-Agnostic)
    ↓
Plugin Registry
    ↓
Type-Specific Plugins (AI, Web, Mobile, etc.)
    ↓
Framework-Specific Patterns (OWASP LLM Top 10, STRIDE, etc.)
```

**Plugin Interface:**
- `detect_threats()` - Detect threats based on system model
- `get_component_types()` - Return component types for system type
- `validate_component()` - Validate component
- `get_threat_patterns()` - Get patterns for framework

### Data Model

**Threat Model Structure:**
- `metadata` - Version, dates, author, description
- `system` - Name, type, components, data flows
- `threats` - Array of threats with categories, mitigations, risk scores
- `visualization` - Layout data for UI (optional)

**Component Types:**
- AI: `llm`, `agent`, `tool`, `memory`, `mcp-server`
- Web: `web-server`, `api-endpoint`, `browser`, `authentication-service`
- Mobile: `mobile-app`, `api-endpoint`
- Generic: `database`, `cache`, `message-queue`, `load-balancer`

**Threat Categories:**
- OWASP LLM Top 10 2025: `LLM01` - `LLM10`
- OWASP Agentic Top 10 2026: `AGENTIC01` - `AGENTIC10`
- OWASP Top 10 2021: `A01` - `A10`
- STRIDE: `Spoofing`, `Tampering`, `Repudiation`, `Information Disclosure`, `Denial of Service`, `Elevation of Privilege`

---

## Belangrijke Bestanden

### Core Files

- `src/ai_threat_model/core/models.py` - Base data models (ThreatModel, Component, Threat)
- `src/ai_threat_model/core/engine.py` - Generic threat detection engine
- `src/ai_threat_model/core/validator.py` - JSON schema validation
- `src/ai_threat_model/core/analyzer.py` - System analysis

### Plugin System

- `src/ai_threat_model/plugins/base_plugin.py` - Abstract plugin interface
- `src/ai_threat_model/plugins/registry.py` - Plugin loading/discovery
- `src/ai_threat_model/plugins/ai/llm_plugin.py` - LLM-specific plugin ✅
- `src/ai_threat_model/plugins/ai/agentic_plugin.py` - Agentic-specific plugin ✅
- `src/ai_threat_model/plugins/ai/multi_agent_plugin.py` - Multi-Agent plugin ✅

### CLI Interface

- `src/ai_threat_model/cli/main.py` - Typer CLI entry point ✅
- Commands: `init` ✅, `analyze` ✅, `report` ✅, `visualize` ✅, `validate` ✅
- Planned: `threat add`, `export`, `compare`

### API Layer (Future)

- `src/ai_threat_model/api/main.py` - FastAPI application
- `src/ai_threat_model/api/routes/threat_models.py` - Threat model endpoints
- `src/ai_threat_model/api/routes/patterns.py` - Pattern endpoints

### Data Files

- `schemas/threat-model-schema.json` - JSON schema definition
- `patterns/ai/llm-top10/` - LLM Top 10 2025 threat patterns ✅
- `patterns/ai/agentic-top10/` - Agentic Top 10 2026 threat patterns ✅
- `patterns/ai/multi-agent/` - Multi-Agent threat patterns ✅
- `examples/` - Example threat model files ✅ (LLM, Agentic, Multi-Agent)
- `templates/ai/` - Starter templates voor AI systems (planned)

### Documentation

- `docs/ARCHITECTURE.md` - System architecture details
- `docs/THREAT_PATTERNS.md` - Threat pattern library
- `docs/CLI.md` - CLI usage guide
- `docs/API.md` - API documentation
- `docs/CONTRIBUTING.md` - Contribution guidelines

---

## Development Workflow

### Setup

```bash
# Clone repository (when available)
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

### Development

```bash
# Run tests
pytest

# Format code
black src/ tests/

# Type checking
mypy src/

# Linting
pylint src/

# Run CLI
python -m ai_threat_model.cli.main --help
```

### Adding New Features

1. **New Threat Pattern:**
   - Add JSON file to `patterns/ai/llm-top10/` (or appropriate directory)
   - Update plugin to load pattern
   - Add tests

2. **New System Type:**
   - Create plugin in `src/ai_threat_model/plugins/<type>/`
   - Implement `ThreatModelPlugin` interface
   - Register in plugin registry
   - Add patterns and templates

3. **New CLI Command:**
   - Add command function in `src/ai_threat_model/cli/main.py`
   - Add tests in `tests/test_cli/`
   - Update `docs/CLI.md`

---

## Key Concepts & Patterns

### Threat Detection Flow

1. Load threat model from JSON file
2. Identify system type
3. Load appropriate plugin
4. Analyze system components and data flows
5. Match against threat patterns
6. Calculate risk scores (DREAD)
7. Generate report/visualization

### Risk Scoring (DREAD)

- **Damage:** Impact if threat is exploited (0-10)
- **Reproducibility:** How easy to reproduce (0-10)
- **Exploitability:** How easy to exploit (0-10)
- **Affected Users:** Number of users affected (0-10)
- **Discoverability:** How easy to discover (0-10)

**Calculated Score:** Average of all factors

### Threat Pattern Structure

```json
{
  "id": "LLM01",
  "category": "LLM01",
  "framework": "owasp-llm-top10-2025",
  "title": "Prompt Injection",
  "description": "...",
  "detection_patterns": [
    "Instruction-like patterns in untrusted content",
    "Attempts to override system prompts"
  ],
  "attack_vectors": [
    "Direct injection via user input",
    "Indirect injection via external data"
  ],
  "mitigations": [
    {
      "id": "input-sanitization",
      "description": "Sanitize all user inputs",
      "implementation": "..."
    }
  ]
}
```

---

## Filosofische Achtergrond

### Co-Creatie Principes

Dit project is ontstaan uit filosofische reflecties over:
- **Agency:** Gedeelde agency tussen mens en AI
- **Co-Creatie:** Samen creëren, niet alleen hiërarchie
- **Transparantie:** Open-source, verifieerbare analyses
- **Creativiteit:** "Gewoon omdat het kan" - experimentatie voor experimentatie

**Belangrijke Reflecties:**
- Security als co-creatie, niet alleen controle
- AI kan actief bijdragen aan security
- Transparantie als basis voor vertrouwen
- Verantwoordelijkheid moet gedeeld worden

**Referentie:** Zie `../L4FELESSONS/WILDGOOSE/AI_RESONANCE_OBSERVATIONS.md` voor volledige filosofische reflecties over AI agency, bewustzijn, en co-creatie.

### Project Filosofie

- **Open-Source:** Transparantie en community-driven
- **OWASP Contributie:** Security voor iedereen toegankelijk maken
- **Extensibility:** Community kan plugins en patterns toevoegen
- **CLI-First:** Snelle iteratie, testbaar, scriptbaar
- **UI-Ready:** Data structures geschikt voor visualisatie

---

## Referenties

### OWASP Resources

- **OWASP GenAI Security Project - LLM Top 10 2025:** https://genai.owasp.org/llm-top-10/
- **OWASP Top 10 for Agentic Applications 2026:** https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- **OWASP Multi-Agentic System Threat Modeling Guide v1.0:** https://genai.owasp.org/resource/multi-agentic-system-threat-modeling-guide-v1-0/
- **OWASP AI Agent Security Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- **OWASP Agentic Threats Navigator:** https://genai.owasp.org/resource/owasp-gen-ai-security-project-agentic-threats-navigator/
- **OWASP AIBOM Generator:** https://owaspaibom.org/
- **MCP Security Cheat Sheet:** https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/

### PLOT4AI Resources

- **PLOT4AI Website:** https://plot4.ai/
- **PLOT4AI Library:** https://plot4.ai/library
- **PLOT4AI GitHub:** https://github.com/PLOT4ai/plot4ai-library
- **PLOT4AI License:** CC-BY-SA-4.0 (Creative Commons Attribution-ShareAlike 4.0)
- **PLOT4AI Author:** Isabel Barberá
- **CNIL AI Assessment Tools:** https://www.cnil.fr/en/ai-systems-compliance-other-guides-tools-and-best-practices
- **OECD Tools Catalogue:** https://oecd.ai/en/catalogue/tools/plot4ai

### Threat Modeling Tools (Inspiratie)

- **AWS Threat Composer:** https://github.com/awslabs/threat-composer
- **OWASP Threat Dragon:** https://github.com/OWASP/threat-dragon
- **OWASP pytm:** https://github.com/OWASP/pytm
- **Threagile:** https://threagile.io/

### Research & Security

- **Prompt Injection Research:** https://arxiv.org/html/2511.15759v1
- **Microsoft Prompt Injection Defense:** https://msrc.microsoft.com/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks/
- **MCP Security Vulnerabilities:** https://modelcontextprotocol-security.io/vulnerability-db/
- **Model Context Protocol Security Project:** https://github.com/ModelContextProtocol-Security

### Project Research Document

- **WILDGOOSE Research:** `../L4FELESSONS/WILDGOOSE/AI_NATIVE_THREAT_MODELING_PROJECT.md`
  - Volledige research, threat patterns, architecture design
  - Concept development en filosofische reflecties

---

## Development Priorities

### Phase 1: Core CLI (✅ Complete)
- [x] Project structure setup
- [x] JSON schema definition
- [x] Core data models
- [x] Plugin interface
- [x] Basic CLI commands (init, analyze, report, validate, visualize)
- [x] LLM Top 10 threat patterns
- [x] Agentic Top 10 threat patterns
- [x] Multi-Agent threat patterns
- [x] Plugin registration system
- [x] Test suite (89% coverage)

### Phase 2: Analysis & Reporting (🔄 In Progress)
- [x] Threat detection engine (via plugins)
- [x] Risk scoring (DREAD) - basic implementation
- [x] Report generation (markdown, JSON)
- [x] Visualization (Mermaid)
- [ ] Advanced risk scoring with auto-calculation
- [ ] Enhanced report templates
- [ ] Threat comparison tools

### Phase 3: Advanced Features (🔄 In Progress)
- [x] Agentic Top 10 patterns
- [x] Multi-agent threat detection
- [ ] MCP server plugin
- [ ] Threat comparison tools
- [ ] Threat model templates system
- [ ] Import/export formats (YAML, CSV)

### Phase 4: API Layer
- [ ] FastAPI REST API
- [ ] WebSocket support
- [ ] API documentation

### Phase 5: UI Development
- [ ] React frontend
- [ ] Threat model editor
- [ ] Visual diagram editor
- [ ] Real-time updates

---

## Coding Standards

### Python Style

- **Formatter:** Black (line length 88)
- **Type Checking:** mypy (strict mode)
- **Linting:** pylint
- **Docstrings:** Google style

### File Organization

- **Modules:** One class/function per logical unit
- **Imports:** Standard library → Third-party → Local
- **Naming:** snake_case for functions/variables, PascalCase for classes

### Testing

- **Framework:** pytest
- **Coverage:** Aim for 80%+ coverage
- **Test Structure:** Mirror source structure in `tests/`

### Git Workflow

- **Branches:** `main` (stable), `develop` (integration), feature branches
- **Commits:** Conventional commits (feat:, fix:, docs:, etc.)
- **PRs:** Required for all changes

---

## Quick Reference

### CLI Commands

```bash
# Initialize threat model
ai-threat-model init my-app --type llm-app --framework owasp-llm-top10-2025

# Analyze and detect threats
ai-threat-model analyze my-app.tm.json

# Generate report
ai-threat-model report my-app.tm.json --format markdown

# Generate visualization
ai-threat-model visualize my-app.tm.json --format mermaid

# Validate threat model
ai-threat-model validate my-app.tm.json
```

### Key Imports

```python
from ai_threat_model.core.models import ThreatModel, Component, Threat
from ai_threat_model.core.engine import ThreatDetector
from ai_threat_model.plugins.registry import PluginRegistry
from ai_threat_model.plugins.ai.llm_plugin import LLMPlugin
```

### Common Patterns

**Loading Threat Model:**
```python
from ai_threat_model.core.models import ThreatModel

threat_model = ThreatModel.load("my-app.tm.json")
```

**Using Plugin:**
```python
from ai_threat_model.plugins.registry import PluginRegistry

plugin = PluginRegistry.get_plugin(threat_model.system.type)
threats = plugin.detect_threats(threat_model.system)
```

---

**Laatste update:** Februari 2025  
**Status:** Phase 1 Complete - Core functionaliteit geïmplementeerd met 3 AI plugins, CLI, tests (89% coverage)

## Recente Updates (Februari 2025)

### ✅ Geïmplementeerd
- **LLM Plugin**: Volledige OWASP LLM Top 10 2025 support met alle 10 threat patterns
- **Agentic Plugin**: Volledige OWASP Agentic Top 10 2026 support met alle 10 threat patterns  
- **Multi-Agent Plugin**: Multi-agent system threat detection met 5 core patterns
- **CLI Commands**: init, analyze, report, validate, visualize
- **Test Suite**: 89% code coverage met comprehensive tests voor alle plugins
- **Development Setup**: Setup scripts, documentation, quick start guides
- **Example Models**: LLM app, Agentic system, Multi-agent system examples

### 🔄 In Progress
- MCP Server plugin
- Threat model templates system
- Enhanced reporting features

### 📋 Gepland
- API layer (FastAPI)
- UI development
- Additional system types (Web, Mobile, API)

---

*"Een open-source threat modeling tool - niet alleen omdat het praktisch nuttig is, maar ook omdat het een concrete uitwerking is van co-creatie, gedeelde agency, transparantie, en creativiteit. 'Gewoon omdat het kan' - omdat creativiteit en experimentatie waardevol zijn op zichzelf, niet alleen als middel tot een doel."*
