# OWASP Agentic Top 10 2026 Threat Patterns

This directory contains threat pattern definitions for the OWASP Top 10 for Agentic Applications 2026 framework.

## Patterns

- **AGENTIC01**: Agent Goal Hijack
- **AGENTIC02**: Tool Misuse and Exploitation
- **AGENTIC03**: Identity and Privilege Abuse
- **AGENTIC04**: Agentic Supply Chain Vulnerabilities
- **AGENTIC05**: Unexpected Code Execution (RCE)
- **AGENTIC06**: Memory and Context Poisoning
- **AGENTIC07**: Insecure Inter-Agent Communication
- **AGENTIC08**: Cascading Failures
- **AGENTIC09**: Human-Agent Trust Exploitation
- **AGENTIC10**: Rogue Agents

## Official OWASP Names

The OWASP framework uses codes ASI01-ASI10, but we use AGENTIC01-AGENTIC10 for consistency with our naming convention. The threats are equivalent:

- ASI01 = AGENTIC01: Agent Goal Hijack
- ASI02 = AGENTIC02: Tool Misuse and Exploitation
- ASI03 = AGENTIC03: Identity and Privilege Abuse
- ASI04 = AGENTIC04: Agentic Supply Chain Vulnerabilities
- ASI05 = AGENTIC05: Unexpected Code Execution
- ASI06 = AGENTIC06: Memory and Context Poisoning
- ASI07 = AGENTIC07: Insecure Inter-Agent Communication
- ASI08 = AGENTIC08: Cascading Failures
- ASI09 = AGENTIC09: Human-Agent Trust Exploitation
- ASI10 = AGENTIC10: Rogue Agents

## Pattern Format

Each pattern file contains:
- Threat identification (ID, category, framework)
- Official OWASP title and description
- Detection patterns
- Real-world attack vectors (including CVEs)
- Mitigation strategies with priorities
- References to OWASP documentation and research

## Real-World Incidents

These patterns include references to real-world CVEs and incidents:
- **EchoLeak (CVE-2025-32711)**: Zero-click prompt injection in Microsoft 365 Copilot
- **Amazon Q (CVE-2025-8217)**: Supply chain compromise with destructive commands
- **GitHub Copilot YOLO Mode (CVE-2025-53773)**: Wormable RCE via prompt injection
- **CurXecute (CVE-2025-54135)**: Cursor MCP auto-start RCE
- **MCP Remote RCE (CVE-2025-6514)**: Critical MCP vulnerability
- **30+ CVEs in AI IDEs**: IDEsaster research findings

## Usage

These patterns are used by the AgenticPlugin to automatically detect threats in agentic systems.

## References

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
- [NHI Management Group Guide](https://nhimg.org/complete-guide-to-the-2026-owasp-top-10-risks-for-agentic-applications)
- [Lares Labs: Threats in the Wild](https://labs.lares.com/owasp-agentic-top-10/)
