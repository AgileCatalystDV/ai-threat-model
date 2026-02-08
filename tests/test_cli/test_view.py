"""
Tests for view command.
"""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ai_threat_model.cli.main import app

runner = CliRunner()


class TestCLIView:
    """Tests for view command."""

    def test_view_displays_threat_model(self, tmp_path):
        """Test that view displays threat model in readable format."""
        threat_model_file = tmp_path / "test.tm.json"
        threat_model_data = {
            "metadata": {"version": "1.0.0", "author": "Test Author"},
            "system": {
                "name": "Test System",
                "type": "llm-app",
                "threat_modeling_framework": "owasp-llm-top10-2025",
                "components": [
                    {
                        "id": "comp1",
                        "name": "Component 1",
                        "type": "llm",
                        "capabilities": [],
                        "trust_level": "internal",
                    }
                ],
                "data_flows": [
                    {
                        "from": "comp1",
                        "to": "comp1",
                        "classification": "internal",
                        "encrypted": False,
                    }
                ],
            },
            "threats": [
                {
                    "id": "threat1",
                    "category": "LLM01",
                    "framework": "owasp-llm-top10-2025",
                    "title": "Prompt Injection",
                    "description": "Test threat description",
                    "severity": "critical",
                    "affected_components": ["comp1"],
                }
            ],
        }
        threat_model_file.write_text(json.dumps(threat_model_data))

        result = runner.invoke(app, ["view", str(threat_model_file)])

        assert result.exit_code == 0
        # Should contain key information
        assert "Test System" in result.stdout
        assert "Component 1" in result.stdout
        assert "LLM01" in result.stdout or "Prompt Injection" in result.stdout
        assert "Test Author" in result.stdout

    def test_view_file_not_found(self):
        """Test view with non-existent file."""
        result = runner.invoke(app, ["view", "nonexistent.tm.json"])
        assert result.exit_code == 1
        assert "does not exist" in result.stdout.lower()

    def test_view_empty_threats(self, tmp_path):
        """Test view with threat model that has no threats."""
        threat_model_file = tmp_path / "test.tm.json"
        threat_model_data = {
            "metadata": {"version": "1.0.0"},
            "system": {
                "name": "Test System",
                "type": "llm-app",
                "threat_modeling_framework": "owasp-llm-top10-2025",
                "components": [],
                "data_flows": [],
            },
            "threats": [],
        }
        threat_model_file.write_text(json.dumps(threat_model_data))

        result = runner.invoke(app, ["view", str(threat_model_file)])

        assert result.exit_code == 0
        assert "Test System" in result.stdout
        # Should indicate no threats
        assert "No threats" in result.stdout or "threats identified" in result.stdout.lower()

    def test_view_displays_components_table(self, tmp_path):
        """Test that components are displayed in a table."""
        threat_model_file = tmp_path / "test.tm.json"
        threat_model_data = {
            "metadata": {"version": "1.0.0"},
            "system": {
                "name": "Test System",
                "type": "llm-app",
                "threat_modeling_framework": "owasp-llm-top10-2025",
                "components": [
                    {
                        "id": "comp1",
                        "name": "Component 1",
                        "type": "llm",
                        "capabilities": [],
                        "trust_level": "internal",
                    },
                    {
                        "id": "comp2",
                        "name": "Component 2",
                        "type": "database",
                        "capabilities": [],
                        "trust_level": "privileged",
                    },
                ],
                "data_flows": [],
            },
            "threats": [],
        }
        threat_model_file.write_text(json.dumps(threat_model_data))

        result = runner.invoke(app, ["view", str(threat_model_file)])

        assert result.exit_code == 0
        assert "Component 1" in result.stdout
        assert "Component 2" in result.stdout
        assert "internal" in result.stdout
        assert "privileged" in result.stdout

    def test_view_displays_data_flows_table(self, tmp_path):
        """Test that data flows are displayed in a table."""
        threat_model_file = tmp_path / "test.tm.json"
        threat_model_data = {
            "metadata": {"version": "1.0.0"},
            "system": {
                "name": "Test System",
                "type": "llm-app",
                "threat_modeling_framework": "owasp-llm-top10-2025",
                "components": [
                    {"id": "comp1", "name": "Component 1", "type": "llm", "capabilities": [], "trust_level": "internal"},
                    {"id": "comp2", "name": "Component 2", "type": "database", "capabilities": [], "trust_level": "internal"},
                ],
                "data_flows": [
                    {
                        "from": "comp1",
                        "to": "comp2",
                        "data_type": "user-data",
                        "classification": "confidential",
                        "encrypted": True,
                    }
                ],
            },
            "threats": [],
        }
        threat_model_file.write_text(json.dumps(threat_model_data))

        result = runner.invoke(app, ["view", str(threat_model_file)])

        assert result.exit_code == 0
        assert "Component 1" in result.stdout
        assert "Component 2" in result.stdout
        # Rich tables truncate long text, so check for partial match
        assert "confidenti" in result.stdout or "confidential" in result.stdout
        # Should show encrypted status
        assert "✓" in result.stdout or "encrypted" in result.stdout.lower()

    def test_view_displays_affected_items_in_threats_table(self, tmp_path):
        """Test that affected items are shown in threats table."""
        threat_model_file = tmp_path / "test.tm.json"
        threat_model_data = {
            "metadata": {"version": "1.0.0"},
            "system": {
                "name": "Test System",
                "type": "llm-app",
                "threat_modeling_framework": "owasp-llm-top10-2025",
                "components": [
                    {"id": "comp1", "name": "LLM Service", "type": "llm", "capabilities": [], "trust_level": "internal"},
                    {"id": "comp2", "name": "Database", "type": "database", "capabilities": [], "trust_level": "internal"},
                ],
                "data_flows": [
                    {
                        "from": "comp1",
                        "to": "comp2",
                        "data_type": "data",
                        "classification": "confidential",
                        "encrypted": False,
                    }
                ],
            },
            "threats": [
                {
                    "id": "threat1",
                    "category": "LLM01",
                    "framework": "owasp-llm-top10-2025",
                    "title": "Prompt Injection",
                    "severity": "critical",
                    "affected_components": ["comp1"],
                    "affected_data_flows": ["comp1->comp2"],
                }
            ],
        }
        threat_model_file.write_text(json.dumps(threat_model_data))

        result = runner.invoke(app, ["view", str(threat_model_file)])

        assert result.exit_code == 0
        # Should show affected components and flows
        assert "LLM Service" in result.stdout or "Component: LLM Service" in result.stdout
        assert "→" in result.stdout or "Flow:" in result.stdout

    def test_view_displays_detailed_threat_panels(self, tmp_path):
        """Test that detailed threat information is shown in panels."""
        threat_model_file = tmp_path / "test.tm.json"
        threat_model_data = {
            "metadata": {"version": "1.0.0"},
            "system": {
                "name": "Test System",
                "type": "llm-app",
                "threat_modeling_framework": "owasp-llm-top10-2025",
                "components": [
                    {"id": "comp1", "name": "LLM Service", "type": "llm", "capabilities": [], "trust_level": "internal"}
                ],
                "data_flows": [],
            },
            "threats": [
                {
                    "id": "threat1",
                    "category": "LLM01",
                    "framework": "owasp-llm-top10-2025",
                    "title": "Prompt Injection",
                    "description": "This is a test threat description",
                    "severity": "critical",
                    "affected_components": ["comp1"],
                    "attack_vectors": ["Direct injection", "Indirect injection"],
                    "mitigations": [
                        {
                            "id": "mit1",
                            "description": "Sanitize inputs",
                            "status": "proposed",
                        }
                    ],
                }
            ],
        }
        threat_model_file.write_text(json.dumps(threat_model_data))

        result = runner.invoke(app, ["view", str(threat_model_file)])

        assert result.exit_code == 0
        # Should show detailed threat information
        assert "This is a test threat description" in result.stdout
        assert "Affected Components" in result.stdout
        assert "Attack Vectors" in result.stdout
        assert "Mitigations" in result.stdout
        assert "Sanitize inputs" in result.stdout

    def test_view_handles_missing_component_references(self, tmp_path):
        """Test that view handles threats referencing non-existent components gracefully."""
        threat_model_file = tmp_path / "test.tm.json"
        threat_model_data = {
            "metadata": {"version": "1.0.0"},
            "system": {
                "name": "Test System",
                "type": "llm-app",
                "threat_modeling_framework": "owasp-llm-top10-2025",
                "components": [
                    {"id": "comp1", "name": "Component 1", "type": "llm", "capabilities": [], "trust_level": "internal"}
                ],
                "data_flows": [],
            },
            "threats": [
                {
                    "id": "threat1",
                    "category": "LLM01",
                    "framework": "owasp-llm-top10-2025",
                    "title": "Test Threat",
                    "severity": "high",
                    "affected_components": ["nonexistent"],
                }
            ],
        }
        threat_model_file.write_text(json.dumps(threat_model_data))

        result = runner.invoke(app, ["view", str(threat_model_file)])

        assert result.exit_code == 0
        # Should still display threat, using component ID if not found
        assert "Test Threat" in result.stdout
        assert "nonexistent" in result.stdout

    def test_view_shows_summary(self, tmp_path):
        """Test that summary is displayed at the end."""
        threat_model_file = tmp_path / "test.tm.json"
        threat_model_data = {
            "metadata": {"version": "1.0.0"},
            "system": {
                "name": "Test System",
                "type": "llm-app",
                "threat_modeling_framework": "owasp-llm-top10-2025",
                "components": [
                    {"id": "comp1", "name": "Component 1", "type": "llm", "capabilities": [], "trust_level": "internal"}
                ],
                "data_flows": [
                    {"from": "comp1", "to": "comp1", "classification": "internal", "encrypted": False}
                ],
            },
            "threats": [
                {
                    "id": "threat1",
                    "category": "LLM01",
                    "framework": "owasp-llm-top10-2025",
                    "title": "Test Threat",
                    "severity": "high",
                }
            ],
        }
        threat_model_file.write_text(json.dumps(threat_model_data))

        result = runner.invoke(app, ["view", str(threat_model_file)])

        assert result.exit_code == 0
        # Should show summary
        assert "Summary" in result.stdout or "components" in result.stdout.lower()
        assert "1" in result.stdout  # At least one component, flow, or threat

    def test_view_handles_multiple_threats(self, tmp_path):
        """Test view with multiple threats."""
        threat_model_file = tmp_path / "test.tm.json"
        threat_model_data = {
            "metadata": {"version": "1.0.0"},
            "system": {
                "name": "Test System",
                "type": "llm-app",
                "threat_modeling_framework": "owasp-llm-top10-2025",
                "components": [
                    {"id": "comp1", "name": "Component 1", "type": "llm", "capabilities": [], "trust_level": "internal"}
                ],
                "data_flows": [],
            },
            "threats": [
                {
                    "id": "threat1",
                    "category": "LLM01",
                    "framework": "owasp-llm-top10-2025",
                    "title": "Threat 1",
                    "severity": "critical",
                },
                {
                    "id": "threat2",
                    "category": "LLM02",
                    "framework": "owasp-llm-top10-2025",
                    "title": "Threat 2",
                    "severity": "high",
                },
                {
                    "id": "threat3",
                    "category": "LLM03",
                    "framework": "owasp-llm-top10-2025",
                    "title": "Threat 3",
                    "severity": "medium",
                },
            ],
        }
        threat_model_file.write_text(json.dumps(threat_model_data))

        result = runner.invoke(app, ["view", str(threat_model_file)])

        assert result.exit_code == 0
        # Should show all threats in table
        assert "Threat 1" in result.stdout
        assert "Threat 2" in result.stdout
        assert "Threat 3" in result.stdout
        # Should show first 5 in detail (we have 3, so all should be shown)
        assert "LLM01" in result.stdout or "LLM02" in result.stdout or "LLM03" in result.stdout

    def test_view_handles_more_than_5_threats(self, tmp_path):
        """Test view truncates detailed panels when more than 5 threats."""
        threat_model_file = tmp_path / "test.tm.json"
        components = [
            {"id": f"comp{i}", "name": f"Component {i}", "type": "llm", "capabilities": [], "trust_level": "internal"}
            for i in range(1, 3)
        ]
        threats = [
            {
                "id": f"threat{i}",
                "category": f"LLM{i:02d}",
                "framework": "owasp-llm-top10-2025",
                "title": f"Threat {i}",
                "severity": "high",
            }
            for i in range(1, 8)  # 7 threats
        ]
        threat_model_data = {
            "metadata": {"version": "1.0.0"},
            "system": {
                "name": "Test System",
                "type": "llm-app",
                "threat_modeling_framework": "owasp-llm-top10-2025",
                "components": components,
                "data_flows": [],
            },
            "threats": threats,
        }
        threat_model_file.write_text(json.dumps(threat_model_data))

        result = runner.invoke(app, ["view", str(threat_model_file)])

        assert result.exit_code == 0
        # Should show all threats in table
        assert "Threat 1" in result.stdout
        assert "Threat 7" in result.stdout
        # Should indicate more threats exist
        assert "more threats" in result.stdout.lower() or "2 more" in result.stdout
