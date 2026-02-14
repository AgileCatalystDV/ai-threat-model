"""
Tests for pattern registry and versioning.
"""

import json
from pathlib import Path
from datetime import datetime

import pytest

from ai_threat_model.core.models import ThreatModelingFramework
from ai_threat_model.plugins.base_plugin import ThreatPattern
from ai_threat_model.plugins.pattern_registry import PatternMetadata, PatternRegistry, get_registry


class TestPatternMetadata:
    """Tests for PatternMetadata."""

    def test_pattern_metadata_creation(self):
        """Test creating pattern metadata."""
        metadata = PatternMetadata(
            version="1.0.0",
            created=datetime.utcnow(),
            author="Test Author",
        )
        assert metadata.version == "1.0.0"
        assert metadata.author == "Test Author"
        assert metadata.deprecated is False

    def test_pattern_metadata_deprecated(self):
        """Test deprecated pattern metadata."""
        metadata = PatternMetadata(
            version="1.0.0",
            deprecated=True,
            deprecated_reason="Replaced by new pattern",
            replaced_by="NEW01",
        )
        assert metadata.deprecated is True
        assert metadata.replaced_by == "NEW01"


class TestPatternRegistry:
    """Tests for PatternRegistry."""

    def setup_method(self):
        """Set up test fixtures."""
        self.registry = PatternRegistry()

    def test_register_pattern(self):
        """Test registering a pattern."""
        pattern = ThreatPattern(
            id="TEST01",
            category="TEST01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Test Pattern",
            description="Test description",
            detection_patterns=["test"],
            attack_vectors=["test"],
            mitigations=[],
        )

        result = self.registry.register_pattern(pattern)
        assert result is True
        assert self.registry.get_pattern("TEST01") == pattern

    def test_register_pattern_with_metadata(self):
        """Test registering pattern with metadata."""
        pattern = ThreatPattern(
            id="TEST01",
            category="TEST01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Test Pattern",
            description="Test",
            detection_patterns=["test"],
            attack_vectors=["test"],
            mitigations=[],
        )

        metadata = PatternMetadata(
            version="1.0.0",
            author="Test Author",
        )

        self.registry.register_pattern(pattern, metadata)
        assert self.registry.get_pattern_metadata("TEST01") == metadata

    def test_get_patterns_by_framework(self):
        """Test getting patterns by framework."""
        pattern1 = ThreatPattern(
            id="LLM01",
            category="LLM01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Pattern 1",
            description="Test",
            detection_patterns=["test"],
            attack_vectors=["test"],
            mitigations=[],
        )

        pattern2 = ThreatPattern(
            id="AGENTIC01",
            category="AGENTIC01",
            framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
            title="Pattern 2",
            description="Test",
            detection_patterns=["test"],
            attack_vectors=["test"],
            mitigations=[],
        )

        self.registry.register_pattern(pattern1)
        self.registry.register_pattern(pattern2)

        llm_patterns = self.registry.get_patterns_by_framework(
            ThreatModelingFramework.OWASP_LLM_TOP10_2025
        )
        assert len(llm_patterns) == 1
        assert llm_patterns[0].id == "LLM01"

        agentic_patterns = self.registry.get_patterns_by_framework(
            ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026
        )
        assert len(agentic_patterns) == 1
        assert agentic_patterns[0].id == "AGENTIC01"

    def test_validate_dependencies(self):
        """Test dependency validation."""
        pattern1 = ThreatPattern(
            id="DEP01",
            category="DEP01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Dependency Pattern",
            description="Test",
            detection_patterns=["test"],
            attack_vectors=["test"],
            mitigations=[],
        )

        pattern2 = ThreatPattern(
            id="DEP02",
            category="DEP02",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Dependent Pattern",
            description="Test",
            detection_patterns=["test"],
            attack_vectors=["test"],
            mitigations=[],
        )

        metadata = PatternMetadata(
            version="1.0.0",
            dependencies=["DEP01"],
        )

        self.registry.register_pattern(pattern1)
        self.registry.register_pattern(pattern2, metadata)

        # DEP02 depends on DEP01, which exists
        missing = self.registry.validate_dependencies("DEP02")
        assert len(missing) == 0

        # DEP03 depends on DEP01 and NONEXISTENT
        pattern3 = ThreatPattern(
            id="DEP03",
            category="DEP03",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Pattern with Missing Dep",
            description="Test",
            detection_patterns=["test"],
            attack_vectors=["test"],
            mitigations=[],
        )

        metadata3 = PatternMetadata(
            version="1.0.0",
            dependencies=["DEP01", "NONEXISTENT"],
        )

        self.registry.register_pattern(pattern3, metadata3)
        missing = self.registry.validate_dependencies("DEP03")
        assert "NONEXISTENT" in missing

    def test_check_conflicts_duplicate_id(self):
        """Test conflict detection for duplicate IDs."""
        pattern1 = ThreatPattern(
            id="DUPLICATE",
            category="DUPLICATE",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Pattern 1",
            description="Test",
            detection_patterns=["test"],
            attack_vectors=["test"],
            mitigations=[],
        )

        pattern2 = ThreatPattern(
            id="DUPLICATE",
            category="DUPLICATE",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Pattern 2",
            description="Test",
            detection_patterns=["test"],
            attack_vectors=["test"],
            mitigations=[],
        )

        self.registry.register_pattern(pattern1)
        self.registry.register_pattern(pattern2)  # Same ID, same framework - OK

        conflicts = self.registry.check_conflicts()
        # Should not conflict if same framework
        assert len(conflicts) == 0

    def test_check_conflicts_deprecated(self):
        """Test conflict detection for deprecated patterns."""
        pattern = ThreatPattern(
            id="DEPRECATED",
            category="DEPRECATED",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Deprecated Pattern",
            description="Test",
            detection_patterns=["test"],
            attack_vectors=["test"],
            mitigations=[],
        )

        metadata = PatternMetadata(
            version="1.0.0",
            deprecated=True,
            deprecated_reason="Replaced by NEW01",
            replaced_by="NEW01",
        )

        self.registry.register_pattern(pattern, metadata)
        conflicts = self.registry.check_conflicts()

        assert len(conflicts) > 0
        deprecated_conflicts = [c for c in conflicts if c["type"] == "deprecated"]
        assert len(deprecated_conflicts) == 1
        assert deprecated_conflicts[0]["pattern_id"] == "DEPRECATED"

    def test_validate_pattern_missing_fields(self):
        """Test pattern validation for missing required fields."""
        # Missing ID
        with pytest.raises(ValueError, match="Pattern ID is required"):
            invalid_pattern = ThreatPattern(
                id="",
                category="TEST",
                framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
                title="Test",
                description="Test",
                detection_patterns=["test"],
                attack_vectors=["test"],
                mitigations=[],
            )
            self.registry.register_pattern(invalid_pattern)

    def test_is_deprecated(self):
        """Test checking if pattern is deprecated."""
        pattern = ThreatPattern(
            id="TEST01",
            category="TEST01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Test",
            description="Test",
            detection_patterns=["test"],
            attack_vectors=["test"],
            mitigations=[],
        )

        metadata = PatternMetadata(version="1.0.0", deprecated=True)
        self.registry.register_pattern(pattern, metadata)

        assert self.registry.is_deprecated("TEST01") is True
        assert self.registry.is_deprecated("NONEXISTENT") is False

    def test_load_patterns_from_directory(self, tmp_path):
        """Test loading patterns from directory."""
        # Create test pattern file
        pattern_dir = tmp_path / "patterns"
        pattern_dir.mkdir()

        pattern_file = pattern_dir / "TEST01.json"
        pattern_data = {
            "id": "TEST01",
            "category": "TEST01",
            "framework": "owasp-llm-top10-2025",
            "title": "Test Pattern",
            "description": "Test description",
            "detection_patterns": ["test"],
            "attack_vectors": ["test"],
            "mitigations": [],
        }

        with open(pattern_file, "w") as f:
            json.dump(pattern_data, f)

        count = self.registry.load_patterns_from_directory(pattern_dir)
        assert count == 1
        assert self.registry.get_pattern("TEST01") is not None

    def test_load_patterns_with_metadata(self, tmp_path):
        """Test loading patterns with metadata."""
        pattern_dir = tmp_path / "patterns"
        pattern_dir.mkdir()

        pattern_file = pattern_dir / "TEST01.json"
        pattern_data = {
            "id": "TEST01",
            "category": "TEST01",
            "framework": "owasp-llm-top10-2025",
            "title": "Test Pattern",
            "description": "Test",
            "detection_patterns": ["test"],
            "attack_vectors": ["test"],
            "mitigations": [],
            "metadata": {
                "version": "1.0.0",
                "author": "Test Author",
            },
        }

        with open(pattern_file, "w") as f:
            json.dump(pattern_data, f)

        count = self.registry.load_patterns_from_directory(pattern_dir)
        assert count == 1

        metadata = self.registry.get_pattern_metadata("TEST01")
        assert metadata is not None
        assert metadata.version == "1.0.0"
        assert metadata.author == "Test Author"


class TestGlobalRegistry:
    """Tests for global registry instance."""

    def test_get_registry_singleton(self):
        """Test that get_registry returns singleton."""
        registry1 = get_registry()
        registry2 = get_registry()
        assert registry1 is registry2
