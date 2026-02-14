"""
Pattern registry and validation system.

Provides pattern versioning, validation, and dependency management.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime

from pydantic import BaseModel, Field, ValidationError

from .base_plugin import ThreatPattern
from ..core.models import ThreatModelingFramework


class PatternMetadata(BaseModel):
    """Metadata for a threat pattern."""

    version: str = Field(..., description="Pattern version (semver)")
    created: Optional[datetime] = Field(None, description="Creation date")
    updated: Optional[datetime] = Field(None, description="Last update date")
    author: Optional[str] = Field(None, description="Pattern author")
    dependencies: List[str] = Field(default_factory=list, description="Pattern IDs this pattern depends on")
    deprecated: bool = Field(default=False, description="Whether pattern is deprecated")
    deprecated_reason: Optional[str] = Field(None, description="Reason for deprecation")
    replaced_by: Optional[str] = Field(None, description="Pattern ID that replaces this one")


class PatternRegistry:
    """
    Registry for threat patterns with versioning and validation.

    Provides:
    - Pattern loading and caching
    - Version management
    - Dependency resolution
    - Pattern validation
    - Conflict detection
    """

    def __init__(self):
        """Initialize pattern registry."""
        self._patterns: Dict[str, ThreatPattern] = {}
        self._metadata: Dict[str, PatternMetadata] = {}
        self._framework_patterns: Dict[ThreatModelingFramework, Set[str]] = {}

    def register_pattern(
        self,
        pattern: ThreatPattern,
        metadata: Optional[PatternMetadata] = None,
    ) -> bool:
        """
        Register a pattern in the registry.

        Args:
            pattern: Threat pattern to register
            metadata: Optional metadata for the pattern

        Returns:
            True if registered successfully, False if conflict detected

        Raises:
            ValueError: If pattern is invalid or conflicts with existing pattern
        """
        # Validate pattern
        self._validate_pattern(pattern)

        # Check for conflicts
        if pattern.id in self._patterns:
            existing = self._patterns[pattern.id]
            if existing.framework != pattern.framework:
                raise ValueError(
                    f"Pattern {pattern.id} already exists with different framework: "
                    f"{existing.framework} vs {pattern.framework}"
                )

        # Register pattern
        self._patterns[pattern.id] = pattern

        # Register metadata
        if metadata:
            self._metadata[pattern.id] = metadata
        else:
            # Create default metadata
            self._metadata[pattern.id] = PatternMetadata(
                version="1.0.0",
                created=datetime.utcnow(),
            )

        # Index by framework
        if pattern.framework not in self._framework_patterns:
            self._framework_patterns[pattern.framework] = set()
        self._framework_patterns[pattern.framework].add(pattern.id)

        return True

    def get_pattern(self, pattern_id: str) -> Optional[ThreatPattern]:
        """
        Get a pattern by ID.

        Args:
            pattern_id: Pattern ID

        Returns:
            ThreatPattern if found, None otherwise
        """
        return self._patterns.get(pattern_id)

    def get_patterns_by_framework(
        self, framework: ThreatModelingFramework
    ) -> List[ThreatPattern]:
        """
        Get all patterns for a framework.

        Args:
            framework: Threat modeling framework

        Returns:
            List of patterns for the framework
        """
        pattern_ids = self._framework_patterns.get(framework, set())
        return [self._patterns[pid] for pid in pattern_ids if pid in self._patterns]

    def get_all_patterns(self) -> List[ThreatPattern]:
        """
        Get all registered patterns.

        Returns:
            List of all patterns
        """
        return list(self._patterns.values())

    def validate_dependencies(self, pattern_id: str) -> List[str]:
        """
        Validate that all dependencies for a pattern exist.

        Args:
            pattern_id: Pattern ID to validate

        Returns:
            List of missing dependency IDs
        """
        if pattern_id not in self._metadata:
            return []

        metadata = self._metadata[pattern_id]
        missing = []

        for dep_id in metadata.dependencies:
            if dep_id not in self._patterns:
                missing.append(dep_id)

        return missing

    def check_conflicts(self) -> List[Dict[str, str]]:
        """
        Check for pattern conflicts.

        Returns:
            List of conflict descriptions
        """
        conflicts = []

        # Check for duplicate IDs with different frameworks
        seen_ids: Dict[str, ThreatPattern] = {}
        for pattern in self._patterns.values():
            if pattern.id in seen_ids:
                existing = seen_ids[pattern.id]
                if existing.framework != pattern.framework:
                    conflicts.append(
                        {
                            "type": "duplicate_id",
                            "pattern_id": pattern.id,
                            "message": f"Pattern {pattern.id} exists with frameworks "
                            f"{existing.framework} and {pattern.framework}",
                        }
                    )
            else:
                seen_ids[pattern.id] = pattern

        # Check for deprecated patterns
        for pattern_id, metadata in self._metadata.items():
            if metadata.deprecated and pattern_id in self._patterns:
                conflicts.append(
                    {
                        "type": "deprecated",
                        "pattern_id": pattern_id,
                        "message": f"Pattern {pattern_id} is deprecated: {metadata.deprecated_reason or 'No reason provided'}",
                        "replaced_by": metadata.replaced_by,
                    }
                )

        return conflicts

    def _validate_pattern(self, pattern: ThreatPattern) -> None:
        """
        Validate a pattern.

        Args:
            pattern: Pattern to validate

        Raises:
            ValueError: If pattern is invalid
        """
        # Check required fields
        if not pattern.id:
            raise ValueError("Pattern ID is required")

        if not pattern.title:
            raise ValueError("Pattern title is required")

        if not pattern.description:
            raise ValueError("Pattern description is required")

        if not pattern.detection_patterns:
            raise ValueError("Pattern must have at least one detection pattern")

        if not pattern.attack_vectors:
            raise ValueError("Pattern must have at least one attack vector")

        # Validate framework
        if not isinstance(pattern.framework, ThreatModelingFramework):
            try:
                pattern.framework = ThreatModelingFramework(pattern.framework)
            except ValueError:
                raise ValueError(f"Invalid framework: {pattern.framework}")

    def load_patterns_from_directory(self, directory: Path) -> int:
        """
        Load patterns from a directory.

        Args:
            directory: Directory containing pattern JSON files

        Returns:
            Number of patterns loaded
        """
        count = 0

        if not directory.exists():
            return count

        for pattern_file in directory.glob("*.json"):
            try:
                with open(pattern_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Extract metadata if present
                metadata_data = data.pop("metadata", None)
                metadata = None
                if metadata_data:
                    metadata = PatternMetadata(**metadata_data)

                # Create pattern
                pattern = ThreatPattern(**data)
                self.register_pattern(pattern, metadata)
                count += 1

            except (json.JSONDecodeError, ValidationError, ValueError) as e:
                # Log error but continue loading other patterns
                from ..utils.logging import log_pattern_load_error
                log_pattern_load_error(str(pattern_file), e)

        return count

    def get_pattern_metadata(self, pattern_id: str) -> Optional[PatternMetadata]:
        """
        Get metadata for a pattern.

        Args:
            pattern_id: Pattern ID

        Returns:
            PatternMetadata if found, None otherwise
        """
        return self._metadata.get(pattern_id)

    def is_deprecated(self, pattern_id: str) -> bool:
        """
        Check if a pattern is deprecated.

        Args:
            pattern_id: Pattern ID

        Returns:
            True if deprecated, False otherwise
        """
        metadata = self._metadata.get(pattern_id)
        return metadata.deprecated if metadata else False


# Global registry instance
_registry: Optional[PatternRegistry] = None


def get_registry() -> PatternRegistry:
    """
    Get the global pattern registry instance.

    Returns:
        PatternRegistry instance
    """
    global _registry
    if _registry is None:
        _registry = PatternRegistry()
    return _registry
