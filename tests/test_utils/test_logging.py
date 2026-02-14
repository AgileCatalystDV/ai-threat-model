"""
Tests for logging utilities.
"""

import logging
from io import StringIO

import pytest

from ai_threat_model.utils.logging import (
    get_logger,
    is_debug_mode,
    log_pattern_load_error,
    log_threat_detection,
    setup_logging,
)


class TestLoggingSetup:
    """Tests for logging setup."""

    def test_setup_logging_default(self):
        """Test default logging setup."""
        setup_logging()
        logger = get_logger()
        assert logger.level == logging.INFO
        assert is_debug_mode() is False

    def test_setup_logging_debug(self):
        """Test debug logging setup."""
        setup_logging(debug=True)
        logger = get_logger()
        assert logger.level == logging.DEBUG
        assert is_debug_mode() is True

    def test_setup_logging_custom_level(self):
        """Test custom log level."""
        setup_logging(log_level="WARNING")
        logger = get_logger()
        assert logger.level == logging.WARNING

    def test_get_logger(self):
        """Test getting logger instance."""
        setup_logging()
        logger1 = get_logger()
        logger2 = get_logger()
        assert logger1 is logger2

    def test_get_logger_with_name(self):
        """Test getting logger with child name."""
        setup_logging()
        logger = get_logger("test_module")
        assert logger.name == "ai_threat_model.test_module"


class TestLoggingFunctions:
    """Tests for logging utility functions."""

    def setup_method(self):
        """Set up test fixtures."""
        setup_logging(debug=False)

    def test_log_pattern_load_error(self):
        """Test logging pattern load error."""
        log_stream = StringIO()
        handler = logging.StreamHandler(log_stream)
        logger = get_logger()
        logger.addHandler(handler)
        logger.setLevel(logging.WARNING)

        log_pattern_load_error("test.json", ValueError("Test error"))
        log_output = log_stream.getvalue()
        assert "Failed to load pattern" in log_output
        assert "test.json" in log_output

    def test_log_threat_detection_debug_mode(self):
        """Test threat detection logging in debug mode."""
        setup_logging(debug=True)
        log_stream = StringIO()
        handler = logging.StreamHandler(log_stream)
        logger = get_logger()
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        log_threat_detection("comp1", "LLM01", matched=True, reason="type match")
        log_output = log_stream.getvalue()
        assert "Threat detection" in log_output
        assert "LLM01" in log_output
        assert "comp1" in log_output

    def test_log_threat_detection_no_debug(self):
        """Test threat detection logging without debug mode."""
        setup_logging(debug=False)
        log_stream = StringIO()
        handler = logging.StreamHandler(log_stream)
        logger = get_logger()
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        log_threat_detection("comp1", "LLM01", matched=True)
        log_output = log_stream.getvalue()
        # Should not log in non-debug mode
        assert "Threat detection" not in log_output
