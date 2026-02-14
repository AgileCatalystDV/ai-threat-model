"""
Logging configuration for AI Threat Model.

Provides centralized logging with debug mode support.
"""

import logging
import sys
from typing import Optional

# Logger instance
_logger: Optional[logging.Logger] = None

# Debug mode flag
_debug_mode: bool = False


def setup_logging(debug: bool = False, log_level: Optional[str] = None) -> None:
    """
    Setup logging configuration.

    Args:
        debug: Enable debug mode (verbose logging)
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    global _debug_mode, _logger

    _debug_mode = debug

    # Determine log level
    if log_level:
        level = getattr(logging, log_level.upper(), logging.INFO)
    elif debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    # Create logger
    _logger = logging.getLogger("ai_threat_model")
    _logger.setLevel(level)

    # Remove existing handlers
    _logger.handlers.clear()

    # Create console handler
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)

    # Create formatter
    if debug:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    else:
        formatter = logging.Formatter(
            "%(levelname)s: %(message)s"
        )

    handler.setFormatter(formatter)
    _logger.addHandler(handler)


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get logger instance.

    Args:
        name: Optional logger name (defaults to 'ai_threat_model')

    Returns:
        Logger instance
    """
    global _logger

    if _logger is None:
        setup_logging()

    if name:
        return _logger.getChild(name)

    return _logger


def is_debug_mode() -> bool:
    """
    Check if debug mode is enabled.

    Returns:
        True if debug mode is enabled
    """
    return _debug_mode


def log_pattern_load_error(pattern_file: str, error: Exception) -> None:
    """
    Log pattern loading error.

    Args:
        pattern_file: Path to pattern file
        error: Exception that occurred
    """
    logger = get_logger()
    logger.warning(f"Failed to load pattern {pattern_file}: {error}")


def log_threat_detection(
    component_id: str,
    pattern_id: str,
    matched: bool,
    reason: Optional[str] = None,
) -> None:
    """
    Log threat detection activity (debug mode only).

    Args:
        component_id: Component ID being analyzed
        pattern_id: Pattern ID being checked
        matched: Whether pattern matched
        reason: Optional reason for match/no-match
    """
    if not is_debug_mode():
        return

    logger = get_logger()
    status = "MATCHED" if matched else "no match"
    message = f"Threat detection: {pattern_id} vs {component_id} - {status}"
    if reason:
        message += f" ({reason})"
    logger.debug(message)


def log_pattern_registry(
    action: str,
    pattern_id: str,
    details: Optional[str] = None,
) -> None:
    """
    Log pattern registry activity (debug mode only).

    Args:
        action: Action performed (register, load, validate, etc.)
        pattern_id: Pattern ID
        details: Optional details
    """
    if not is_debug_mode():
        return

    logger = get_logger()
    message = f"Pattern registry: {action} - {pattern_id}"
    if details:
        message += f" - {details}"
    logger.debug(message)
