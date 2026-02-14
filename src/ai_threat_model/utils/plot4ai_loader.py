"""
PLOT4AI deck.json loader and cache manager.

Downloads and caches the PLOT4AI deck.json file from GitHub.

PLOT4AI Source: https://plot4.ai/
GitHub: https://github.com/PLOT4ai/plot4ai-library
License: CC-BY-SA-4.0
Author: Isabel Barberá
"""

import json
from pathlib import Path
from typing import Optional

import requests

from ..core.plot4ai_models import Plot4AIDeck

# PLOT4AI deck.json URL
PLOT4AI_DECK_URL = "https://raw.githubusercontent.com/PLOT4ai/plot4ai-library/main/deck.json"

# Default cache location
DEFAULT_CACHE_DIR = Path(__file__).parent.parent.parent / "patterns" / "ai" / "plot4ai"
DEFAULT_CACHE_FILE = DEFAULT_CACHE_DIR / "deck.json"


def ensure_cache_dir() -> Path:
    """Ensure cache directory exists."""
    DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_CACHE_DIR


def download_deck(url: str = PLOT4AI_DECK_URL, timeout: int = 30) -> dict:
    """
    Download PLOT4AI deck.json from GitHub.

    Args:
        url: URL to download deck.json from
        timeout: Request timeout in seconds

    Returns:
        Parsed JSON data as dictionary

    Raises:
        requests.RequestException: If download fails
        json.JSONDecodeError: If JSON parsing fails
    """
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to download PLOT4AI deck.json: {e}") from e
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in PLOT4AI deck.json: {e}") from e


def save_deck(data: dict, cache_file: Path = DEFAULT_CACHE_FILE) -> None:
    """
    Save deck.json to cache file.

    Args:
        data: Deck JSON data
        cache_file: Path to cache file
    """
    ensure_cache_dir()
    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_deck_from_file(cache_file: Path = DEFAULT_CACHE_FILE) -> Optional[dict]:
    """
    Load deck.json from cache file.

    Args:
        cache_file: Path to cache file

    Returns:
        Parsed JSON data or None if file doesn't exist
    """
    if not cache_file.exists():
        return None

    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        raise ValueError(f"Failed to load cached deck.json: {e}") from e


def load_plot4ai_deck(
    cache_file: Path = DEFAULT_CACHE_FILE,
    force_download: bool = False,
    use_cache: bool = True,
) -> Plot4AIDeck:
    """
    Load PLOT4AI deck, using cache if available.

    Args:
        cache_file: Path to cache file
        force_download: Force download even if cache exists
        use_cache: Use cache if available (download if not)

    Returns:
        Plot4AIDeck instance

    Raises:
        RuntimeError: If download fails and no cache available
        ValueError: If JSON parsing fails
    """
    # Try to load from cache first (unless force_download)
    if not force_download and use_cache:
        cached_data = load_deck_from_file(cache_file)
        if cached_data is not None:
            try:
                return Plot4AIDeck.model_validate({"categories": cached_data})
            except Exception as e:
                # If cached data is invalid, try to download fresh
                print(f"Warning: Cached deck.json is invalid, downloading fresh: {e}")

    # Download fresh deck.json
    try:
        deck_data = download_deck()
        # Save to cache
        save_deck(deck_data, cache_file)
        return Plot4AIDeck.model_validate({"categories": deck_data})
    except RuntimeError as e:
        # If download fails, try to use cache as fallback
        if use_cache:
            cached_data = load_deck_from_file(cache_file)
            if cached_data is not None:
                print(f"Warning: Download failed, using cached deck.json: {e}")
                return Plot4AIDeck.model_validate({"categories": cached_data})
        raise


def get_deck_path() -> Path:
    """Get path to cached deck.json file."""
    return DEFAULT_CACHE_FILE


def is_deck_cached() -> bool:
    """Check if deck.json is cached locally."""
    return DEFAULT_CACHE_FILE.exists()
