"""Tests for core config module."""
import pytest
from pathlib import Path
from src.core.config import config


def test_config_dirs_exist():
    config.ensure_dirs()
    assert config.DATA_DIR.exists()
    assert config.LOGS_DIR.exists()
    assert config.CACHE_DIR.exists()


def test_api_keys_returns_dict():
    keys = config.check_api_keys()
    assert isinstance(keys, dict)
    assert "hibp" in keys
    assert "github" in keys


def test_summary_structure():
    summary = config.summary()
    assert "log_level" in summary
    assert "api_keys_configured" in summary
    assert "modules_enabled" in summary


def test_default_headers():
    assert "User-Agent" in config.DEFAULT_HEADERS
    assert "Mozilla" in config.DEFAULT_HEADERS["User-Agent"]
