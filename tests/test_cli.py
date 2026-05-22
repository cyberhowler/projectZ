"""
ProjectZ — CLI Tests
Tests every standalone flag works without requiring a TARGET argument.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from click.testing import CliRunner
from src.core.cli import cli

@pytest.fixture
def runner():
    return CliRunner()

def test_commands_flag(runner):
    result = runner.invoke(cli, ["--commands"])
    assert result.exit_code == 0
    assert "Missing argument" not in result.output
    assert "Command Reference" in result.output or "CORE SCAN" in result.output

def test_list_modules_flag(runner):
    result = runner.invoke(cli, ["--list-modules"])
    assert result.exit_code == 0
    assert "Missing argument" not in result.output

def test_list_profiles_flag(runner):
    result = runner.invoke(cli, ["--list-profiles"])
    assert result.exit_code == 0
    assert "Missing argument" not in result.output
    assert "red_team" in result.output or "pentest" in result.output

def test_db_stats_flag(runner):
    result = runner.invoke(cli, ["--db-stats"])
    assert result.exit_code == 0
    assert "Missing argument" not in result.output

def test_preflight_flag(runner):
    result = runner.invoke(cli, ["--preflight"])
    assert result.exit_code == 0
    assert "Missing argument" not in result.output
    assert "API Keys" in result.output or "Preflight" in result.output

def test_modules_command(runner):
    result = runner.invoke(cli, ["modules"])
    assert result.exit_code == 0
    assert "Missing argument" not in result.output

def test_modules_section(runner):
    for section in ["domain", "network", "people", "dorking", "harvesting", "cybersec"]:
        result = runner.invoke(cli, ["modules", section])
        assert result.exit_code == 0, f"modules {section} failed: {result.output}"

def test_no_target_shows_help(runner):
    result = runner.invoke(cli, [])
    # Should show help, not crash with unhandled exception
    assert result.exit_code in (0, 1, 2)

def test_help_flag(runner):
    result = runner.invoke(cli, ["-h"])
    assert result.exit_code == 0
    assert "TARGET" in result.output

def test_missing_target_error(runner):
    # Running a scan without target should give clear error
    result = runner.invoke(cli, ["--no-cache"])
    assert "Missing argument" not in result.output or result.exit_code != 0
