#!/usr/bin/env python3
"""ProjectZ OSINT Framework — Entry Point"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from src.core.cli import cli
if __name__ == "__main__":
    cli()
