"""
ProjectZ - Programmatic API Usage Example
Run: python3 examples/04_api_usage.py
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.engine import Engine


async def basic_scan():
    """Run a quick domain scan and get results."""
    engine = Engine(
        target="example.com",
        modules=["quick"],  # whois, dns, subdomains, ssl, emails, tech
    )
    results = await engine.run()
    return results


async def custom_modules_scan():
    """Run specific modules only."""
    engine = Engine(
        target="8.8.8.8",
        modules=["geo", "iprep"],
        options={"timeout": 15, "no_cache": False},
    )

    # Real-time callback
    def on_module_done(module_name: str, data: dict):
        print(f"[{module_name}] completed — status: {data.get('status')}")

    engine.on_result = on_module_done
    return await engine.run()


async def full_corp_recon():
    """Full corporate recon — all domain + cybersec modules."""
    engine = Engine(
        target="tesla.com",
        modules=["domain", "cybersec"],
    )
    return await engine.run()


if __name__ == "__main__":
    print("Running basic scan on example.com...")
    results = asyncio.run(basic_scan())
    print(f"\nModules run: {list(results.keys())}")
