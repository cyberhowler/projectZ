"""Tests for storage layer."""
import asyncio
import pytest
from src.core.storage import CacheManager, WordlistManager, DatabaseManager


def test_cache_set_get():
    cache = CacheManager(ttl=3600)
    cache.set("test", "key1", {"data": "hello"})
    result = cache.get("test", "key1")
    assert result == {"data": "hello"}


def test_cache_miss():
    cache = CacheManager(ttl=3600)
    result = cache.get("test", "nonexistent_key_xyz_123")
    assert result is None


def test_cache_stats():
    cache = CacheManager()
    stats = cache.stats()
    assert "total_entries" in stats
    assert "valid" in stats


def test_wordlist_load_missing():
    words = WordlistManager.load("nonexistent_wordlist_abc")
    assert words == []


def test_wordlist_load_subdomains():
    words = WordlistManager.get_subdomains(limit=10)
    assert isinstance(words, list)


@pytest.mark.asyncio
async def test_db_init():
    await DatabaseManager.init_all()
    # Should not raise


@pytest.mark.asyncio
async def test_db_insert_scan():
    await DatabaseManager.init_all()
    row_id = await DatabaseManager.insert_scan("test-001", "example.com", ["whois", "dns"])
    assert row_id > 0


@pytest.mark.asyncio
async def test_db_insert_subdomain():
    await DatabaseManager.init_all()
    await DatabaseManager.insert_subdomain("example.com", "sub.example.com", "1.2.3.4", "test")
