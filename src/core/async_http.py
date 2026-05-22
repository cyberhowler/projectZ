"""
ProjectZ - Async HTTP Compatibility Layer v2
Drop-in replacement for aiohttp. Routes through http_client.fetch() which provides:
  - Retry + exponential backoff (capped at 2s, not 30s)
  - 429/403 aware (backoff only for affected domain)
  - User-agent rotation on every request
  - Proxy support (set PROXY_URL in env)
  - Hard asyncio timeout (no more infinite hangs)
"""
import asyncio
import re
from typing import Any
from src.core.http_client import fetch as _fetch, random_ua


class ClientTimeout:
    def __init__(self, total: float = 12, connect: float = None, sock_read: float = None):
        self.total = float(total or 12)


class TCPConnector:
    def __init__(self, ssl: bool = True, limit: int = 100, **kw):
        self.ssl = ssl



class _FakeCookie:
    def __init__(self, key, value):
        self.key   = key
        self.value = value

class _FakeCookies:
    """Minimal cookie jar — enough for modules that do dict(resp.cookies)."""
    def __init__(self, set_cookie_header: str = ""):
        self._jar: dict = {}
        if set_cookie_header:
            for part in set_cookie_header.split(","):
                kv = part.strip().split(";")[0].strip()
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    self._jar[k.strip()] = v.strip()

    def __iter__(self):
        return iter(self._jar)

    def values(self):
        return [_FakeCookie(k,v) for k,v in self._jar.items()]

    def items(self):
        return self._jar.items()

    def get(self, key, default=None):
        return self._jar.get(key, default)

    def __getitem__(self, key):
        return self._jar[key]

    def __len__(self):
        return len(self._jar)

    def __bool__(self):
        return bool(self._jar)

    # Support: dict(resp.cookies)
    def keys(self):
        return self._jar.keys()

class _FakeResponse:
    def __init__(self, result: dict):
        self._r      = result
        self.status  = result["status"]
        self.headers = result["headers"]
        self.url     = result["url"]

    async def text(self, errors: str = "ignore") -> str:
        return self._r.get("text", "")

    async def json(self, content_type: Any = None) -> Any:
        j = self._r.get("json")
        if j is not None:
            return j
        import json as _json
        try:
            return _json.loads(self._r.get("text", "{}"))
        except Exception:
            return {}

    async def read(self) -> bytes:
        return self._r.get("text", "").encode()

    @property
    def cookies(self):
        """Return a cookie jar compatible object (dict-like)."""
        return _FakeCookies(self._r.get("headers", {}).get("Set-Cookie", ""))

    async def __aenter__(self): return self
    async def __aexit__(self, *a): pass


class _RequestContext:
    def __init__(self, method, url, session,
                 headers=None, data=None, json=None,
                 params=None, allow_redirects=True, **kw):
        self._method  = method
        self._url     = url
        self._headers = {**session._headers, **(headers or {})}
        self._data    = data
        self._json    = json
        self._params  = params
        self._timeout = session._timeout
        self._redir   = allow_redirects

    async def __aenter__(self) -> _FakeResponse:
        key = re.sub(r"https?://([^/:]+).*", r"\1", self._url)
        result = await _fetch(
            url             = self._url,
            method          = self._method,
            headers         = self._headers,
            data            = self._data,
            json_data       = self._json,
            params          = self._params,
            timeout         = self._timeout,
            retries         = 2,
            domain_key      = key,
            rotate_ua       = True,
            allow_redirects = self._redir,
        )
        return _FakeResponse(result)

    async def __aexit__(self, *a): pass


class _Session:
    def __init__(self, timeout: ClientTimeout = None,
                 connector: TCPConnector = None,
                 headers: dict = None, **kw):
        t = timeout or ClientTimeout(total=12)
        self._timeout  = t.total
        self._headers  = headers or {}

    def get(self, url, headers=None, **kw):
        return _RequestContext("get", url, self, headers=headers, **kw)

    def post(self, url, headers=None, **kw):
        return _RequestContext("post", url, self, headers=headers, **kw)

    def head(self, url, headers=None, **kw):
        return _RequestContext("head", url, self, headers=headers, **kw)

    async def __aenter__(self): return self
    async def __aexit__(self, *a): pass


ClientSession = _Session

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
