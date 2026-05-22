# Contributing to ProjectZ

## How to Add a New Module

1. Create `src/modules/<group>/<module_name>.py`
2. Subclass `BaseModule` from `src.core.engine`
3. Set `MODULE_NAME` and `DESCRIPTION` class attributes
4. Implement `async def run(self) -> dict:`  — must return `{"total": N, ...}`
5. Call `await self._persist_db(result)` before returning
6. Register in `MODULE_REGISTRY` in `src/core/engine.py`
7. Add to appropriate group in `MODULE_GROUPS`
8. Add entry to `MODULES` dict in `src/core/module_guide.py`

## Module Template

```python
from src.core.engine import BaseModule
from src.core.http_client import fetch
from src.core.storage import cache

class MyModule(BaseModule):
    MODULE_NAME = "mymodule"
    DESCRIPTION = "What this module does"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        cached = cache.get("mymodule", domain)
        if cached and not self.options.get("no_cache"):
            return cached

        result = {"domain": domain, "findings": [], "total": 0,
                  "critical_findings": []}
        try:
            resp = await fetch(f"https://api.example.com/{domain}", timeout=10)
            if resp.get("ok"):
                # process resp
                pass
        except Exception as e:
            result["error"] = str(e)

        result["total"] = len(result["findings"])
        cache.set("mymodule", domain, result)
        await self._persist_db(result)
        return result
```

## Code Style

- All modules must be `async`
- Always wrap HTTP calls in `try/except`  — never let a module crash the engine
- Use `self.log.info()`, `self.log.found()`, `self.log.warning()` for output
- Return `{"total": 0, "error": str(e)}` on failure — never raise
- Use `cache.get/set` with your module name as the key prefix
- Keep timeout ≤ 15s per HTTP call
