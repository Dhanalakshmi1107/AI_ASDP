"""Service fingerprint cache — stores LLM-generated attack surface knowledge
per (product, version) pair so it is never re-derived across scans.

Cache file: cache/fingerprint_cache.json
Key: "<product>|<version>" (lowercased, stripped)

Usage
-----
    from backend.fingerprint_cache import FingerprintCache

    cache = FingerprintCache()
    entry = cache.get("nginx", "1.18.0")   # None on first encounter
    if entry is None:
        entry = <call LLM to generate attack surface>
        cache.set("nginx", "1.18.0", entry)
"""

import json
import logging
import time
from pathlib import Path


LOGGER = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT_DIR / "cache"
CACHE_PATH = CACHE_DIR / "fingerprint_cache.json"

# Cache entries expire after 30 days (seconds).
# Set to 0 to disable expiry entirely.
TTL_SECONDS = 30 * 24 * 60 * 60


class FingerprintCache:
    """Persistent JSON cache keyed by service fingerprint (product + version)."""

    def __init__(self):
        CACHE_DIR.mkdir(exist_ok=True)
        self._data: dict = self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, product: str, version: str) -> dict | None:
        """Return the cached entry for this fingerprint, or None if absent/expired."""
        key = self._key(product, version)
        entry = self._data.get(key)
        if entry is None:
            return None
        if TTL_SECONDS and time.time() - entry.get("cached_at", 0) > TTL_SECONDS:
            LOGGER.debug("Fingerprint cache expired for %s", key)
            del self._data[key]
            return None
        return entry.get("payload")

    def set(self, product: str, version: str, payload: dict) -> None:
        """Store a payload for this fingerprint and persist to disk."""
        key = self._key(product, version)
        self._data[key] = {
            "cached_at": time.time(),
            "payload": payload,
        }
        self._save()

    def has(self, product: str, version: str) -> bool:
        """Return True if a non-expired entry exists for this fingerprint."""
        return self.get(product, version) is not None

    def stats(self) -> dict:
        """Return basic cache statistics."""
        now = time.time()
        total = len(self._data)
        expired = sum(
            1 for v in self._data.values()
            if TTL_SECONDS and now - v.get("cached_at", 0) > TTL_SECONDS
        )
        return {"total": total, "live": total - expired, "expired": expired}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _key(product: str, version: str) -> str:
        p = (product or "unknown").strip().lower()[:60]
        v = (version or "").strip().lower()[:20]
        return f"{p}|{v}"

    def _load(self) -> dict:
        if not CACHE_PATH.exists():
            return {}
        try:
            return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            LOGGER.warning("Could not load fingerprint cache: %s", exc)
            return {}

    def _save(self) -> None:
        try:
            CACHE_PATH.write_text(
                json.dumps(self._data, indent=2), encoding="utf-8"
            )
        except OSError as exc:
            LOGGER.warning("Could not persist fingerprint cache: %s", exc)


# Module-level singleton — import and reuse across the process lifetime
_instance: FingerprintCache | None = None


def get_cache() -> FingerprintCache:
    """Return the shared FingerprintCache instance, creating it on first call."""
    global _instance
    if _instance is None:
        _instance = FingerprintCache()
    return _instance
