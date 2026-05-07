"""Tests for backend/cve_service.py — cache TTL, keyword builders, dedup, atomic write."""

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from backend.cve_service import CVEEnricher, _CACHE_TTL_DAYS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_service(port=443, service_name="https", product="nginx", version="1.24.0"):
    return {
        "port": port,
        "service_name": service_name,
        "product": product,
        "version": version,
    }


def _fresh_cache_entry(results):
    return {
        "results": results,
        "cached_at": datetime.now(timezone.utc).isoformat(),
    }


def _stale_cache_entry(results):
    old = datetime.now(timezone.utc) - timedelta(days=_CACHE_TTL_DAYS + 1)
    return {
        "results": results,
        "cached_at": old.isoformat(),
    }


# ---------------------------------------------------------------------------
# Cache read / TTL eviction
# ---------------------------------------------------------------------------

class TestCacheEviction:
    def test_fresh_entry_is_returned(self, tmp_path):
        """A recently cached entry should be returned from cache."""
        cached_results = [{"cve_id": "CVE-2023-0001", "description": "test", "severity": "HIGH", "cvss_score": 8.0, "confidence": "high"}]
        cache = {"cpe:cpe:2.3:a:*:nginx:1.24.0:*:*:*:*:*:*:*": _fresh_cache_entry(cached_results)}
        cache_file = tmp_path / "cve_cache.json"
        cache_file.write_text(json.dumps(cache))

        with patch.object(CVEEnricher, "__init__", lambda self: None):
            enricher = CVEEnricher.__new__(CVEEnricher)
            enricher.cache = cache
            enricher._fallback_db = None

        svc = _make_service(product="nginx", version="1.24.0")
        result = enricher.lookup_matches(svc, [])
        assert result == cached_results

    def test_stale_entry_is_evicted(self, tmp_path):
        """A cache entry older than TTL should be evicted at startup."""
        cached_results = [{"cve_id": "CVE-2023-0001", "description": "test", "severity": "HIGH", "cvss_score": 8.0, "confidence": "high"}]
        cache = {"some_key": _stale_cache_entry(cached_results)}
        cache_file = tmp_path / "cve_cache.json"
        cache_file.write_text(json.dumps(cache))

        with patch("backend.cve_service.CACHE_PATH", cache_file), \
             patch("backend.cve_service.FALLBACK_DB_PATH", tmp_path / "cve_fallback.json"), \
             patch("backend.cve_service.CACHE_DIR", tmp_path), \
             patch("backend.cve_service.DATA_DIR", tmp_path):
            (tmp_path / "cve_fallback.json").write_text(json.dumps({"entries": []}))
            enricher = CVEEnricher()

        assert "some_key" not in enricher.cache

    def test_legacy_list_cache_format_returned(self):
        """Pre-TTL cache entries stored as bare lists should still be readable."""
        cached_results = [{"cve_id": "CVE-2020-1234", "description": "legacy", "severity": "MEDIUM", "cvss_score": 5.0, "confidence": "low"}]
        key = "cpe:cpe:2.3:a:*:nginx:1.24.0:*:*:*:*:*:*:*"

        with patch.object(CVEEnricher, "__init__", lambda self: None):
            enricher = CVEEnricher.__new__(CVEEnricher)
            enricher.cache = {key: cached_results}  # legacy list format
            enricher._fallback_db = None

        svc = _make_service(product="nginx", version="1.24.0")
        result = enricher.lookup_matches(svc, [])
        assert result == cached_results


# ---------------------------------------------------------------------------
# Keyword / CPE builder
# ---------------------------------------------------------------------------

class TestKeywordAndCpeBuilders:
    def setup_method(self):
        with patch.object(CVEEnricher, "__init__", lambda self: None):
            self.enricher = CVEEnricher.__new__(CVEEnricher)
            self.enricher.cache = {}
            self.enricher._fallback_db = None

    def test_cpe_built_from_product_and_version(self):
        svc = _make_service(product="nginx", version="1.24.0")
        cpe = self.enricher._build_cpe_virtual_match(svc)
        assert cpe is not None
        assert "nginx" in cpe
        assert "1.24" in cpe

    def test_cpe_none_when_no_product(self):
        svc = _make_service(product="", version="1.0")
        assert self.enricher._build_cpe_virtual_match(svc) is None

    def test_service_keywords_do_not_include_extra_techs(self):
        svc = _make_service(product="nginx", version="1.24.0")
        keywords = self.enricher._build_service_keywords(svc)
        assert "nginx" in keywords
        # Technologies list should NOT be in service keywords
        for kw in keywords:
            assert "wordpress" not in kw

    def test_keywords_include_port(self):
        svc = _make_service(port=3306, product="", version="", service_name="mysql")
        keywords = self.enricher._build_service_keywords(svc)
        assert "3306" in keywords


# ---------------------------------------------------------------------------
# Local fallback query
# ---------------------------------------------------------------------------

class TestLocalFallback:
    def setup_method(self):
        with patch.object(CVEEnricher, "__init__", lambda self: None):
            self.enricher = CVEEnricher.__new__(CVEEnricher)
            self.enricher.cache = {}
            self.enricher._fallback_db = {
                "entries": [
                    {
                        "cve_id": "CVE-2021-99999",
                        "description": "Test nginx vuln",
                        "severity": "HIGH",
                        "cvss_score": 8.0,
                        "confidence": "medium",
                        "keywords": ["nginx", "http"],
                        "port": 443,
                    }
                ]
            }

    def test_returns_matching_cve(self):
        results = self.enricher._query_fallback(["nginx", "443"])
        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2021-99999"

    def test_no_match_returns_empty(self):
        results = self.enricher._query_fallback(["mysql", "3306"])
        assert results == []

    def test_port_mismatch_excludes_entry(self):
        results = self.enricher._query_fallback(["nginx", "80"])
        # Entry requires port 443; keyword match on port 80 should fail port check
        assert results == []


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------

class TestDedupe:
    def setup_method(self):
        with patch.object(CVEEnricher, "__init__", lambda self: None):
            self.enricher = CVEEnricher.__new__(CVEEnricher)

    def test_deduplicates_by_cve_id(self):
        matches = [
            {"cve_id": "CVE-2023-0001", "severity": "HIGH"},
            {"cve_id": "CVE-2023-0001", "severity": "HIGH"},
            {"cve_id": "CVE-2023-0002", "severity": "MEDIUM"},
        ]
        result = self.enricher._dedupe(matches)
        assert len(result) == 2

    def test_empty_list(self):
        assert self.enricher._dedupe([]) == []


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------

class TestAtomicWrite:
    def test_writes_json_correctly(self, tmp_path):
        with patch.object(CVEEnricher, "__init__", lambda self: None):
            enricher = CVEEnricher.__new__(CVEEnricher)

        target = tmp_path / "output.json"
        payload = {"key": "value", "list": [1, 2, 3]}
        enricher._save_json(target, payload)

        assert target.exists()
        loaded = json.loads(target.read_text())
        assert loaded == payload

    def test_tmp_file_cleaned_up(self, tmp_path):
        with patch.object(CVEEnricher, "__init__", lambda self: None):
            enricher = CVEEnricher.__new__(CVEEnricher)

        target = tmp_path / "output.json"
        enricher._save_json(target, {"x": 1})
        tmp = target.with_suffix(".tmp")
        assert not tmp.exists(), "Temp file should be removed after successful write"
