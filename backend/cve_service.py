"""CVE enrichment service.

Lookup strategy (NVD mode):
  1. If product + version are known, try a CPE ``virtualMatchString`` query
     first — this is far more precise than a keyword search.
  2. Fall back to ``keywordSearch`` if the CPE query returns nothing or if
     the service lacks product/version information.

Local fallback (``CVE_DATA_SOURCE=local`` or no ``NVD_API_KEY``):
  Full-text keyword match against the bundled ``cve_fallback.json``.

Results are cached in ``cache/cve_cache.json`` keyed by the normalised
lookup signature (CPE string or sorted keyword list).  Each cache entry
stores the results alongside a ``cached_at`` timestamp; entries older than
``_CACHE_TTL_DAYS`` are evicted at startup so stale data never persists
indefinitely.
"""

import json
import logging
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib import error, parse, request


LOGGER = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT_DIR / "cache"
DATA_DIR = ROOT_DIR / "data"
CACHE_PATH = CACHE_DIR / "cve_cache.json"
FALLBACK_DB_PATH = DATA_DIR / "cve_fallback.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Characters allowed in CPE component fields (everything else → underscore)
_CPE_CLEAN_RE = re.compile(r"[^a-z0-9.\-]")

# Cache TTL — entries older than this are evicted on startup
_CACHE_TTL_DAYS = 7


class CVEEnricher:
    def __init__(self):
        CACHE_DIR.mkdir(exist_ok=True)
        DATA_DIR.mkdir(exist_ok=True)
        self.cache = self._load_json(CACHE_PATH, {})
        self._evict_stale_cache()
        # Lazy-loaded fallback DB — only read from disk when first needed
        self._fallback_db: dict | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich(self, scan_data: dict) -> dict:
        """Attach CVE matches to every service in scan_data in place."""
        technologies = self._technology_names(scan_data)

        for host in scan_data["hosts"]:
            for service in host["services"]:
                matches = self.lookup_matches(service=service, technologies=technologies)
                service["cve_matches"] = matches

        self._save_json(CACHE_PATH, self.cache)
        return scan_data

    def lookup_matches(self, service: dict, technologies: list[str]) -> list[dict]:
        """Return CVE matches for a single service, using cache when available."""
        cpe = self._build_cpe_virtual_match(service)
        service_keywords = self._build_service_keywords(service)
        if cpe:
            cache_key = f"cpe:{cpe}"
        else:
            cache_key = "kw:" + "|".join(sorted(service_keywords))

        cached = self.cache.get(cache_key)
        if cached is not None:
            # New format: {"results": [...], "cached_at": "<ISO>"}
            if isinstance(cached, dict) and "results" in cached:
                return cached["results"]
            # Legacy format: flat list (pre-TTL entries still in the file)
            if isinstance(cached, list):
                return cached

        matches: list[dict] = []
        cve_data_source = os.getenv("CVE_DATA_SOURCE", "local").strip().lower()

        if cve_data_source == "nvd" and os.getenv("NVD_API_KEY"):
            matches = self._query_nvd(service, technologies, cpe)

        if not matches:
            matches = self._query_fallback(service_keywords)

        # Only cache non-empty results — caching empty lists creates a permanent
        # poison entry that masks fixes to parsing, keyword builders, or the
        # fallback DB. A re-scan should always retry an empty lookup.
        if matches:
            self.cache[cache_key] = {
                "results": matches,
                "cached_at": datetime.now(timezone.utc).isoformat(),
            }
        return matches

    # ------------------------------------------------------------------
    # CPE construction
    # ------------------------------------------------------------------

    def _build_cpe_virtual_match(self, service: dict) -> str | None:
        """Build a CPE 2.3 virtualMatchString from the service fingerprint."""
        product = (service.get("product") or "").strip().lower()
        if not product:
            return None

        product_norm = _CPE_CLEAN_RE.sub("_", product.replace(" ", "_"))
        product_norm = re.sub(r"_+", "_", product_norm).strip("_")
        if not product_norm:
            return None

        version = (service.get("version") or "").strip()
        version_clean = re.split(r"[^0-9.]", version)[0] if version else ""
        version_part = version_clean if version_clean else "*"

        return f"cpe:2.3:a:*:{product_norm}:{version_part}:*:*:*:*:*:*:*"

    # ------------------------------------------------------------------
    # NVD query (CPE-first, keyword fallback)
    # ------------------------------------------------------------------

    def _query_nvd(
        self,
        service: dict,
        technologies: list[str],
        cpe: str | None,
    ) -> list[dict]:
        """Query NVD.  Try CPE virtualMatchString first; fall back to keywords."""
        api_key = os.getenv("NVD_API_KEY", "")
        headers = {"User-Agent": "AI_ASDP/1.0", "apiKey": api_key}

        matches: list[dict] = []

        if cpe:
            matches = self._nvd_request(
                {"virtualMatchString": cpe, "resultsPerPage": 10},
                headers,
            )
            if matches:
                LOGGER.debug("CPE query '%s' → %d CVEs", cpe, len(matches))
                return self._dedupe(matches)

        keywords = self._build_keywords(service, technologies)
        for keyword in keywords[:3]:
            batch = self._nvd_request(
                {"keywordSearch": keyword, "resultsPerPage": 5},
                headers,
            )
            matches.extend(batch)
            if len(matches) >= 10:
                break

        return self._dedupe(matches)

    def _nvd_request(self, params: dict, headers: dict) -> list[dict]:
        """Make a single NVD API request and parse the response."""
        query = parse.urlencode(params)
        req = request.Request(f"{NVD_URL}?{query}", headers=headers)
        try:
            with request.urlopen(req, timeout=12) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            LOGGER.warning("NVD request failed (params=%s): %s", params, exc)
            return []

        results = []
        for vulnerability in payload.get("vulnerabilities", []):
            cve = vulnerability.get("cve", {})
            metrics = cve.get("metrics", {})
            severity, score = self._extract_cvss(metrics)
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            results.append(
                {
                    "cve_id": cve_id,
                    "description": self._extract_description(cve),
                    "severity": severity,
                    "cvss_score": score,
                    "confidence": "high" if "virtualMatchString" in str(params) else "medium",
                }
            )
        return results

    # ------------------------------------------------------------------
    # Local fallback (lazy-loaded)
    # ------------------------------------------------------------------

    @property
    def fallback_db(self) -> dict:
        """Return the fallback CVE database, loading from disk on first access."""
        if self._fallback_db is None:
            self._fallback_db = self._load_json(FALLBACK_DB_PATH, {"entries": []})
        return self._fallback_db

    def _query_fallback(self, keywords: list[str]) -> list[dict]:
        """Match against the bundled cve_fallback.json using keyword overlap."""
        lowered_keywords = {item.lower() for item in keywords}
        matches = []

        for entry in self.fallback_db.get("entries", []):
            entry_terms = {term.lower() for term in entry.get("keywords", [])}
            term_overlap = entry_terms & lowered_keywords

            raw_port = entry.get("port")
            if raw_port is None or raw_port == "":
                port_values = []
            elif isinstance(raw_port, list):
                port_values = [str(p).lower() for p in raw_port if str(p).strip()]
            else:
                port_values = [str(raw_port).lower()]

            port_match = (
                not port_values
                or any(p in lowered_keywords for p in port_values)
            )
            if term_overlap and port_match:
                matches.append(
                    {
                        "cve_id": entry.get("cve_id", ""),
                        "description": entry.get("description", ""),
                        "severity": entry.get("severity", "UNKNOWN"),
                        "cvss_score": float(entry.get("cvss_score", 0.0)),
                        "confidence": entry.get("confidence", "low"),
                    }
                )

        return self._dedupe(matches)

    # ------------------------------------------------------------------
    # Keyword builder
    # ------------------------------------------------------------------

    def _build_keywords(self, service: dict, technologies: list[str]) -> list[str]:
        raw = {
            str(service.get("port", "")),
            service.get("service_name", ""),
            service.get("product", ""),
            service.get("version", ""),
        }
        raw.update(technologies)
        return self._tokenize(raw)

    def _build_service_keywords(self, service: dict) -> list[str]:
        raw = {
            str(service.get("port", "")),
            service.get("service_name", ""),
            service.get("product", ""),
            service.get("version", ""),
        }
        return self._tokenize(raw)

    def _tokenize(self, raw: set[str]) -> list[str]:
        keywords: set[str] = set()
        for item in raw:
            if not item:
                continue
            cleaned = item.strip().lower()
            if cleaned:
                keywords.add(cleaned)
            for token in re.split(r"[^a-zA-Z0-9]+", cleaned):
                if token:
                    keywords.add(token)
        return sorted(keywords)

    def _technology_names(self, scan_data: dict) -> list[str]:
        names: set[str] = set()
        for host in scan_data["hosts"]:
            server_name = host["web_stack"]["server"].get("name", "")
            if server_name:
                names.add(server_name)
            for tech in host["web_stack"]["technologies"]:
                if tech["name"]:
                    names.add(tech["name"])
        return list(names)

    # ------------------------------------------------------------------
    # CVSS / description extraction
    # ------------------------------------------------------------------

    def _extract_description(self, cve: dict) -> str:
        descriptions = cve.get("descriptions", [])
        for item in descriptions:
            if item.get("lang") == "en":
                return item.get("value", "")
        return descriptions[0].get("value", "") if descriptions else ""

    def _extract_cvss(self, metrics: dict) -> tuple[str, float]:
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(version_key, [])
            if entries:
                metric = entries[0]
                cvss_data = metric.get("cvssData", {})
                severity = (
                    metric.get("baseSeverity")
                    or cvss_data.get("baseSeverity")
                    or "UNKNOWN"
                )
                score = float(cvss_data.get("baseScore", 0.0))
                return severity, score
        return "UNKNOWN", 0.0

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def _evict_stale_cache(self) -> None:
        """Remove cache entries that exceed the TTL."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=_CACHE_TTL_DAYS)
        stale_keys = []
        for k, v in self.cache.items():
            if isinstance(v, dict) and "cached_at" in v:
                try:
                    entry_time = datetime.fromisoformat(v["cached_at"])
                    if entry_time < cutoff:
                        stale_keys.append(k)
                except (ValueError, TypeError):
                    stale_keys.append(k)  # malformed timestamp → evict
        for k in stale_keys:
            del self.cache[k]
        if stale_keys:
            LOGGER.info("CVE cache: evicted %d stale entries (TTL=%dd)", len(stale_keys), _CACHE_TTL_DAYS)

    # ------------------------------------------------------------------
    # Dedup + I/O
    # ------------------------------------------------------------------

    def _dedupe(self, matches: list[dict]) -> list[dict]:
        deduped: list[dict] = []
        seen: set[str] = set()
        for match in matches:
            key = match.get("cve_id", "")
            if key and key not in seen:
                seen.add(key)
                deduped.append(match)
        return deduped

    def _load_json(self, path: Path, default):
        if not path.exists():
            return default
        try:
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except json.JSONDecodeError:
            return default

    def _save_json(self, path: Path, payload) -> None:
        """Atomically write *payload* to *path* via a temp file + rename.

        This prevents a partially-written cache file from corrupting future runs
        if the process is killed mid-write.
        """
        tmp_path = path.with_suffix(".tmp")
        try:
            with tmp_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
            tmp_path.replace(path)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise
