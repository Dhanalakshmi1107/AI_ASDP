"""Lightweight retrieval layer — replaces ChromaDB + sentence-transformers.

Static collections (attack_playbook, cve_knowledge, security_kb)
    In-memory BM25 indexes built once at startup. No persistence needed
    because these datasets never change between runs.

Dynamic collection (scan_results)
    Reads scan history directly from the existing SQLite database
    (db_service.py). A temporary BM25 index is built per query so the
    collection always reflects the current database state with zero
    write overhead at ingest time.

Public API matches the previous ChromaDB-backed implementation exactly:
    get_collection(name)              → collection adapter
    collection.query(...)             → ChromaDB-shape result dict
    collection.upsert(...)            → indexes documents
    collection.count()                → int
    ingest_scan / ingest_pentest_plan → no-ops (data already in SQLite)
    ingest_cve_corpus                 → loads CVE fallback into BM25
    ingest_security_kb                → loads data/security_kb.json
    ingest_attack_playbook            → loads attack_playbook module entries
"""

import json
import logging
import re
from pathlib import Path


LOGGER = logging.getLogger(__name__)
ROOT_DIR = Path(__file__).resolve().parent.parent

# Module-level collection registry (lazy-initialised on first access)
_collections: dict = {}


# ---------------------------------------------------------------------------
# Tokenizer — splits on non-alphanumerics so that hyphenated terms like
# "CVE-2021-41773" and slashed strings like "Apache/2.4.49" tokenise into
# their constituent parts. Both queries and corpus text use this same
# tokenizer so matching is consistent.
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")


def _tokenize(text: str) -> list[str]:
    """Lowercase + alphanumeric token split for BM25 indexing."""
    return _TOKEN_RE.findall((text or "").lower())


# ---------------------------------------------------------------------------
# BM25 collection adapter (ChromaDB-shape API on top of rank-bm25)
# ---------------------------------------------------------------------------

class _BM25Collection:
    """In-memory BM25 index that exposes a ChromaDB-compatible query() API."""

    def __init__(self, name: str):
        self.name = name
        self._docs: list[dict] = []        # [{"id", "text", "metadata"}, ...]
        self._index = None                 # rank_bm25.BM25Okapi instance

    # --- write ---

    def upsert(self, ids, documents, metadatas=None):
        """Insert or replace documents and rebuild the BM25 index."""
        metadatas = list(metadatas) if metadatas else [{}] * len(ids)
        existing_idx = {d["id"]: i for i, d in enumerate(self._docs)}

        for doc_id, text, meta in zip(ids, documents, metadatas):
            record = {"id": str(doc_id), "text": text or "", "metadata": meta or {}}
            if str(doc_id) in existing_idx:
                self._docs[existing_idx[str(doc_id)]] = record
            else:
                self._docs.append(record)

        self._rebuild()

    def _rebuild(self):
        try:
            from rank_bm25 import BM25Okapi
            corpus = [_tokenize(d["text"]) for d in self._docs]
            self._index = BM25Okapi(corpus) if corpus else None
        except Exception as exc:
            LOGGER.warning("BM25 index rebuild failed for %s: %s", self.name, exc)
            self._index = None

    # --- read ---

    def query(self, query_texts, n_results=5, where=None, **_ignored):
        """Return a ChromaDB-shape result dict for the given query."""
        empty = {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}
        if not self._index or not self._docs:
            return empty

        query_tokens = _tokenize(query_texts[0] if query_texts else "")
        if not query_tokens:
            return empty

        scores = self._index.get_scores(query_tokens)

        # Apply optional metadata filter (matches ChromaDB's `where` semantics
        # for simple equality on top-level keys)
        candidate_indices = list(range(len(self._docs)))
        if where:
            candidate_indices = [
                i for i in candidate_indices
                if all(self._docs[i]["metadata"].get(k) == v for k, v in where.items())
            ]

        # Rank by BM25 score, drop zero-overlap results
        candidate_indices.sort(key=lambda i: scores[i], reverse=True)
        ranked = [i for i in candidate_indices if scores[i] > 0][:n_results]

        if not ranked:
            return empty

        max_score = max(scores[i] for i in ranked) if ranked else 1.0
        ids, docs, metas, dists = [], [], [], []
        for i in ranked:
            d = self._docs[i]
            ids.append(d["id"])
            docs.append(d["text"])
            metas.append(d["metadata"])
            # Normalise to [0, 1] pseudo-distance; 0.0 = best match
            dists.append(1.0 - (scores[i] / (max_score + 1e-9)))

        return {
            "ids":       [ids],
            "documents": [docs],
            "metadatas": [metas],
            "distances": [dists],
        }

    def count(self) -> int:
        return len(self._docs)


# ---------------------------------------------------------------------------
# Scan-results collection — queries SQLite via db_service, no separate store
# ---------------------------------------------------------------------------

class _ScanResultsCollection:
    """Adapter exposing scan history as a queryable BM25 collection.

    The ChromaDB scan_results collection used to receive duplicate copies
    of every scan chunk via ingest_scan(). With this adapter the data lives
    only in SQLite and chunks are rebuilt on demand at query time.
    """

    name = "scan_results"

    # Maximum number of recent scans to materialise per query — bounds memory
    _MAX_SCANS_PER_QUERY = 25

    def upsert(self, ids, documents, metadatas=None):
        """No-op — scan data persists in SQLite via db_service.save_scan."""
        # Kept as a method so existing call sites that use this interface
        # (manager.py, scan_service.py) continue to work without changes.
        return None

    def query(self, query_texts, n_results=5, where=None, exclude_scan_id=None, **_ignored):
        """Query scan history as a BM25 collection.

        ``exclude_scan_id`` filters out the scan currently being analysed so
        it is not fed back as its own "historical context" (circular reference).
        """
        empty = {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}

        try:
            scans = self._load_scans(where, exclude_scan_id=exclude_scan_id)
        except Exception as exc:
            LOGGER.warning("scan_results: db_service load failed: %s", exc)
            return empty

        if not scans:
            return empty

        # Materialise scan chunks (host / service / cve / tls / subdomain /
        # attack_vector) into a temporary BM25 index
        ids, documents, metadatas = [], [], []
        for scan in scans:
            ids_b, docs_b, metas_b = self._chunk_scan(scan)
            ids.extend(ids_b)
            documents.extend(docs_b)
            metadatas.extend(metas_b)

        if not ids:
            return empty

        tmp = _BM25Collection("_tmp_scan_results")
        tmp.upsert(ids=ids, documents=documents, metadatas=metadatas)
        return tmp.query(query_texts=query_texts, n_results=n_results)

    def count(self) -> int:
        try:
            from backend import db_service
            return len(db_service.get_all_scans())
        except Exception:
            return 0

    # --- helpers ---

    def _load_scans(self, where, exclude_scan_id=None) -> list[dict]:
        """Return up to _MAX_SCANS_PER_QUERY full scan payloads, filtered.

        ``exclude_scan_id`` removes a specific scan from the result set so the
        current scan is never included in its own historical context.
        """
        from backend import db_service

        def _exclude(scans: list[dict]) -> list[dict]:
            if exclude_scan_id is None:
                return scans
            return [s for s in scans if s.get("scan_id") != exclude_scan_id]

        # Filter by scan_id (single scan) — exact lookup
        if where and "scan_id" in where:
            try:
                row = db_service.get_scan_by_id(int(where["scan_id"]))
            except (TypeError, ValueError):
                return []
            return _exclude([row["result_json"]]) if row else []

        # Filter by target — newest first
        if where and "target" in where:
            rows = db_service.get_scans_by_target(where["target"])
            return _exclude([r["result_json"] for r in rows[: self._MAX_SCANS_PER_QUERY]])

        # No filter — fetch metadata, then load up to N most recent payloads
        meta_rows = db_service.get_all_scans()[: self._MAX_SCANS_PER_QUERY]
        scans: list[dict] = []
        for meta in meta_rows:
            row = db_service.get_scan_by_id(meta["id"])
            if row and row.get("result_json"):
                scans.append(row["result_json"])
        return _exclude(scans)

    def _chunk_scan(self, scan: dict) -> tuple[list, list, list]:
        """Convert one stored scan into BM25 documents (host/service/cve/etc.)."""
        ids: list[str] = []
        documents: list[str] = []
        metadatas: list[dict] = []

        scan_id = scan.get("scan_id", "")
        target = scan.get("target", "")
        timestamp = scan.get("scan_timestamp", "")

        for host in scan.get("hosts", []):
            hostname = host.get("hostname", "")
            ip = host.get("ip", "")
            waf = host.get("waf", {}) or {}
            waf_name = waf.get("name", "") if waf.get("detected") else "none"
            http_status = (host.get("http", {}) or {}).get("status_code", 0)

            ids.append(f"{scan_id}_host_{hostname}")
            documents.append(
                f"Host {hostname} ({ip}) — WAF: {waf_name}, HTTP status: {http_status}"
            )
            metadatas.append({
                "scan_id": scan_id, "target": target, "chunk_type": "host",
                "hostname": hostname, "timestamp": timestamp,
            })

            for svc in host.get("services", []):
                port = svc.get("port", 0)
                proto = svc.get("protocol", "")
                ids.append(f"{scan_id}_service_{hostname}_{port}")
                documents.append(
                    f"Host {hostname} port {port}/{proto} — service: "
                    f"{svc.get('service_name', '')}, product: "
                    f"{svc.get('product', '')} {svc.get('version', '')}".strip()
                )
                metadatas.append({
                    "scan_id": scan_id, "target": target, "chunk_type": "service",
                    "hostname": hostname, "port": port, "timestamp": timestamp,
                })

                for cve in svc.get("cve_matches", []) or []:
                    cve_id = cve.get("cve_id", "")
                    ids.append(f"{scan_id}_cve_{cve_id}_{hostname}_{port}")
                    documents.append(
                        f"CVE {cve_id} on {hostname}:{port} — "
                        f"{cve.get('description', '')} — "
                        f"severity: {cve.get('severity', '')}, "
                        f"CVSS: {float(cve.get('cvss_score', 0.0))}"
                    )
                    metadatas.append({
                        "scan_id": scan_id, "target": target, "chunk_type": "cve",
                        "hostname": hostname, "port": port,
                        "severity": cve.get("severity", ""), "cve_id": cve_id,
                        "timestamp": timestamp,
                    })

            tls = host.get("tls", {}) or {}
            if (tls.get("supported_versions") or tls.get("weak_protocols")
                    or tls.get("weak_ciphers") or tls.get("certificate_expired")):
                ids.append(f"{scan_id}_tls_{hostname}")
                documents.append(
                    f"Host {hostname} TLS — weak protocols: "
                    f"{tls.get('weak_protocols', [])}, weak ciphers: "
                    f"{tls.get('weak_ciphers', [])}, cert expired: "
                    f"{tls.get('certificate_expired', False)}"
                )
                metadatas.append({
                    "scan_id": scan_id, "target": target, "chunk_type": "tls",
                    "hostname": hostname, "timestamp": timestamp,
                })

        for sd in scan.get("subdomains", []) or []:
            sd_name = sd.get("name", "")
            ids.append(f"{scan_id}_subdomain_{sd_name}")
            documents.append(
                f"Subdomain {sd_name} ({sd.get('ip', '')}) — "
                f"status: {sd.get('status', '')}"
            )
            metadatas.append({
                "scan_id": scan_id, "target": target, "chunk_type": "subdomain",
                "timestamp": timestamp,
            })

        # Confirmed attack vectors from pentest_plan
        plan = scan.get("pentest_plan") or {}
        for av in (plan.get("attack_vectors") or []):
            av_id = av.get("id", "unknown")
            ids.append(f"{scan_id}_av_{av_id}")
            documents.append(
                f"Attack vector: {av.get('attack_name', '')}. "
                f"Service: {av.get('service', '')} on {av.get('service_key', '')}. "
                f"Severity: {av.get('severity', '')}. "
                f"MITRE: {av.get('mitre_technique', '')}. "
                f"Description: {av.get('description', '')} "
                f"Tools: {', '.join(av.get('tools', []))}. "
                f"Command: {av.get('quick_command', '')}. "
                f"CVEs: {', '.join(av.get('cve_refs', []))}."
            )
            metadatas.append({
                "scan_id": scan_id, "target": target, "chunk_type": "attack_vector",
                "attack_id": av_id, "severity": av.get("severity", ""),
                "service": av.get("service", ""),
                "mitre_technique": av.get("mitre_technique", ""),
            })

        return ids, documents, metadatas


# ---------------------------------------------------------------------------
# Public API — preserved exactly so reasoning_chain / pentest_engine / main
# do not need any changes.
# ---------------------------------------------------------------------------

def _initialize_collections() -> None:
    for cname in ("cve_knowledge", "security_kb", "attack_playbook"):
        _collections.setdefault(cname, _BM25Collection(cname))
    _collections.setdefault("scan_results", _ScanResultsCollection())


def get_collection(name: str):
    """Return the named collection, lazy-initialising the registry."""
    if not _collections:
        _initialize_collections()
    return _collections.get(name)


# --- Static-corpus ingestion -----------------------------------------------

def ingest_cve_corpus(cve_fallback_path: str) -> None:
    """Load the CVE fallback corpus into the cve_knowledge BM25 index."""
    coll = get_collection("cve_knowledge")
    if coll is None or coll.count() > 0:
        return
    try:
        path = ROOT_DIR / cve_fallback_path
        payload = json.loads(path.read_text(encoding="utf-8"))
        entries = payload.get("entries", [])
        ids, docs, metas = [], [], []
        for e in entries:
            cve_id = str(e.get("cve_id", ""))
            keywords = " ".join(e.get("keywords", []) or [])
            port = e.get("port", "")
            ids.append(cve_id)
            docs.append(
                f"CVE {cve_id}: {e.get('description', '')}. "
                f"Affects: {keywords} on port {port}. "
                f"Severity: {e.get('severity', '')}. "
                f"CVSS: {float(e.get('cvss_score', 0.0))}."
            )
            metas.append({
                "cve_id": cve_id,
                "severity": e.get("severity", ""),
                "cvss_score": float(e.get("cvss_score", 0.0)),
            })
        if ids:
            coll.upsert(ids=ids, documents=docs, metadatas=metas)
            LOGGER.info("Ingested %d CVE entries into BM25 index", len(ids))
    except Exception as exc:
        LOGGER.warning("CVE corpus ingestion failed: %s", exc)


def ingest_security_kb() -> None:
    """Load security KB passages from data/security_kb.json into BM25."""
    coll = get_collection("security_kb")
    if coll is None or coll.count() > 0:
        return
    try:
        path = ROOT_DIR / "data" / "security_kb.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        entries = payload.get("entries", [])
        if not entries:
            return
        coll.upsert(
            ids=[e["id"] for e in entries],
            documents=[e["text"] for e in entries],
            metadatas=[{
                "topic": e.get("topic", ""),
                "category": e.get("category", ""),
                "severity": e.get("severity", ""),
            } for e in entries],
        )
        LOGGER.info("Ingested %d security KB entries", len(entries))
    except Exception as exc:
        LOGGER.warning("Security KB ingestion failed: %s", exc)


def ingest_attack_playbook() -> None:
    """Load the attack playbook into the attack_playbook BM25 index."""
    coll = get_collection("attack_playbook")
    if coll is None:
        return
    try:
        from backend.attack_playbook import get_all_entries

        entries = get_all_entries()
        if not entries:
            return

        ids, docs, metas = [], [], []
        for e in entries:
            doc_text = (
                f"Attack: {e['attack_name']}. "
                f"Service: {e['service']} port {e.get('ports', [])}. "
                f"Description: {e['description']} "
                f"Tools: {', '.join(e.get('tools', []))}. "
                f"Command: {e.get('quick_command', '')}. "
                f"CVEs: {', '.join(e.get('cve_refs', []))}. "
                f"Preconditions: {'; '.join(e.get('preconditions', []))}. "
                f"Expected evidence: {e.get('expected_evidence', '')}."
            )
            ids.append(e["id"])
            docs.append(doc_text)
            metas.append({
                "attack_id": e["id"],
                "service": e["service"],
                "severity": e["severity"],
                "mitre_technique": e.get("mitre_technique", ""),
                "has_cve": len(e.get("cve_refs", [])) > 0,
            })
        coll.upsert(ids=ids, documents=docs, metadatas=metas)
        LOGGER.info("Ingested %d attack playbook entries", len(ids))
    except Exception as exc:
        LOGGER.warning("Attack playbook ingestion failed: %s", exc)


# --- Dynamic ingestion (no-ops; data lives in SQLite) ----------------------

def ingest_scan(scan_result: dict, scan_id: int) -> None:
    """No-op — db_service.save_scan() already persists the full scan JSON.

    Kept for backwards compatibility with manager.py / persist_scan_result.
    The _ScanResultsCollection adapter rebuilds chunks from SQLite at query
    time, so any caller that queries scan_results immediately after this
    function returns will see the latest data.
    """
    return None


def ingest_pentest_plan(scan_result: dict) -> None:
    """No-op — pentest_plan is part of the scan JSON written by db_service.

    Kept for backwards compatibility with scan_service.py.
    """
    return None
