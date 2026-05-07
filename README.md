# AIASDP — AI-Assisted Security Discovery Platform

An AI-powered reconnaissance and attack surface analysis tool built with React + Vite (frontend) and Flask (backend). Designed as a research project for CSP 558 — Ethical Hacking and Penetration Testing.

## What It Does

AIASDP automates the full recon-to-report pipeline that a penetration tester would normally do manually:

1. **Scan** — runs nmap, subfinder, whatweb, wafw00f, sslscan, and Wappalyzer against a target
2. **Enrich** — maps detected product versions to CVEs (NVD API or local fallback)
3. **Reason** — runs a 4-stage LLM reasoning chain (per-service assessment → cross-service correlation → remediation → executive synthesis)
4. **Plan** — generates a pentest plan by merging a curated attack playbook with LLM-generated attack vectors, then validates every vector through a two-tier critic
5. **Report** — exports a structured Markdown attack-surface report

---

## Features

- **4 Scan Modes**: Fast (rule-based, 0 LLM calls), Standard (full AI pipeline), Deep (full-port + TLS), Organization (subfinder → parallel liveness check → full recon per alive host)
- **Async job queue**: `/start-scan` returns 202 immediately with a `scan_id`; frontend polls `/scan-status/<id>` for live progress
- **BM25 retrieval** (no GPU/CUDA required): in-memory BM25 replaces ChromaDB + sentence-transformers (~180 MB stack vs 5.2 GB)
- **4-stage reasoning chain**: per-service CVE assessment → cross-service correlation → remediation → executive synthesis
- **Attack playbook + LLM merge**: 99 curated playbook entries always run as a baseline; LLM enrichment adds target-specific attacks on top — both sources merged, neither skipped
- **Two-tier pentest plan critic**: deterministic rules (zero token cost) + LLM validation (skeptical reviewer on a different model tier)
- **Precondition grounding**: deterministic critic rejects attacks requiring undetected technologies (WordPress, Nginx, GraphQL, etc.) and downgrades attacks with unverifiable preconditions (login forms, auth config, database backends) to `needs_manual_check`
- **Organization mode**: subfinder discovers subdomains → parallel liveness check → full recon on each alive host (capped at 10)
- **CVE enrichment**: NVD API (optional, 7-day TTL cache) + local fallback `cve_fallback.json`
- **Risk score**: 0–100 computed from CVSS averages, exposed service count, and AI severity assessment
- **Markdown export**: download an `attacksurface_<target>.md` report
- **RAG chat**: ask natural-language questions about any scan result via `/rag-query`

---

## Stack

| Layer | Technology |
|---|---|
| Frontend | React 18 + Vite + Tailwind CSS 4 |
| Backend | Flask + Python 3.10+ |
| Retrieval | rank-bm25 (in-process, no vector DB) |
| AI — primary | Groq llama-3.3-70b-versatile |
| AI — secondary | Groq llama-3.1-8b-instant |
| AI — lightweight | Google Gemini 1.5 Flash |
| Database | SQLite (scan history + async job status) |
| Recon tools | nmap · subfinder · whatweb · wafw00f · sslscan · wappalyzer |

---

## Quick Start

### Backend (WSL / Linux)

```bash
# 1. Create and activate virtual environment
python3 -m venv myvenv
source myvenv/bin/activate

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Configure API keys (optional — local fallbacks work without keys)
cp .env.example .env
# Edit .env: GROQ_API_KEY, GEMINI_API_KEY, NVD_API_KEY

# 4. Start the Flask server
python main.py
# → http://127.0.0.1:5000
```

### Frontend (WSL / Linux)

```bash
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

> **Windows note**: Always run `npm install` and `npm run dev` from WSL.
> Windows npm creates empty stub files in `.bin/`; WSL npm creates proper symlinks.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GROQ_API_KEY` | — | Groq API key for LLaMA-3 inference |
| `GEMINI_API_KEY` | — | Google Gemini Flash for lightweight synthesis |
| `NVD_API_KEY` | — | NVD API key (set `CVE_DATA_SOURCE=nvd` to enable) |
| `CVE_DATA_SOURCE` | `local` | `local` or `nvd` |
| `API_KEY` | — | Optional API key gate for all endpoints |
| `ALLOWED_ORIGINS` | `http://localhost:5173` | CORS allowed origins (comma-separated) |
| `ALLOWED_TARGETS_FILE` | — | Path to plaintext allowlist of permitted scan targets |
| `RATE_LIMIT_MAX` | `5` | Max scan requests per IP per window |
| `RATE_LIMIT_WINDOW` | `60` | Rate limit window in seconds |
| `RATE_LIMIT_ENABLED` | `1` | Set `0` to disable rate limiting (dev) |
| `FLASK_HOST` | `127.0.0.1` | Flask bind address |
| `FLASK_PORT` | `5000` | Flask port |
| `FLASK_DEBUG` | `0` | Enable Flask debug mode |

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/start-scan` | Queue a new scan → returns `{scan_id, status}` (202) |
| `GET` | `/scan-status/<id>` | Poll scan status and live progress text |
| `GET` | `/scan/<id>` | Get full scan result JSON |
| `GET` | `/scan-history` | List recent scans (metadata only) |
| `GET` | `/export-md/<id>` | Download Markdown attack-surface report |
| `POST` | `/rag-query` | Ask a natural-language question about a scan |

---

## Architecture — How a Scan Works

```
POST /start-scan
      │
      ▼
 job_runner.py (ThreadPoolExecutor)
      │
      ▼
 scan_service.perform_scan()
      │
      ├── subfinder          passive subdomain discovery
      ├── nmap               port + service + version scan
      ├── whatweb            web tech fingerprinting (HTTP-based)
      ├── http_probe         raw headers, body snippet, server banner
      ├── wafw00f            WAF detection
      ├── wappalyzer         deep tech-stack fingerprinting
      ├── sslscan            TLS version + cipher analysis (port 443/8443 or deep mode)
      ├── CVEEnricher        map product versions → CVEs
      ├── ai_service         baseline risk summary (analyze_scan)
      ├── schema validate    enforce Master_Recon_Schema.json
      ├── SQLite persist     save result, update scan row
      ├── reasoning_chain    4-stage RAG pipeline (below)
      └── pentest_engine     attack plan + critic pipeline (below)
```

### 4-Stage Reasoning Chain (`reasoning_chain.py`)

| Stage | Model Tier | What It Does |
|---|---|---|
| 1 — Per-service CVE assessment | Primary (Groq 70B) | One batched LLM call per host; assesses all services together with CVE and KB context |
| 2 — Cross-service correlation | Primary (Groq 70B) | Identifies attack chains across services; retrieves historical scan context from BM25 |
| 3 — Remediation | Secondary (Groq 8B) | Batched remediation steps for all HIGH/CRITICAL findings; prioritized by severity |
| 4 — Executive synthesis | Lightweight (Gemini Flash → Groq 8B) | 6–10 sentence executive summary covering scope, services, TLS, WAF, strengths, weaknesses |

Every stage has a **deterministic fallback** — the system always produces a result even with no API keys.

**Risk score** = `(avg CVSS × 7) + min(open services × 3, 20) + severity boost (0–10)` → clamped 0–100.

### Pentest Plan Pipeline (`pentest_engine.py` + `critic.py`)

```
For each host:
  ┌─────────────────────────────────────┐
  │  attack_playbook (99 entries)       │  ← always runs (baseline)
  │  + LLM attack enumeration (Groq 70B)│  ← always runs (enrichment)
  │  → merge by id, LLM entries first   │
  └─────────────────────────────────────┘
              │
              ▼
  DeterministicCritic (zero token cost)
    Rule 1: CVE format validation
    Rule 2: Port grounding — reject if required ports not in scan
    Rule 3: Tech fingerprint — reject if precondition names a
            detectable tech (WordPress, Nginx, GraphQL, etc.)
            not found in web stack
    Rule 4: Unverifiable precondition — downgrade to
            needs_manual_check if precondition requires active
            probing (login forms, auth config, db backends, etc.)
              │
              ▼
  LLMCritic (Groq 8B — different tier from Stage 1)
    Skeptical reviewer: checks CVE version ranges, precondition
    plausibility, known false positives for the target type
              │
              ▼
  Split: confirmed / needs_manual_check / rejected
```

**Measured false positive rate** (scanme.nmap.org, standard mode, 55 total vectors):

| Verdict | Count | Notes |
|---|---|---|
| `confirmed` | 3 | Fully scan-evidenced: Apache path traversal, directory enum, missing headers |
| `needs_manual_check` | 18 | Valid technique, precondition requires active probe to verify |
| `rejected` (det. critic) | 6 | Wrong tech stack: WordPress ×3, Nginx ×2, GraphQL ×1 |
| `rejected` (LLM critic) | 28 | Port absent or CVE version mismatch |

---

## Security Design

| Concern | Implementation |
|---|---|
| Rate limiting | In-memory token bucket, 5 req/IP/60s on `/start-scan` |
| CORS | Restricted to `ALLOWED_ORIGINS` env var |
| API authentication | Optional `X-API-Key` header via `hmac.compare_digest` |
| Input validation | Hostname regex + IPv4 check; rejects `-` prefix (flag injection); max 253 chars |
| Target allowlist | Optional `ALLOWED_TARGETS_FILE` for production gating |
| Tool allowlist | LLM-generated shell commands validated — only known pentest binaries surfaced; others redacted |
| Prompt injection | Scan data wrapped in `<untrusted_scan_data>` tags with explicit data-only instruction |

---

## Running Tests

```bash
source myvenv/bin/activate
python -m pytest tests/ -v
```

80 tests across 4 files:

| File | Tests | Coverage |
|---|---|---|
| `test_parsers.py` | 39 | nmap, sslscan, whatweb, WAF, HTTP signal parsers |
| `test_schema_utils.py` | 21 | Master schema validation, coercion edge cases |
| `test_cve_service.py` | 14 | CVE enrichment, CVSS parsing, local/NVD fallback |
| `test_org_scan.py` | 6 | Organization mode subdomain pipeline |

---

## Project Structure

```
AIASDP/
├── backend/
│   ├── ai_service.py        # Groq / Gemini LLM wrapper with tiered fallback
│   ├── attack_playbook.py   # 99 curated attack entries keyed by service/port
│   ├── config.py            # .env loader
│   ├── critic.py            # Two-tier critic (deterministic rules + LLM reviewer)
│   ├── cve_service.py       # NVD + fallback CVE enrichment (7-day TTL cache)
│   ├── db_service.py        # SQLite persistence + schema migrations
│   ├── export_md.py         # Markdown report generator
│   ├── fingerprint_cache.py # HTTP fingerprint caching
│   ├── job_runner.py        # Async ThreadPoolExecutor scan queue
│   ├── manager.py           # ReconManager (live scan state + finalize)
│   ├── parsers.py           # Tool output parsers (nmap, sslscan, whatweb, etc.)
│   ├── pentest_engine.py    # Attack plan builder — playbook+LLM merge + critics
│   ├── rag_ingest.py        # BM25 collections (replaces ChromaDB)
│   ├── reasoning_chain.py   # 4-stage RAG reasoning pipeline
│   ├── recon_tools.py       # Subprocess wrappers for recon tools
│   ├── scan_service.py      # Main scan orchestrator + progress signals
│   ├── schema_utils.py      # Schema load/validate (cached, soft on extras)
│   └── schemas.py           # LLM output dataclasses + coercion
├── data/
│   ├── cve_fallback.json    # Local CVE database (used when CVE_DATA_SOURCE=local)
│   ├── security_kb.json     # Security hardening knowledge base
│   └── scan_history.db      # SQLite DB (auto-created on first run)
├── frontend/src/
│   ├── App.jsx              # Root component + progress state
│   ├── components/
│   │   ├── ErrorBoundary.jsx
│   │   ├── Navbar.jsx
│   │   ├── RagChat.jsx        # RAG Q&A chat panel
│   │   ├── RecentScans.jsx    # Clickable scan history (API-backed)
│   │   ├── ScanForm.jsx       # Scan form + async polling loop
│   │   └── ScanProgress.jsx   # Live progress bar + status text
│   └── pages/Dashboard.jsx
├── tests/
│   ├── conftest.py
│   ├── test_cve_service.py
│   ├── test_org_scan.py
│   ├── test_parsers.py
│   └── test_schema_utils.py
├── logs/                    # Rotating log files (auto-created, 10 MB × 5 backups)
├── cache/                   # CVE response cache (auto-created)
├── main.py                  # Flask app entry point
├── Master_Recon_Schema.json # JSON schema for scan result validation
├── requirements.txt
└── pytest.ini
```

---

## Key Design Decisions

**BM25 over vector databases**: ChromaDB + sentence-transformers requires ~5.2 GB and a GPU. BM25 achieves comparable retrieval quality for security knowledge at ~180 MB with zero GPU requirement. The tradeoff is semantic similarity vs. keyword precision — for security terms like CVE IDs, service names, and tool names, keyword precision is often better anyway.

**Always merge playbook + LLM**: Using only the playbook misses CVE-specific and stack-aware attacks. Using only the LLM risks hallucination and inconsistent coverage. Merging both gives guaranteed baseline coverage (every discovered service gets attack entries) plus LLM enrichment (target-specific attacks, version-specific CVE techniques).

**Two-tier critic design**: The deterministic critic runs in milliseconds with zero token cost and eliminates the obvious rejections (wrong port, wrong tech stack, unverifiable preconditions). The LLM critic runs on survivors only, using a different model tier from Stage 1 to avoid shared blind spots. This design saves tokens and catches both rule-checkable and semantically-invalid proposals.

**Precondition grounding**: A passive nmap+Wappalyzer scan cannot confirm whether a login form exists, whether SSH password auth is enabled, or whether a web app uses a MongoDB backend. Surfacing attacks as `confirmed` when their preconditions are unverifiable misleads analysts. The deterministic critic now explicitly distinguishes between "tech definitely absent" (reject) and "precondition unverifiable from passive scan" (needs_manual_check with a specific reason).

---

This project is provided for educational and research purposes only and should not be used for any commercial, malicious, or unauthorized activities.

---
