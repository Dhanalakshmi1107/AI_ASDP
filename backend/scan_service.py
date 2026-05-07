import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from backend import db_service
from backend.ai_service import analyze_scan
from backend.cve_service import CVEEnricher
from backend.manager import ReconManager, persist_scan_result
from backend.recon_tools import (
    is_host_alive,
    run_http_probe,
    run_nmap,
    run_sslscan,
    run_subfinder,
    run_wafwoof,
    run_wappalyzer,
    run_whatweb,
)
from backend.schema_utils import create_scan_result, validate_against_schema


LOGGER = logging.getLogger(__name__)

# Maximum number of subdomains to scan in organization mode (root domain + this many)
_ORG_MAX_SUBDOMAINS = 9


def _progress(scan_id, text: str) -> None:
    """Write a progress message to the DB (no-op when scan_id is None)."""
    if scan_id is not None:
        try:
            db_service.update_scan_status(scan_id, "running", text)
        except Exception as exc:
            LOGGER.debug("Progress update failed (scan_id=%s): %s", scan_id, exc)


def perform_scan(target, mode="standard", scan_id=None):
    """Run the recon pipeline, persist the scan, and attach reasoning outputs.

    mode:
      fast         — recon tools run, reasoning uses deterministic fallbacks (0 LLM calls)
      standard     — recon tools + full 4-stage reasoning chain (~4 LLM calls)
      deep         — same as standard + full-port Nmap + SSLScan
      organization — subfinder first, then full standard recon on each discovered host

    scan_id (optional):
      When provided (async path), progress updates are written to the DB row
      identified by scan_id and finalize_scan() updates that row rather than
      inserting a new one.
    """
    if mode == "organization":
        return _perform_org_scan(target, scan_id=scan_id)

    manager = ReconManager(target, scan_id=scan_id)
    manager.data["scan_timestamp"] = datetime.now(timezone.utc).isoformat()

    try:
        _progress(scan_id, "Seeding host record…")
        manager.get_or_create_host(target)

        _progress(scan_id, "Running subfinder (passive subdomain discovery)…")
        run_subfinder(target, manager)

        _progress(scan_id, "Running Nmap (port + service scan)…")
        run_nmap(target, manager, mode=mode)

        _progress(scan_id, "Running WhatWeb (technology detection)…")
        run_whatweb(target, manager)

        _progress(scan_id, "Probing HTTP/HTTPS responses…")
        run_http_probe(target, manager)

        _progress(scan_id, "Running wafw00f (WAF detection)…")
        run_wafwoof(target, manager)

        _progress(scan_id, "Running Wappalyzer (tech-stack fingerprinting)…")
        run_wappalyzer(target, manager)

        if mode == "deep":
            _progress(scan_id, "Running SSLScan (TLS analysis)…")
            run_sslscan(target, manager)

        # Auto-run SSLScan whenever port 443 or 8443 is discovered (any mode)
        if mode != "deep":  # deep already ran it above
            _tls_ports = {443, 8443}
            _open_ports = {
                int(svc.get("port", 0))
                for host in manager.data.get("hosts", [])
                for svc in host.get("services", [])
            }
            if _tls_ports & _open_ports:
                _progress(scan_id, "Running SSLScan (TLS port detected)…")
                run_sslscan(target, manager)

        _progress(scan_id, "Enriching services with CVE data…")
        enricher = CVEEnricher()
        manager.data = enricher.enrich(manager.data)

        if mode == "fast":
            manager.data["ai_analysis"] = {
                "summary": "Fast mode: rule-based analysis only.",
                "risks": [],
                "recommendations": [],
            }
        else:
            _progress(scan_id, "Running AI analysis…")
            manager.data["ai_analysis"] = analyze_scan(manager.data)

        validate_against_schema(manager.data)
        _progress(scan_id, "Persisting scan result…")
        result = manager.finalize_scan()

        _progress(scan_id, "Running RAG reasoning chain…")
        _attach_rag_analysis(result, mode=mode)

        _progress(scan_id, "Building pentest plan…")
        _attach_pentest_plan(result, mode=mode)
        return result

    except Exception as exc:
        LOGGER.exception("Scan failed for %s", target)
        fallback = create_scan_result(target)
        fallback["scan_timestamp"] = datetime.now(timezone.utc).isoformat()
        fallback["ai_analysis"] = {
            "summary": f"Scan failed: {exc}",
            "risks": [],
            "recommendations": ["Review backend logs and verify tool availability."],
        }
        validate_against_schema(fallback)
        result = persist_scan_result(fallback, scan_id=scan_id)
        _attach_rag_analysis(result, mode=mode)
        _attach_pentest_plan(result, mode=mode)
        return result


def _perform_org_scan(root_domain: str, scan_id=None) -> dict:
    """Organization mode: discover subdomains then run full recon on each host."""
    manager = ReconManager(root_domain, scan_id=scan_id)
    manager.data["scan_timestamp"] = datetime.now(timezone.utc).isoformat()

    try:
        manager.get_or_create_host(root_domain)

        _progress(scan_id, "Running subfinder (subdomain discovery)…")
        LOGGER.info("Organization scan: running subfinder for %s", root_domain)
        run_subfinder(root_domain, manager)

        discovered = [sd["name"] for sd in manager.data.get("subdomains", [])]
        if len(discovered) > _ORG_MAX_SUBDOMAINS:
            LOGGER.info(
                "Organization scan: %d subdomains found, capping at %d",
                len(discovered), _ORG_MAX_SUBDOMAINS,
            )
        hosts_to_scan = [root_domain] + discovered[:_ORG_MAX_SUBDOMAINS]
        LOGGER.info("Organization scan: %d candidate host(s): %s", len(hosts_to_scan), hosts_to_scan)

        _progress(scan_id, f"Checking liveness of {len(hosts_to_scan)} host(s)…")
        LOGGER.info("Organization scan: checking liveness for %d host(s)...", len(hosts_to_scan))
        with ThreadPoolExecutor(max_workers=len(hosts_to_scan)) as pool:
            alive_flags = list(pool.map(is_host_alive, hosts_to_scan))

        alive_hosts = [h for h, ok in zip(hosts_to_scan, alive_flags) if ok]
        dead_hosts  = [h for h, ok in zip(hosts_to_scan, alive_flags) if not ok]

        if dead_hosts:
            LOGGER.info("Organization scan: skipping %d dead host(s): %s", len(dead_hosts), dead_hosts)
        if not alive_hosts:
            LOGGER.warning("Organization scan: no alive hosts found for %s", root_domain)

        LOGGER.info("Organization scan: %d alive host(s) to scan: %s", len(alive_hosts), alive_hosts)
        hosts_to_scan = alive_hosts

        total = len(hosts_to_scan)
        for idx, host_target in enumerate(hosts_to_scan, start=1):
            _progress(scan_id, f"Scanning host {idx}/{total}: {host_target}…")
            LOGGER.info("Organization scan: starting recon for %s", host_target)
            try:
                run_nmap(host_target, manager, mode="standard")
                run_whatweb(host_target, manager)
                run_http_probe(host_target, manager)
                run_wafwoof(host_target, manager)
                run_wappalyzer(host_target, manager)

                open_ports_for_host = {
                    int(svc.get("port", 0))
                    for host in manager.data.get("hosts", [])
                    for svc in host.get("services", [])
                    if host.get("hostname") == host_target
                }
                if {443, 8443} & open_ports_for_host:
                    run_sslscan(host_target, manager)

            except Exception as host_exc:
                LOGGER.warning("Organization scan: host %s failed, skipping: %s", host_target, host_exc)
                continue

        _progress(scan_id, "Enriching services with CVE data…")
        enricher = CVEEnricher()
        manager.data = enricher.enrich(manager.data)

        _progress(scan_id, "Running AI analysis…")
        manager.data["ai_analysis"] = analyze_scan(manager.data)

        validate_against_schema(manager.data)
        _progress(scan_id, "Persisting scan result…")
        result = manager.finalize_scan()

        _progress(scan_id, "Running RAG reasoning chain…")
        _attach_rag_analysis(result, mode="standard")

        _progress(scan_id, "Building pentest plan…")
        _attach_pentest_plan(result, mode="standard")
        return result

    except Exception as exc:
        LOGGER.exception("Organization scan failed for %s", root_domain)
        fallback = create_scan_result(root_domain)
        fallback["scan_timestamp"] = datetime.now(timezone.utc).isoformat()
        fallback["ai_analysis"] = {
            "summary": f"Organization scan failed: {exc}",
            "risks": [],
            "recommendations": ["Review backend logs and verify tool availability."],
        }
        validate_against_schema(fallback)
        result = persist_scan_result(fallback, scan_id=scan_id)
        _attach_rag_analysis(result, mode="standard")
        _attach_pentest_plan(result, mode="standard")
        return result


def _attach_pentest_plan(result, mode="standard"):
    """Build and attach the attacker-oriented pentest plan."""
    try:
        from backend.pentest_engine import build_pentest_plan

        plan = build_pentest_plan(result, mode=mode)
        result["pentest_plan"] = plan
        if result.get("scan_id") is not None:
            db_service._update_result_json(result["scan_id"], result)
    except Exception as exc:
        LOGGER.warning("Pentest plan generation failed: %s", exc)
        result["pentest_plan"] = {
            "attack_vectors": [],
            "excluded": [],
            "critic_summary": {"total": 0, "confirmed": 0, "rejected": 0, "needs_manual_check": 0},
        }
        if result.get("scan_id") is not None:
            db_service._update_result_json(result["scan_id"], result)


def _attach_rag_analysis(result, mode="standard"):
    """Attach the multi-stage reasoning output and computed risk score."""
    try:
        from backend import reasoning_chain

        rag = reasoning_chain.run_chain(result, mode=mode)
        result["rag_analysis"] = rag
        risk = reasoning_chain.compute_risk_score(result, rag)
        result["risk_score"] = risk
        if result.get("scan_id") is not None:
            db_service.update_risk_score(result["scan_id"], risk)
            db_service._update_result_json(result["scan_id"], result)
    except Exception as exc:
        logging.warning("RAG chain failed: %s", exc)
        result["rag_analysis"] = {}
        result["risk_score"] = None
        if result.get("scan_id") is not None:
            db_service._update_result_json(result["scan_id"], result)
