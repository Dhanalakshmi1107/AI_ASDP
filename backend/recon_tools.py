import logging
import socket
import subprocess
from urllib import error, request

from backend.parsers import (
    extract_http_signal_techs,
    parse_http_output,
    parse_nmap_output,
    parse_sslscan_output,
    parse_subfinder_output,
    parse_waf_output,
    parse_whatweb_output,
)


LOGGER = logging.getLogger(__name__)


def run_subfinder(target, manager):
    # Passive sources (crt.sh, dnsdumpster, etc.) can each take 20-40s on
    # slow targets; 45s was too tight. -t 20 caps per-source threads and
    # -max-time bounds subfinder itself so we get partial results before
    # the subprocess hard-kill.
    stdout = run_command(
        ["subfinder", "-silent", "-d", target, "-t", "20", "-max-time", "2"],
        timeout=150,
    )
    manager.add_subdomains(parse_subfinder_output(stdout, target))


def run_nmap(target, manager, mode="standard"):
    # --host-timeout lets nmap abort cleanly on slow hosts and still print partial
    # results (open ports seen so far), instead of subprocess.run killing it with
    # nothing emitted. subprocess timeout is a higher hard cap as safety net.
    #
    # Web ports (80/443/8080/8443) are explicitly listed first via -p so they
    # always get probed, even if the host-timeout fires before all top-ports
    # finish. Targets like testphp.vulnweb.com sit behind WAFs that turn -sV
    # into a slow grind — without this, nmap can run out of time before
    # reaching ports 80/443 in its default top-1000 ordering.
    WEB_PORTS = "80,443,8080,8443,8000,8888"
    if mode == "deep":
        # Deep mode scans the top 1000 ports so non-standard services
        # (e.g. scanme.nmap.org:9929/nping-echo, :31337/ncat) are caught
        # without having to curate an ever-growing port list. Host timeout
        # bumped to 300s because -sV across 1000 ports is substantially
        # slower than across a curated 40-port list.
        command = [
            "nmap", "-sV", "-Pn", "-T4",
            "--top-ports", "1000",
            "--host-timeout", "300s",
            "--max-retries", "1",
            target,
        ]
        timeout = 360
    elif mode == "standard":
        command = [
            "nmap", "-sV", "--version-light", "-Pn", "-T4",
            "-p", f"{WEB_PORTS},21,22,23,25,53,110,143,445,3306,3389,5432,6379,27017",
            "--host-timeout", "120s",
            "--max-retries", "1",
            target,
        ]
        timeout = 150
    else:  # fast
        command = [
            "nmap", "-Pn", "-T4",
            "-p", WEB_PORTS + ",22,21,25,3389",
            "--host-timeout", "60s",
            target,
        ]
        timeout = 90

    stdout = run_command(command, timeout=timeout)
    services = parse_nmap_output(stdout, target)
    for service in services:
        if service.get("status") != "open":
            continue
        service.pop("host", None)
        manager.add_service(target, service)


def run_whatweb(target, manager):
    """Probe both HTTPS and HTTP with WhatWeb and merge discovered technologies."""
    host = manager.get_or_create_host(target)
    merged_stack = None

    for scheme in ("https", "http"):
        stdout = run_command(["whatweb", f"{scheme}://{target}"], timeout=20)
        if not stdout.strip():
            continue
        parsed = parse_whatweb_output(stdout)
        if merged_stack is None:
            merged_stack = parsed
        else:
            # Merge technologies from both probes — keep first probe's server/meta
            existing_keys = {
                (t["name"], t["version"])
                for t in merged_stack.get("technologies", [])
            }
            for tech in parsed.get("technologies", []):
                key = (tech["name"], tech["version"])
                if key not in existing_keys:
                    existing_keys.add(key)
                    merged_stack["technologies"].append(tech)

    host["web_stack"] = merged_stack or parse_whatweb_output("")


def run_http_probe(target, manager):
    """Probe both HTTPS and HTTP; record the richer response and note redirect behaviour.

    Also grabs a capped slice of the response body and runs a lightweight
    signal extractor (cookies, meta generator, script CDNs, GA/GTM, JSP/PHP
    extensions, HTML5 doctype) so tech detection isn't solely dependent on
    WhatWeb / Wappalyzer.
    """
    resolved_ip = resolve_host_ip(target)
    host = manager.get_or_create_host(target, ip=resolved_ip)

    results = {}
    bodies = {}
    for scheme in ("https", "http"):
        try:
            req = request.Request(
                f"{scheme}://{target}",
                headers={"User-Agent": "AI_ASDP/1.0"},
            )
            with request.urlopen(req, timeout=8) as response:
                status_line = f"HTTP/1.1 {response.status}"
                header_lines = [f"{key}: {value}" for key, value in response.headers.items()]
                results[scheme] = "\n".join([status_line, *header_lines])
                try:
                    raw_body = response.read(65536)
                    bodies[scheme] = raw_body.decode("utf-8", errors="ignore")
                except Exception:
                    bodies[scheme] = ""
        except (error.URLError, TimeoutError, socket.timeout):
            continue

    # Prefer HTTPS response; fall back to HTTP
    raw_http = results.get("https") or results.get("http") or ""
    host["http"] = parse_http_output(raw_http)
    body = bodies.get("https") or bodies.get("http") or ""

    server_header = next(
        (item["value"] for item in host["http"]["headers"] if item["name"] == "server"),
        "",
    )
    if server_header:
        parts = server_header.split("/", 1)
        host["web_stack"]["server"]["name"] = parts[0].strip()
        host["web_stack"]["server"]["version"] = parts[1].strip() if len(parts) > 1 else ""

    # Supplementary signal-based tech extraction (runs regardless of Wappalyzer).
    signal_techs = extract_http_signal_techs(host["http"].get("headers", []), body)
    if signal_techs:
        existing = {
            (t.get("name", "").lower(), t.get("version", ""))
            for t in host["web_stack"].get("technologies", [])
        }
        added = 0
        for tech in signal_techs:
            key = (tech["name"].lower(), tech["version"])
            if key not in existing:
                existing.add(key)
                host["web_stack"]["technologies"].append(tech)
                added += 1
        LOGGER.info(
            "HTTP signal extractor: added %d tech entries for %s (total signals=%d)",
            added, target, len(signal_techs),
        )


def run_sslscan(target, manager):
    """Run sslscan against port 443, but only after a quick TCP pre-check.

    Without this guard a target with no TLS listener causes sslscan to hang
    for its full 60 s timeout.  The pre-check is a sub-second TCP connect
    attempt; if the port is closed we skip the tool entirely.
    """
    # Pre-check: does port 443 actually accept a TCP connection?
    if not _tls_port_open(target, 443):
        LOGGER.info("sslscan: port 443 not open on %s, skipping", target)
        return

    stdout = run_command(
        ["sslscan", "--no-check-certificate", f"{target}:443"],
        timeout=60,
    )
    if stdout:
        host = manager.get_or_create_host(target)
        host["tls"] = parse_sslscan_output(stdout)


def _tls_port_open(hostname: str, port: int, timeout: float = 3.0) -> bool:
    """Return True if *hostname*:*port* accepts a TCP connection within *timeout* s."""
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except (socket.timeout, OSError, ConnectionRefusedError):
        return False


def run_wafwoof(target, manager):
    stdout = run_command(["wafw00f", target], timeout=25)
    host = manager.get_or_create_host(target)
    host["waf"] = parse_waf_output(stdout)


def run_wappalyzer(target, manager, retries=2, timeout=10):
    for attempt in range(retries + 1):
        try:
            try:
                from wappalyzer.scanner import Wappalyzer
            except ImportError as imp_exc:
                LOGGER.error(
                    "Wappalyzer NOT INSTALLED — tech-stack detection will be "
                    "limited to WhatWeb only. Install with: "
                    "pip install wappalyzer (error: %s)", imp_exc,
                )
                return

            LOGGER.info("Wappalyzer: starting analysis for %s (attempt %s)",
                        target, attempt + 1)

            fetched_url = None
            techs = {}
            for scheme in ("https", "http"):
                candidate = f"{scheme}://{target}/"
                try:
                    with Wappalyzer(scan_type="fast", timeout=timeout) as wappalyzer:
                        result = wappalyzer.analyze(candidate)
                    # API returns {url: {tech: ...}}; the value may be an empty dict
                    # if the connection failed silently — only accept non-empty tech results.
                    candidate_techs = result.get(candidate) or {}
                    if candidate_techs:
                        fetched_url = candidate
                        techs = candidate_techs
                        LOGGER.info("Wappalyzer: fetched %s", candidate)
                        break
                except Exception as fetch_exc:
                    LOGGER.debug("Wappalyzer fetch failed for %s: %s", candidate, fetch_exc)
                    continue

            if not techs:
                LOGGER.warning("Wappalyzer: could not fetch %s over HTTP/HTTPS", target)
                return
            LOGGER.info("Wappalyzer: detected %d technologies on %s", len(techs), target)
            host = manager.get_or_create_host(target)

            existing = {(item["name"], item["version"]) for item in host["web_stack"]["technologies"]}
            added = 0
            for tech_name, tech_data in techs.items():
                version = tech_data.get("version", "") or ""
                categories = tech_data.get("categories") or []
                category = categories[0] if categories else _categorize_wappalyzer_name(tech_name)
                key = (tech_name, version)
                if key not in existing:
                    existing.add(key)
                    host["web_stack"]["technologies"].append({
                        "name": tech_name,
                        "version": version,
                        "category": category,
                    })
                    added += 1
            LOGGER.info("Wappalyzer: added %d new tech entries for %s", added, target)
            return
        except Exception as exc:
            LOGGER.warning("Wappalyzer attempt %s failed for %s: %s", attempt + 1, target, exc)


def run_command(command, timeout=20):
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return completed.stdout or ""
    except subprocess.TimeoutExpired as exc:
        # Preserve whatever stdout was captured before the kill so slow scans
        # still surface partial nmap/sslscan output instead of zeroing out.
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        LOGGER.warning(
            "Command timed out for %s (returning %d bytes of partial output)",
            command, len(partial),
        )
        return partial
    except FileNotFoundError as exc:
        LOGGER.warning("Command failed for %s: %s", command, exc)
        return ""


def resolve_host_ip(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return ""


def is_host_alive(hostname: str, timeout: int = 4) -> bool:
    """Return True if the host is reachable — DNS resolves AND a TCP port responds.

    Strategy:
      1. DNS resolution — if the name doesn't resolve the host is definitely dead.
      2. TCP connect on ports 80, 443, then 22 with a short timeout.
         Any successful connect (even a refused/reset) means the host is up.

    Avoids ICMP ping which is blocked on most cloud/CDN hosts.
    """
    # Step 1: DNS must resolve
    ip = resolve_host_ip(hostname)
    if not ip:
        LOGGER.info("Liveness: %s — DNS failed, skipping", hostname)
        return False

    # Step 2: TCP connect on common ports
    for port in (80, 443, 22):
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                LOGGER.info("Liveness: %s — alive (TCP:%d)", hostname, port)
                return True
        except ConnectionRefusedError:
            # Port actively refused — host is up, just not running this service
            LOGGER.info("Liveness: %s — alive (port %d refused, host up)", hostname, port)
            return True
        except (socket.timeout, OSError):
            continue

    LOGGER.info("Liveness: %s — no response on ports 80/443/22, skipping", hostname)
    return False


def _categorize_wappalyzer_name(name):
    lowered = name.lower()
    if lowered in {"wordpress", "drupal", "joomla"}:
        return "cms"
    if lowered in {"react", "vue.js", "angular", "next.js", "django"}:
        return "framework"
    if lowered in {"jquery", "bootstrap"}:
        return "library"
    return "technology"
