"""Shared pytest fixtures for AIASDP2 tests."""

import json
import sys
from pathlib import Path

import pytest

# Ensure the project root is on sys.path so ``from backend import ...`` works
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


# ---------------------------------------------------------------------------
# Minimal scan-result fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def minimal_scan():
    """A minimal scan result dict that satisfies the schema."""
    return {
        "target": "example.com",
        "scan_timestamp": "2025-01-01T00:00:00+00:00",
        "subdomains": [],
        "hosts": [],
        "ai_analysis": {
            "summary": "Test scan",
            "risks": [],
            "recommendations": [],
        },
    }


@pytest.fixture
def scan_with_host(minimal_scan):
    """A scan result with one host, one service, and one CVE match."""
    minimal_scan["hosts"] = [
        {
            "hostname": "example.com",
            "ip": "93.184.216.34",
            "services": [
                {
                    "port": 443,
                    "protocol": "tcp",
                    "status": "open",
                    "service_name": "https",
                    "product": "nginx",
                    "version": "1.24.0",
                    "scripts": [],
                    "cve_matches": [
                        {
                            "cve_id": "CVE-2023-44487",
                            "description": "HTTP/2 Rapid Reset Attack",
                            "severity": "HIGH",
                            "cvss_score": 7.5,
                            "confidence": "medium",
                        }
                    ],
                }
            ],
            "waf": {"detected": False, "name": ""},
            "http": {"status_code": 200, "headers": []},
            "tls": {
                "supported_versions": ["TLSv1.2", "TLSv1.3"],
                "weak_protocols": [],
                "weak_ciphers": [],
                "certificate_expired": False,
            },
            "web_stack": {
                "server": {"name": "nginx", "version": "1.24.0"},
                "technologies": [],
            },
        }
    ]
    return minimal_scan


@pytest.fixture
def nmap_sample_output():
    return """\
Starting Nmap 7.94
Nmap scan report for example.com (93.184.216.34)
Host is up.

PORT    STATE SERVICE    VERSION
80/tcp  open  http       nginx 1.24.0
443/tcp open  https      nginx 1.24.0
22/tcp  open  ssh        OpenSSH 8.9 p1 Ubuntu 3ubuntu0.6

Nmap done: 1 IP address (1 host up) scanned in 2.34 seconds
"""


@pytest.fixture
def sslscan_sample_output():
    # Modern server: only TLSv1.2 and TLSv1.3 are enabled.
    # TLSv1.0 / TLSv1.1 intentionally absent so they do NOT appear as supported.
    return """\
Version: 2.1.3
OpenSSL 3.0.2

Testing SSL server example.com on port 443

  Supported Server Cipher(s):
    Preferred TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384
    Preferred TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384

  SSL/TLS Protocols:
TLSv1.2   enabled
TLSv1.3   enabled
"""


@pytest.fixture
def waf_detected_output():
    return "[+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF."


@pytest.fixture
def waf_not_detected_output():
    return "[*] Checking https://example.com\n[-] No WAF detected by the generic detection"
