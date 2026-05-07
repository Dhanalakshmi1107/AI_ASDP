"""Tests for backend/parsers.py — all functions, no external dependencies."""

import pytest

from backend.parsers import (
    extract_version,
    parse_http_output,
    parse_nmap_output,
    parse_sslscan_output,
    parse_subfinder_output,
    parse_waf_output,
    parse_whatweb_output,
    split_product_version,
)


# ---------------------------------------------------------------------------
# parse_subfinder_output
# ---------------------------------------------------------------------------

class TestParseSubfinderOutput:
    def test_returns_subdomains_under_target(self):
        output = "api.example.com\nwww.example.com\nblog.example.com\n"
        results = parse_subfinder_output(output, "example.com")
        names = [r["name"] for r in results]
        assert "api.example.com" in names
        assert "www.example.com" in names
        assert "blog.example.com" in names

    def test_excludes_unrelated_domains(self):
        output = "api.example.com\nevil.notexample.com\n"
        results = parse_subfinder_output(output, "example.com")
        names = [r["name"] for r in results]
        assert "evil.notexample.com" not in names

    def test_does_not_include_unrelated_root(self):
        """Subdomains of a *different* domain must not appear in results."""
        output = "www.example.com\nother.com\n"
        results = parse_subfinder_output(output, "example.com")
        names = [r["name"] for r in results]
        assert "other.com" not in names
        assert "www.example.com" in names

    def test_deduplicates(self):
        output = "api.example.com\napi.example.com\n"
        results = parse_subfinder_output(output, "example.com")
        assert len(results) == 1

    def test_empty_output(self):
        assert parse_subfinder_output("", "example.com") == []

    def test_result_structure(self):
        output = "api.example.com\n"
        results = parse_subfinder_output(output, "example.com")
        assert results[0] == {"name": "api.example.com", "ip": "", "status": "active"}

    def test_case_insensitive_matching(self):
        output = "API.Example.COM\n"
        results = parse_subfinder_output(output, "example.com")
        assert len(results) == 1
        assert results[0]["name"] == "api.example.com"


# ---------------------------------------------------------------------------
# parse_nmap_output
# ---------------------------------------------------------------------------

class TestParseNmapOutput:
    def test_parses_open_ports(self, nmap_sample_output):
        services = parse_nmap_output(nmap_sample_output, "example.com")
        ports = [s["port"] for s in services]
        assert 80 in ports
        assert 443 in ports
        assert 22 in ports

    def test_service_fields_populated(self, nmap_sample_output):
        services = parse_nmap_output(nmap_sample_output, "example.com")
        port80 = next(s for s in services if s["port"] == 80)
        assert port80["protocol"] == "tcp"
        assert port80["service_name"] == "http"
        assert port80["product"] == "nginx"
        assert port80["version"] == "1.24.0"
        assert port80["status"] == "open"

    def test_empty_output(self):
        assert parse_nmap_output("", "example.com") == []

    def test_no_service_version(self):
        output = "22/tcp  open  ssh\n"
        services = parse_nmap_output(output, "example.com")
        assert services[0]["port"] == 22
        assert services[0]["product"] == ""
        assert services[0]["version"] == ""

    def test_cve_matches_initialized_empty(self, nmap_sample_output):
        services = parse_nmap_output(nmap_sample_output, "example.com")
        for s in services:
            assert s["cve_matches"] == []
            assert s["scripts"] == []

    def test_host_defaults_set(self, nmap_sample_output):
        services = parse_nmap_output(nmap_sample_output, "myhost.com")
        for s in services:
            assert s["host"] == "myhost.com"


# ---------------------------------------------------------------------------
# parse_http_output
# ---------------------------------------------------------------------------

class TestParseHttpOutput:
    def test_parses_status_code(self):
        raw = "HTTP/1.1 200\nContent-Type: text/html\n"
        result = parse_http_output(raw)
        assert result["status_code"] == 200

    def test_parses_headers(self):
        raw = "HTTP/1.1 200\nServer: nginx\nX-Frame-Options: DENY\n"
        result = parse_http_output(raw)
        header_names = [h["name"] for h in result["headers"]]
        assert "server" in header_names
        assert "x-frame-options" in header_names

    def test_header_names_lowercased(self):
        raw = "HTTP/1.1 200\nContent-Type: application/json\n"
        result = parse_http_output(raw)
        assert result["headers"][0]["name"] == "content-type"

    def test_empty_output(self):
        result = parse_http_output("")
        assert result["status_code"] == 0
        assert result["headers"] == []

    def test_deduplicates_headers(self):
        raw = "HTTP/1.1 200\nServer: nginx\nServer: nginx\n"
        result = parse_http_output(raw)
        server_headers = [h for h in result["headers"] if h["name"] == "server"]
        assert len(server_headers) == 1

    def test_status_code_301(self):
        raw = "HTTP/1.1 301\nLocation: https://example.com\n"
        result = parse_http_output(raw)
        assert result["status_code"] == 301


# ---------------------------------------------------------------------------
# parse_sslscan_output
# ---------------------------------------------------------------------------

class TestParseSslscanOutput:
    def test_detects_supported_versions(self, sslscan_sample_output):
        result = parse_sslscan_output(sslscan_sample_output)
        assert "TLSv1.2" in result["supported_versions"]
        assert "TLSv1.3" in result["supported_versions"]

    def test_no_weak_protocols_on_modern_tls(self, sslscan_sample_output):
        result = parse_sslscan_output(sslscan_sample_output)
        assert result["weak_protocols"] == []

    def test_detects_weak_tls10(self):
        output = "TLSv1.0   enabled\nTLSv1.2   enabled\n"
        result = parse_sslscan_output(output)
        assert "TLSv1.0" in result["weak_protocols"]
        assert "TLSv1.2" not in result["weak_protocols"]

    def test_detects_weak_ciphers(self):
        output = "TLSv1.2   enabled\nTLS_RSA_WITH_3DES_EDE_CBC_SHA\n"
        result = parse_sslscan_output(output)
        assert any("3DES" in c for c in result["weak_ciphers"])

    def test_detects_expired_cert(self):
        output = "TLSv1.2   enabled\ncertificate expired\n"
        result = parse_sslscan_output(output)
        assert result["certificate_expired"] is True

    def test_empty_output(self):
        result = parse_sslscan_output("")
        assert result["supported_versions"] == []
        assert result["weak_protocols"] == []
        assert result["certificate_expired"] is False


# ---------------------------------------------------------------------------
# parse_waf_output
# ---------------------------------------------------------------------------

class TestParseWafOutput:
    def test_detects_cloudflare(self, waf_detected_output):
        result = parse_waf_output(waf_detected_output)
        assert result["detected"] is True
        assert "cloudflare" in result["name"].lower()

    def test_no_waf_detected(self, waf_not_detected_output):
        result = parse_waf_output(waf_not_detected_output)
        assert result["detected"] is False

    def test_empty_output(self):
        result = parse_waf_output("")
        assert result == {"detected": False, "name": ""}

    def test_does_not_echo_checking_line(self):
        output = "[*] Checking https://example.com\n[*] Number of requests: 0\n"
        result = parse_waf_output(output)
        assert result["detected"] is False

    def test_aws_waf_detection(self):
        output = "[+] The site https://example.com is behind AWS ALB WAF."
        result = parse_waf_output(output)
        assert result["detected"] is True
        assert "aws" in result["name"].lower()


# ---------------------------------------------------------------------------
# split_product_version
# ---------------------------------------------------------------------------

class TestSplitProductVersion:
    def test_splits_product_and_version(self):
        assert split_product_version("nginx 1.24.0") == ("nginx", "1.24.0")

    def test_no_version(self):
        assert split_product_version("nginx") == ("nginx", "")

    def test_empty_string(self):
        assert split_product_version("") == ("", "")

    def test_multi_word_product_version_at_end(self):
        """Version extraction works when the version token is the last word."""
        product, version = split_product_version("OpenSSH 8.9p1")
        assert "OpenSSH" in product
        assert version == "8.9p1"

    def test_none_input(self):
        assert split_product_version(None) == ("", "")


# ---------------------------------------------------------------------------
# extract_version
# ---------------------------------------------------------------------------

class TestExtractVersion:
    def test_extracts_numeric_version(self):
        assert extract_version("1.24.0") == "1.24.0"

    def test_extracts_from_string(self):
        assert extract_version("nginx 1.24.0") == "1.24.0"

    def test_empty_string(self):
        assert extract_version("") == ""

    def test_none_input(self):
        assert extract_version(None) == ""
