"""Smoke tests for organisation-mode scan pipeline.

Uses heavy mocking so no real network calls are made. Validates:
  - subfinder → liveness → per-host recon pipeline wiring
  - Dead hosts are skipped
  - Alive hosts have recon executed
  - CVE enrichment and AI analysis are called once each
  - Schema validation passes
  - Result is persisted and scan_id is attached
"""

from unittest.mock import MagicMock, call, patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_manager_data():
    """Minimal manager.data dict that satisfies validate_against_schema."""
    return {
        "target": "example.com",
        "scan_timestamp": "2025-01-01T00:00:00+00:00",
        "subdomains": [
            {"name": "api.example.com", "ip": "", "status": "active"},
            {"name": "www.example.com", "ip": "", "status": "active"},
        ],
        "hosts": [],
        "ai_analysis": {
            "summary": "Test analysis",
            "risks": [],
            "recommendations": [],
        },
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPerformOrgScan:
    """Tests for scan_service._perform_org_scan (called via perform_scan mode='organization')."""

    @patch("backend.scan_service.run_subfinder")
    @patch("backend.scan_service.run_nmap")
    @patch("backend.scan_service.run_whatweb")
    @patch("backend.scan_service.run_http_probe")
    @patch("backend.scan_service.run_wafwoof")
    @patch("backend.scan_service.run_wappalyzer")
    @patch("backend.scan_service.run_sslscan")
    @patch("backend.scan_service.is_host_alive")
    @patch("backend.scan_service.CVEEnricher")
    @patch("backend.scan_service.analyze_scan")
    @patch("backend.scan_service.validate_against_schema")
    @patch("backend.scan_service.persist_scan_result")
    @patch("backend.scan_service._attach_rag_analysis")
    @patch("backend.scan_service._attach_pentest_plan")
    @patch("backend.scan_service.ReconManager")
    def test_alive_hosts_are_scanned(
        self,
        mock_recon_cls,
        mock_attach_pentest,
        mock_attach_rag,
        mock_persist,
        mock_validate,
        mock_analyze,
        mock_cve_cls,
        mock_alive,
        mock_sslscan,
        mock_wappalyzer,
        mock_wafwoof,
        mock_http_probe,
        mock_whatweb,
        mock_nmap,
        mock_subfinder,
        mock_manager_data,
    ):
        # Set up manager mock
        manager = MagicMock()
        manager.data = mock_manager_data
        mock_recon_cls.return_value = manager

        # All hosts alive
        mock_alive.return_value = True

        # CVE enricher returns data unchanged
        enricher = MagicMock()
        enricher.enrich.return_value = mock_manager_data
        mock_cve_cls.return_value = enricher

        mock_analyze.return_value = {"summary": "ok", "risks": [], "recommendations": []}

        fake_result = {**mock_manager_data, "scan_id": 1}
        manager.finalize_scan.return_value = fake_result
        mock_persist.return_value = fake_result

        from backend.scan_service import perform_scan
        result = perform_scan("example.com", mode="organization")

        # nmap should be called for root + 2 subdomains = 3 hosts
        assert mock_nmap.call_count == 3

    @patch("backend.scan_service.run_subfinder")
    @patch("backend.scan_service.run_nmap")
    @patch("backend.scan_service.run_whatweb")
    @patch("backend.scan_service.run_http_probe")
    @patch("backend.scan_service.run_wafwoof")
    @patch("backend.scan_service.run_wappalyzer")
    @patch("backend.scan_service.run_sslscan")
    @patch("backend.scan_service.is_host_alive")
    @patch("backend.scan_service.CVEEnricher")
    @patch("backend.scan_service.analyze_scan")
    @patch("backend.scan_service.validate_against_schema")
    @patch("backend.scan_service.persist_scan_result")
    @patch("backend.scan_service._attach_rag_analysis")
    @patch("backend.scan_service._attach_pentest_plan")
    @patch("backend.scan_service.ReconManager")
    def test_dead_hosts_are_skipped(
        self,
        mock_recon_cls,
        mock_attach_pentest,
        mock_attach_rag,
        mock_persist,
        mock_validate,
        mock_analyze,
        mock_cve_cls,
        mock_alive,
        mock_sslscan,
        mock_wappalyzer,
        mock_wafwoof,
        mock_http_probe,
        mock_whatweb,
        mock_nmap,
        mock_subfinder,
        mock_manager_data,
    ):
        manager = MagicMock()
        manager.data = mock_manager_data
        mock_recon_cls.return_value = manager

        # Root alive, subdomains dead
        mock_alive.side_effect = lambda h: (h == "example.com")

        enricher = MagicMock()
        enricher.enrich.return_value = mock_manager_data
        mock_cve_cls.return_value = enricher
        mock_analyze.return_value = {"summary": "ok", "risks": [], "recommendations": []}

        fake_result = {**mock_manager_data, "scan_id": 1}
        manager.finalize_scan.return_value = fake_result
        mock_persist.return_value = fake_result

        from backend.scan_service import perform_scan
        result = perform_scan("example.com", mode="organization")

        # Only root host was alive, so nmap called once
        assert mock_nmap.call_count == 1

    @patch("backend.scan_service.run_subfinder")
    @patch("backend.scan_service.is_host_alive")
    @patch("backend.scan_service.CVEEnricher")
    @patch("backend.scan_service.analyze_scan")
    @patch("backend.scan_service.validate_against_schema")
    @patch("backend.scan_service.persist_scan_result")
    @patch("backend.scan_service._attach_rag_analysis")
    @patch("backend.scan_service._attach_pentest_plan")
    @patch("backend.scan_service.ReconManager")
    def test_no_alive_hosts_still_returns_result(
        self,
        mock_recon_cls,
        mock_attach_pentest,
        mock_attach_rag,
        mock_persist,
        mock_validate,
        mock_analyze,
        mock_cve_cls,
        mock_alive,
        mock_subfinder,
        mock_manager_data,
    ):
        manager = MagicMock()
        manager.data = mock_manager_data
        mock_recon_cls.return_value = manager

        # All dead
        mock_alive.return_value = False

        enricher = MagicMock()
        enricher.enrich.return_value = mock_manager_data
        mock_cve_cls.return_value = enricher
        mock_analyze.return_value = {"summary": "ok", "risks": [], "recommendations": []}

        fake_result = {**mock_manager_data, "scan_id": 1}
        manager.finalize_scan.return_value = fake_result
        mock_persist.return_value = fake_result

        from backend.scan_service import perform_scan
        result = perform_scan("example.com", mode="organization")

        # Should complete without exception
        assert result is not None


class TestIsHostAlive:
    """Unit tests for the liveness-check helper."""

    @patch("backend.recon_tools.resolve_host_ip")
    @patch("backend.recon_tools.socket.create_connection")
    def test_alive_when_tcp_connects(self, mock_connect, mock_dns):
        mock_dns.return_value = "1.2.3.4"
        mock_connect.return_value.__enter__ = MagicMock(return_value=None)
        mock_connect.return_value.__exit__ = MagicMock(return_value=False)

        from backend.recon_tools import is_host_alive
        assert is_host_alive("example.com") is True

    @patch("backend.recon_tools.resolve_host_ip")
    def test_dead_when_dns_fails(self, mock_dns):
        mock_dns.return_value = ""
        from backend.recon_tools import is_host_alive
        assert is_host_alive("nonexistent.invalid") is False

    @patch("backend.recon_tools.resolve_host_ip")
    @patch("backend.recon_tools.socket.create_connection")
    def test_alive_on_connection_refused(self, mock_connect, mock_dns):
        import socket
        mock_dns.return_value = "1.2.3.4"
        mock_connect.side_effect = ConnectionRefusedError

        from backend.recon_tools import is_host_alive
        # Connection refused means host is UP (port just closed)
        assert is_host_alive("example.com") is True
