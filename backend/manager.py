import logging

from backend import db_service
from backend.schema_utils import clone_schema_section, create_scan_result


LOGGER = logging.getLogger(__name__)


class ReconManager:
    def __init__(self, target, scan_id=None):
        self.data = create_scan_result(target)
        # Pre-allocated scan_id from the async /start-scan path.
        # When present, finalize_scan() UPDATEs this row instead of INSERTing.
        self._pending_scan_id = scan_id

    def add_subdomains(self, subdomains):
        existing = {item["name"] for item in self.data["subdomains"]}
        for subdomain in subdomains:
            name = subdomain["name"]
            if name not in existing:
                self.data["subdomains"].append(subdomain)
                existing.add(name)

    def get_or_create_host(self, hostname, ip=""):
        for host in self.data["hosts"]:
            if host["hostname"] == hostname:
                if ip and not host["ip"]:
                    host["ip"] = ip
                return host

        host_template = clone_schema_section(["hosts", 0])
        host_template["hostname"] = hostname
        host_template["ip"] = ip
        host_template["waf"] = {"detected": False, "name": ""}
        host_template["http"] = {"status_code": 0, "headers": []}
        host_template["services"] = []
        host_template["tls"] = {
            "supported_versions": [],
            "weak_protocols": [],
            "weak_ciphers": [],
            "certificate_expired": False,
        }
        host_template["web_stack"] = {
            "server": {"name": "", "version": ""},
            "technologies": [],
        }
        self.data["hosts"].append(host_template)
        return host_template

    def add_service(self, hostname, service, ip=""):
        host = self.get_or_create_host(hostname, ip=ip)
        existing = next(
            (
                item
                for item in host["services"]
                if item["port"] == service["port"] and item["protocol"] == service["protocol"]
            ),
            None,
        )

        if existing is None:
            host["services"].append(service)
            return service

        existing.update(service)
        return existing

    def finalize_scan(self):
        """Persist the assembled scan result and attach its database id."""
        scan_id = db_service.save_scan(
            self.data["target"],
            self.data["scan_timestamp"],
            self.data,
            scan_id=self._pending_scan_id,
        )
        self.data["scan_id"] = scan_id
        return self.data


def persist_scan_result(result, scan_id=None):
    """Persist an already assembled scan result and attach its database id."""
    assigned_id = db_service.save_scan(
        result["target"],
        result["scan_timestamp"],
        result,
        scan_id=scan_id,
    )
    result["scan_id"] = assigned_id
    return result
