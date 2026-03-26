from extensions import db
from models import Scan, ScanResult, Vulnerability
from datetime import datetime
from urllib.parse import urlparse
import time

from core.phase_runners import (
    run_dns_lookup, run_subdomain_finder, run_port_scanner,
    run_tech_fingerprint, run_http_security_check, run_auth_protection
)
from core.result_processor import (
    process_generic_results, process_http_security_results, process_auth_results
)


class ScannerEngine:
    def __init__(self, scan_id):
        self.scan_id    = scan_id
        self.scan       = None
        self.target_url = None
        self.domain     = None
        self.ip_address = None

    def update_progress(self, progress, phase):
        try:
            self.scan.progress     = progress
            self.scan.current_phase = phase
            db.session.commit()
            print(f"[Progress] {progress}% - {phase}")
        except Exception as e:
            print(f"[!] Error updating progress: {e}")
            db.session.rollback()

    def run(self):
        try:
            self.scan = Scan.query.get(self.scan_id)
            if not self.scan:
                raise Exception("Scan not found")

            self.scan.status    = 'running'
            self.scan.start_time = datetime.now()
            self.update_progress(5, "Initializing scan...")

            self.target_url = self.scan.target_url
            self.domain     = self._extract_domain(self.target_url)

            self.update_progress(10, "Reconnaissance & Information Gathering")
            dns_raw, ip = run_dns_lookup(self.domain)
            if ip:
                self.ip_address = ip
            time.sleep(0.5)

            self.update_progress(25, "Scanning subdomains...")
            subdomain_results = run_subdomain_finder(self.domain)

            self.update_progress(40, "Port scanning...")
            port_results = run_port_scanner(self.domain, self.ip_address)

            self.update_progress(55, "Technology fingerprinting...")
            tech_results = run_tech_fingerprint(self.target_url)

            self.update_progress(65, "HTTP Security Configuration Check...")
            http_results = run_http_security_check(self.target_url)

            self.update_progress(72, "Protection & Authentication Testing...")
            auth_results = run_auth_protection(self.target_url)

            self.update_progress(80, "Saving results...")
            scan_result = ScanResult(
                scans_scan_id=self.scan_id,
                total_vulnerabilities=0,
                summary=f"Scan completed. Found {len(subdomain_results)} subdomains, {len(port_results)} open ports."
            )
            db.session.add(scan_result)
            db.session.commit()

            self.update_progress(85, "Analyzing vulnerabilities...")
            process_generic_results('DNS', dns_raw, scan_result.result_id)
            process_generic_results('Subdomain',  subdomain_results, scan_result.result_id)
            process_generic_results('Port',       port_results,     scan_result.result_id)
            process_generic_results('Technology', tech_results,     scan_result.result_id)
            process_http_security_results(http_results,  scan_result.result_id)
            process_auth_results(auth_results, scan_result.result_id)

            self.update_progress(95, "Generating report...")
            scan_result.total_vulnerabilities = Vulnerability.query.filter_by(
                scan_results_result_id=scan_result.result_id
            ).count()

            self.scan.status   = 'completed'
            self.scan.end_time = datetime.now()
            self.update_progress(100, "Scan completed")

            print(f"[+] Scan completed. Total Vulns: {scan_result.total_vulnerabilities}")
            return True

        except Exception as e:
            print(f"[!] Error during scan: {e}")
            if self.scan:
                self.scan.status        = 'failed'
                self.scan.error_message = str(e)
                self.update_progress(0, f"Scan failed: {str(e)}")
            return False

    def _extract_domain(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        return domain.replace('www.', '').replace('http://', '').replace('https://', '')
