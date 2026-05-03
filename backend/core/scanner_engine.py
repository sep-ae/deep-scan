from extensions import db
from models import Scan, ScanResult, Vulnerability
from datetime import datetime
from urllib.parse import urlparse
import time

from core.phase_runners import (
    run_dns_lookup, run_subdomain_finder, run_port_scanner,
    run_tech_fingerprint, run_http_security_check, run_auth_protection,
    run_web_vulnerabilities,
)
from core.result_processor import (
    process_generic_results, process_http_security_results,
    process_auth_results, process_web_vuln_results,
)


class ScannerEngine:
    def __init__(self, scan_id):
        self.scan_id    = scan_id
        self.scan       = None
        self.target_url = None
        self.domain     = None
        self.ip_address = None

    def update_progress(self, progress: int, phase: str):
        try:
            self.scan.progress      = progress
            self.scan.current_phase = phase
            db.session.commit()
            print(f"[Progress] {progress}% - {phase}")
        except Exception as e:
            print(f"[!] Error updating progress: {e}")
            db.session.rollback()

    def run(self) -> bool:
        try:
            self.scan = db.session.get(Scan, self.scan_id)
            if not self.scan:
                raise Exception("Scan not found")

            self.scan.status     = 'running'
            self.scan.start_time = datetime.now()
            self.update_progress(5, "Initializing scan...")

            self.target_url = self.scan.target_url
            self.domain     = self._extract_domain(self.target_url)

            self.update_progress(10, "Reconnaissance & Information Gathering")
            dns_raw, ip = run_dns_lookup(self.domain)
            if ip:
                self.ip_address = ip
            time.sleep(0.3)

            self.update_progress(18, "Scanning subdomains...")
            subdomain_results = run_subdomain_finder(self.domain)

            self.update_progress(28, "Port scanning...")
            port_results = run_port_scanner(self.domain, self.ip_address)

            self.update_progress(38, "Technology fingerprinting...")
            tech_results = run_tech_fingerprint(self.target_url)

            self.update_progress(48, "HTTP Security Configuration Check...")
            http_results = run_http_security_check(self.target_url)

            self.update_progress(57, "Protection & Authentication Testing...")
            auth_results = run_auth_protection(self.target_url)

            self.update_progress(65, "Web Vulnerability Scanning...")
            web_vuln_results = run_web_vulnerabilities(
                self.target_url,
                cookies=getattr(self.scan, 'cookies', None),
            )

            self.update_progress(80, "Saving results to database...")
            scan_result = ScanResult(
                scans_scan_id=self.scan_id,
                total_vulnerabilities=0,
                summary='',
            )
            db.session.add(scan_result)
            db.session.commit()

            self.update_progress(85, "Analyzing vulnerabilities...")
            process_generic_results('DNS',        dns_raw,           scan_result.result_id)
            process_generic_results('Subdomain',  subdomain_results, scan_result.result_id)
            process_generic_results('Port',       port_results,      scan_result.result_id)
            process_generic_results('Technology', tech_results,      scan_result.result_id)
            process_http_security_results(http_results,              scan_result.result_id)
            process_auth_results(auth_results,                       scan_result.result_id)
            process_web_vuln_results(web_vuln_results,               scan_result.result_id)

            self.update_progress(95, "Generating report...")
            scan_result.total_vulnerabilities = Vulnerability.query.filter_by(
                scan_results_result_id=scan_result.result_id
            ).count()

            # --- Build comprehensive summary ---
            scan_result.summary = self._build_summary(
                dns_raw, subdomain_results, port_results, tech_results,
                web_vuln_results, scan_result.total_vulnerabilities,
            )
            db.session.commit()

            self.scan.status   = 'completed'
            self.scan.end_time = datetime.now()
            self.update_progress(100, "Scan completed")
            db.session.commit()

            print(f"[+] Scan completed. Total vulns: {scan_result.total_vulnerabilities}")
            return True

        except Exception as e:
            print(f"[!] Error during scan: {e}")
            if self.scan:
                self.scan.status        = 'failed'
                self.scan.error_message = str(e)
                self.update_progress(0, f"Scan failed: {str(e)}")
                db.session.commit()
            return False

    def _extract_domain(self, url: str) -> str:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        return domain.replace('www.', '').replace('http://', '').replace('https://', '')

    def _build_summary(self, dns_raw, subdomain_results, port_results,
                       tech_results, web_vuln_results, total_vulns) -> str:
        parts = [f"Scan completed for {self.target_url}."]

        # DNS
        dns_count = len(dns_raw) if isinstance(dns_raw, dict) else 0
        if dns_count:
            parts.append(f"DNS: {dns_count} record type(s) ditemukan.")

        # Subdomains
        sub_count = len(subdomain_results) if isinstance(subdomain_results, list) else 0
        parts.append(f"Subdomain: {sub_count} ditemukan.")

        # Ports
        port_count = len(port_results) if isinstance(port_results, list) else 0
        parts.append(f"Open Ports: {port_count} port terbuka.")

        # Technologies
        if isinstance(tech_results, dict) and tech_results:
            tech_names = []
            for key, val in tech_results.items():
                if isinstance(val, list):
                    tech_names.extend(val)
                elif isinstance(val, str):
                    tech_names.append(val)
            if tech_names:
                parts.append(f"Teknologi: {', '.join(tech_names[:5])}.")

        # Web Vulnerabilities breakdown
        if isinstance(web_vuln_results, dict):
            vuln_found = []
            for checker, result in web_vuln_results.items():
                if isinstance(result, dict) and result.get('vulnerable'):
                    label = checker.replace('_', ' ').title()
                    count = len(result.get('vulnerable_paths', []))
                    vuln_found.append(f"{label} ({count})")
            if vuln_found:
                parts.append(f"Vulnerability: {', '.join(vuln_found)}.")

        # Total
        parts.append(f"Total kerentanan: {total_vulns}.")

        return ' '.join(parts)