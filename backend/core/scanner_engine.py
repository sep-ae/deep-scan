import socket
from modules.reconnaissance import DNSLookup, SubdomainFinder, PortScanner, TechFingerprint
from modules.http_security import analyze_security_headers, check_cors_misconfig
from extensions import db
from models import Scan, ScanResult, ReconData, Vulnerability
from helpers.vuln_profiles import VULN_PROFILES
from helpers.cvss_calculator import calculate_cvss
from datetime import datetime
from urllib.parse import urlparse
import time


class ScannerEngine:
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.scan = None
        self.target_url = None
        self.domain = None
        self.ip_address = None

    def update_progress(self, progress, phase):
        try:
            self.scan.progress = progress
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

            self.scan.status = 'running'
            self.scan.start_time = datetime.now()
            self.update_progress(5, "Initializing scan...")

            self.target_url = self.scan.target_url
            self.domain = self._extract_domain(self.target_url)

            print(f"[*] Starting reconnaissance for {self.domain}")

            self.update_progress(10, "Reconnaissance & Information Gathering")
            dns_raw, dns_findings = self._run_dns_lookup()
            time.sleep(0.5)

            self.update_progress(25, "Scanning subdomains...")
            subdomain_results = self._run_subdomain_finder()

            self.update_progress(40, "Port scanning...")
            port_results = self._run_port_scanner()

            self.update_progress(55, "Technology fingerprinting...")
            tech_results = self._run_tech_fingerprint()

            self.update_progress(65, "HTTP Security Configuration Check...")
            http_security_results = self._run_http_security_check()

            self.update_progress(75, "Analyzing vulnerabilities...")
            scan_result = ScanResult(
                scans_scan_id=self.scan_id,
                total_vulnerabilities=0,
                summary=f"Scan completed. Found {len(subdomain_results)} subdomains, {len(port_results)} open ports."
            )
            db.session.add(scan_result)
            db.session.commit()

            self.update_progress(85, "Web Vulnerabilities Detection")
            self._process_and_save_results('DNS', dns_raw, scan_result.result_id)
            self._process_and_save_results('DNS', dns_findings, scan_result.result_id)
            self._process_and_save_results('Subdomain', subdomain_results, scan_result.result_id)
            self._process_and_save_results('Port', port_results, scan_result.result_id)
            self._process_and_save_results('Technology', tech_results, scan_result.result_id)
            self._process_http_security_results(http_security_results, scan_result.result_id)

            self.update_progress(95, "Generating report...")
            total_v = Vulnerability.query.filter_by(scan_results_result_id=scan_result.result_id).count()
            scan_result.total_vulnerabilities = total_v

            self.scan.status = 'completed'
            self.scan.end_time = datetime.now()
            self.update_progress(100, "Scan completed")

            print(f"[+] Scan completed. Total Vulns Found: {total_v}")
            return True

        except Exception as e:
            print(f"[!] Error during scan: {e}")
            if self.scan:
                self.scan.status = 'failed'
                self.scan.error_message = str(e)
                self.update_progress(0, f"Scan failed: {str(e)}")
            return False

    def _extract_domain(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        return domain.replace('www.', '').replace('http://', '').replace('https://', '')

    def _run_dns_lookup(self):
        print(f"  [>] DNS Lookup...")
        try:
            dns_obj = DNSLookup(self.domain)
            results = dns_obj.run()
            if 'A' in results and results['A']:
                self.ip_address = results['A'][0]
            vuln_findings = dns_obj.enrich_with_vuln()
            return results, vuln_findings
        except Exception as e:
            print(f"[!] DNS Lookup error: {e}")
            return {}, []

    def _run_subdomain_finder(self):
        print(f"  [>] Subdomain Finder...")
        try:
            finder = SubdomainFinder(self.domain)
            return finder.run(max_workers=10)
        except Exception as e:
            print(f"[!] Subdomain error: {e}")
            return []

    def _run_port_scanner(self):
        try:
            if not self.ip_address:
                self.ip_address = socket.gethostbyname(self.domain)
        except:
            self.ip_address = None

        if not self.ip_address:
            return []

        print(f"  [>] Port Scanner on {self.ip_address}...")
        try:
            scanner = PortScanner(self.ip_address)
            return scanner.run()
        except Exception as e:
            print(f"[!] Port scanner error: {e}")
            return []

    def _run_tech_fingerprint(self):
        print(f"  [>] Tech Fingerprint...")
        try:
            tech = TechFingerprint(self.target_url)
            return tech.run()
        except Exception as e:
            print(f"[!] Tech fingerprint error: {e}")
            return {}

    def _run_http_security_check(self):
        print(f"  [>] HTTP Security Configuration Check...")
        try:
            headers_result = analyze_security_headers(self.target_url)
            cors_result = check_cors_misconfig(self.target_url)
            return {
                'headers': headers_result,
                'cors': cors_result
            }
        except Exception as e:
            print(f"[!] HTTP Security check error: {e}")
            return {}

    def _process_http_security_results(self, http_security_results, result_id):
        if not http_security_results:
            return

        headers_result = http_security_results.get('headers', {})
        cors_result = http_security_results.get('cors', {})

        if headers_result and not headers_result.get('error'):
            for finding in headers_result.get('findings', []):
                recon = ReconData(
                    scan_results_result_id=result_id,
                    category='HTTP Headers',
                    item=finding['header'],
                    details=str(finding)[:500]
                )
                db.session.add(recon)

            missing_headers = headers_result.get('missing', [])
            if missing_headers:
                profile = VULN_PROFILES.get('missing_security_headers')
                if profile:
                    m = profile['metrics']
                    score, severity, vector = calculate_cvss(
                        m['av'], m['ac'], m['pr'], m['ui'], m['s'], m['c'], m['i'], m['a']
                    )
                    missing_str = ', '.join(missing_headers)
                    new_vuln = Vulnerability(
                        scan_results_result_id=result_id,
                        category=profile['category'],
                        vuln_name=profile['name'],
                        severity=severity,
                        description=f"{profile['description']}\nAffected: {missing_str}\nVector: {vector}\nScore: {score}",
                        recommendation=profile['recommendation']
                    )
                    db.session.add(new_vuln)
                    print(f"  [!] Vuln found: {profile['name']}")

        if cors_result and not cors_result.get('error'):
            cors_headers = cors_result.get('cors_headers', {})
            if cors_headers:
                recon = ReconData(
                    scan_results_result_id=result_id,
                    category='CORS',
                    item='CORS Configuration',
                    details=str(cors_headers)[:500]
                )
                db.session.add(recon)

            cors_issues = cors_result.get('issues', [])
            if cors_issues:
                profile = VULN_PROFILES.get('cors_misconfiguration')
                if profile:
                    m = profile['metrics']
                    score, severity, vector = calculate_cvss(
                        m['av'], m['ac'], m['pr'], m['ui'], m['s'], m['c'], m['i'], m['a']
                    )
                    issues_str = '; '.join(cors_issues)
                    new_vuln = Vulnerability(
                        scan_results_result_id=result_id,
                        category=profile['category'],
                        vuln_name=profile['name'],
                        severity=severity,
                        description=f"{profile['description']}\nAffected: CORS Policy\nVector: {vector}\nScore: {score}\nDetail: {issues_str}",
                        recommendation=profile['recommendation']
                    )
                    db.session.add(new_vuln)
                    print(f"  [!] Vuln found: {profile['name']}")

        db.session.commit()

    def _process_and_save_results(self, category, data, result_id):
        if not data:
            return

        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    item_name = str(entry.get('subdomain') or entry.get('port') or 'Unknown')
                    details_str = str(entry)
                    vuln_key = entry.get('vuln_key')
                else:
                    item_name = str(entry)
                    details_str = str(entry)
                    vuln_key = None

                recon = ReconData(
                    scan_results_result_id=result_id,
                    category=category,
                    item=item_name[:255],
                    details=details_str[:500]
                )
                db.session.add(recon)

                if vuln_key:
                    self._create_vulnerability_entry(vuln_key, result_id, item_name)

        elif isinstance(data, dict):
            for key, value in data.items():
                recon = ReconData(
                    scan_results_result_id=result_id,
                    category=category,
                    item=str(key)[:255],
                    details=str(value)[:500]
                )
                db.session.add(recon)

        db.session.commit()

    def _create_vulnerability_entry(self, vuln_key, result_id, affected_item):
        profile = VULN_PROFILES.get(vuln_key)
        if not profile:
            return

        m = profile['metrics']
        score, severity, vector = calculate_cvss(
            m['av'], m['ac'], m['pr'], m['ui'], m['s'], m['c'], m['i'], m['a']
        )

        existing = Vulnerability.query.filter_by(
            scan_results_result_id=result_id,
            vuln_name=profile['name']
        ).first()

        if existing:
            existing.description += f"\n- Terdeteksi pada: {affected_item}"
        else:
            new_vuln = Vulnerability(
                scan_results_result_id=result_id,
                category=profile['category'],
                vuln_name=profile['name'],
                severity=severity,
                description=f"{profile['description']}\nAffected: {affected_item}\nVector: {vector}\nScore: {score}",
                recommendation=profile['recommendation']
            )
            db.session.add(new_vuln)

        db.session.commit()
