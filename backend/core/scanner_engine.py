from modules.reconnaissance import DNSLookup, SubdomainFinder, PortScanner, TechFingerprint
from extensions import db
from models import Scan, ScanResult, ReconData
from datetime import datetime
from urllib.parse import urlparse


class ScannerEngine:
    """
    Orkestrator utama proses scanning:
    - Ambil data Scan dari DB
    - Jalankan modul reconnaissance (DNS, Subdomain, Port, Tech)
    - Simpan ringkasan dan data detail ke database
    """

    def __init__(self, scan_id):
        """
        Inisialisasi engine untuk satu scan tertentu.
        """
        self.scan_id = scan_id
        self.scan = None
        self.target_url = None
        self.domain = None
        self.ip_address = None

    def run(self):
        try:
            # Ambil record Scan dari database
            self.scan = Scan.query.get(self.scan_id)
            if not self.scan:
                raise Exception("Scan not found")

            # Update status awal
            self.scan.status = 'Running'
            db.session.commit()

            # Ambil URL target dan extract domain
            self.target_url = self.scan.target_url
            self.domain = self._extract_domain(self.target_url)

            print(f"[*] Starting reconnaissance for {self.domain}")

            # Jalankan modul-modul reconnaissance
            dns_results = self._run_dns_lookup()
            subdomain_results = self._run_subdomain_finder()
            port_results = self._run_port_scanner()
            tech_results = self._run_tech_fingerprint()

            # Buat record ScanResult sebagai ringkasan
            scan_result = ScanResult(
                scans_scan_id=self.scan_id,
                total_vulnerabilities=0,
                summary=f"Reconnaissance completed. Found {len(subdomain_results)} subdomains, {len(port_results)} open ports."
            )
            db.session.add(scan_result)
            db.session.commit()

            # Simpan data detail ke tabel ReconData
            self._save_recon_data('DNS', dns_results, scan_result.result_id)
            self._save_recon_data('Subdomain', subdomain_results, scan_result.result_id)
            self._save_recon_data('Port', port_results, scan_result.result_id)
            self._save_recon_data('Technology', tech_results, scan_result.result_id)

            # Update status akhir
            self.scan.status = 'Completed'
            self.scan.end_time = datetime.now()
            db.session.commit()

            print(f"[+] Scan completed successfully!")
            return True

        except Exception as e:
            print(f"[!] Error during scan: {e}")
            if self.scan:
                self.scan.status = 'Failed'
                db.session.commit()
            return False

    def _extract_domain(self, url):
        """
        Ambil nama domain dari URL:
        - Hapus schema (http/https) dan prefix www.
        """
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        return domain.replace('www.', '').replace('http://', '').replace('https://', '')

    def _run_dns_lookup(self):
        """
        Jalankan modul DNSLookup dan set IP address utama untuk port scan.
        """
        print(f"  [>] DNS Lookup...")
        try:
            dns = DNSLookup(self.domain)
            results = dns.run()

            # Simpan satu IP (A record pertama) sebagai target port scan
            if results.get('A'):
                # results['A'] bisa list of dict atau list of string tergantung implementasi
                first_a = results['A'][0]
                self.ip_address = first_a['ip'] if isinstance(first_a, dict) else first_a

            return results
        except Exception as e:
            print(f"  [!] DNS Lookup error: {e}")
            return {}

    def _run_subdomain_finder(self):
        """
        Jalankan modul SubdomainFinder untuk enumerasi subdomain.
        """
        print(f"  [>] Subdomain Finder...")
        try:
            subdomain = SubdomainFinder(self.domain)
            results = subdomain.run(max_workers=5)
            return results
        except Exception as e:
            print(f"  [!] Subdomain error: {e}")
            return []

    def _run_port_scanner(self):
        """
        Jalankan modul PortScanner jika IP address sudah tersedia dari DNS lookup.
        """
        if not self.ip_address:
            print(f"  [!] Skipping port scan (no IP)")
            return []

        print(f"  [>] Port Scanner on {self.ip_address}...")
        try:
            scanner = PortScanner(self.ip_address)
            results = scanner.run(timeout=0.5, max_workers=20)
            return results
        except Exception as e:
            print(f"  [!] Port scan error: {e}")
            return []

    def _run_tech_fingerprint(self):
        """
        Jalankan modul TechFingerprint untuk identifikasi teknologi web.
        """
        print(f"  [>] Tech Fingerprint...")
        try:
            tech = TechFingerprint(self.target_url)
            results = tech.run()
            return results
        except Exception as e:
            print(f"  [!] Tech fingerprint error: {e}")
            return {}

    def _save_recon_data(self, category, data, scan_result_id):
        """
        Simpan hasil reconnaissance ke tabel ReconData.

        - category: label jenis data (DNS / Subdomain / Port / Technology)
        - data: bisa dict (key → value) atau list (kumpulan item)
        - scan_result_id: foreign key ke ScanResult yang terkait
        """
        # Jika tidak ada data, tidak perlu menyimpan apa-apa
        if not data:
            return

        try:
            # Data berbentuk dict: simpan setiap key sebagai satu baris
            if isinstance(data, dict):
                for key, value in data.items():
                    # Skip jika value kosong atau container kosong
                    if value is None or (isinstance(value, (list, dict)) and not value):
                        continue

                    recon = ReconData(
                        scan_results_result_id=scan_result_id,
                        category=category,
                        item=str(key)[:255],
                        details=str(value)[:500]
                    )
                    db.session.add(recon)

            # Data berbentuk list: simpan semua item (tanpa limit)
            elif isinstance(data, list):
                for item in data:
                    # Tentukan nama item yang paling relevan untuk kolom "item"
                    if isinstance(item, dict):
                        item_name = str(
                            item.get(
                                'subdomain',
                                item.get('port', list(item.keys())[0] if item else 'N/A')
                            )
                        )
                    else:
                        item_name = str(item)

                    recon = ReconData(
                        scan_results_result_id=scan_result_id,
                        category=category,
                        item=item_name[:255],
                        details=str(item)[:500]
                    )
                    db.session.add(recon)

            # Commit semua perubahan jika berhasil
            db.session.commit()

        except Exception as e:
            # Rollback kalau ada error saat menyimpan
            print(f"[!] Error saving recon data ({category}): {e}")
            db.session.rollback()
