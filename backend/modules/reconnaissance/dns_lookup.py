import dns.resolver
import dns.exception
import dns.query
import dns.zone
from typing import Dict, List, Any, Optional
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class DNSLookup:
    def __init__(self, domain: str, timeout: float = 5.0, max_workers: int = 6):
        """
        Advanced DNS Lookup dengan timeout & parallel processing
        
        Args:
            domain: Target domain
            timeout: Query timeout per record type (detik)
            max_workers: Max concurrent DNS queries
        """
        self.domain = domain
        self.timeout = timeout
        self.max_workers = max_workers
        self.results: Dict[str, List[Any]] = {}
        self.query_times: Dict[str, float] = {}

    def run(self) -> Dict[str, Any]:
        """Run semua DNS queries secara parallel"""
        record_types = [
            ('A', self._get_a_records),
            ('AAAA', self._get_aaaa_records),
            ('MX', self._get_mx_records),
            ('NS', self._get_ns_records),
            ('TXT', self._get_txt_records),
            ('CNAME', self._get_cname_records),
            ('SOA', self._get_soa_records),
        ]

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_record = {
                executor.submit(func, self.domain, self.timeout): record_type
                for record_type, func in record_types
            }

            for future in as_completed(future_to_record):
                record_type = future_to_record[future]
                try:
                    result = future.result()

                    # --- [PERBAIKAN DI SINI] ---
                    # Hanya simpan ke results jika list TIDAK KOSONG.
                    # Ini mencegah munculnya "[]" di database/laporan.
                    if result:
                        self.results[record_type] = result
                    # ---------------------------

                    self.query_times[record_type] = time.time() - start_time
                except Exception:
                    # Jika error, jangan simpan key-nya sama sekali
                    self.query_times[record_type] = 0.0

        total_time = time.time() - start_time

        # Metadata selalu disimpan
        self.results['metadata'] = {
            'total_queries': len(record_types),
            'total_time': round(total_time, 2),
            'domain': self.domain,
            'timestamp': time.time()
        }

        return self.results

    def _get_a_records(self, domain: str, timeout: float) -> List[str]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            answers = resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except (dns.exception.DNSException, Exception):
            return []

    def _get_aaaa_records(self, domain: str, timeout: float) -> List[str]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            answers = resolver.resolve(domain, 'AAAA')
            return [str(rdata) for rdata in answers]
        except (dns.exception.DNSException, Exception):
            return []

    def _get_mx_records(self, domain: str, timeout: float) -> List[Dict[str, Any]]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            answers = resolver.resolve(domain, 'MX')
            return [
                {
                    'priority': rdata.preference,
                    'mail_server': str(rdata.exchange),
                    'weight': rdata.preference
                } for rdata in answers
            ]
        except (dns.exception.DNSException, Exception):
            return []

    def _get_ns_records(self, domain: str, timeout: float) -> List[str]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            answers = resolver.resolve(domain, 'NS')
            return [str(rdata) for rdata in answers]
        except (dns.exception.DNSException, Exception):
            return []

    def _get_txt_records(self, domain: str, timeout: float) -> List[str]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            answers = resolver.resolve(domain, 'TXT')
            return [str(rdata).strip('"') for rdata in answers]
        except (dns.exception.DNSException, Exception):
            return []

    def _get_cname_records(self, domain: str, timeout: float) -> List[str]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            answers = resolver.resolve(domain, 'CNAME')
            return [str(rdata) for rdata in answers]
        except (dns.exception.DNSException, Exception):
            return []

    def _get_soa_records(self, domain: str, timeout: float) -> List[Dict[str, Any]]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            answers = resolver.resolve(domain, 'SOA')
            soa = answers[0]
            return [{
                'mname': str(soa.mname),
                'rname': str(soa.rname),
                'serial': soa.serial,
                'refresh': soa.refresh,
                'retry': soa.retry,
                'expire': soa.expire,
                'minimum': soa.minimum
            }]
        except (dns.exception.DNSException, Exception):
            return []

    def get_summary(self) -> Dict[str, int]:
        """Ringkasan jumlah records per type"""
        return {
            'total_records': sum(len(records) for records in self.results.values() if isinstance(records, list)),
            'record_counts': {
                k: len(v) for k, v in self.results.items()
                if k != 'metadata' and isinstance(v, list)
            }
        }

    def is_responsive(self) -> bool:
        """Cek apakah domain punya minimal 1 A record"""
        return bool(self.results.get('A', []))

    def enrich_analysis(self) -> Dict[str, Any]:
        """Email provider, registrar, security analysis"""
        analysis = {}

        # 1. EMAIL PROVIDER dari MX
        mx_servers = [mx['mail_server'] for mx in self.results.get('MX', [])]
        analysis['email_provider'] = self._detect_email_provider(mx_servers)

        # 2. NAMESERVER PROVIDER dari NS
        ns_servers = self.results.get('NS', [])
        analysis['nameserver_provider'] = self._detect_ns_provider(ns_servers)

        # 3. EMAIL SECURITY (SPF/DKIM/DMARC)
        txt_records = self.results.get('TXT', [])
        analysis['email_security'] = self._analyze_email_security(txt_records)

        # 4. WHOIS/REGISTRAR hints dari TXT
        analysis['registrar_hints'] = self._extract_registrar_hints(txt_records)

        return analysis

    def _detect_email_provider(self, mx_servers: List[str]) -> str:
        """Detect Google Workspace, Zoho, MS365, etc"""
        providers = {
            'google.com': 'Google Workspace (Gmail)',
            'zoho.com': 'Zoho Mail',
            'outlook.com': 'Microsoft 365',
            'mailgun.org': 'Mailgun',
            'sendgrid.net': 'SendGrid',
            'amazonses.com': 'AWS SES'
        }

        for server in mx_servers:
            for domain, name in providers.items():
                if domain in server.lower():
                    return name
        return 'Custom/Private MX' if mx_servers else 'None'

    def _detect_ns_provider(self, ns_servers: List[str]) -> str:
        """Cloudflare, AWS Route53, etc"""
        providers = {
            'cloudflare.com': 'Cloudflare',
            'aws.com': 'AWS Route53',
            'google.com': 'Google Cloud DNS',
            'azure.com': 'Azure DNS',
            'digitalocean.com': 'DigitalOcean'
        }

        for ns in ns_servers:
            for domain, name in providers.items():
                if domain in ns.lower():
                    return name
        return 'Custom NS'

    def _analyze_email_security(self, txt_records: List[str]) -> Dict[str, bool]:
        """SPF, DKIM, DMARC status"""
        spf = any('v=spf1' in txt.lower() for txt in txt_records)
        dkim = any('v=DKIM1' in txt for txt in txt_records)
        dmarc = any('v=DMARC1' in txt for txt in txt_records)

        return {
            'spf': spf,
            'dkim': dkim,
            'dmarc': dmarc,
            'secure': spf and dmarc
        }

    def _extract_registrar_hints(self, txt_records: List[str]) -> List[str]:
        """Registrar hints dari TXT"""
        hints = []
        registrars = ['namecheap', 'godaddy', 'domains.google']

        for txt in txt_records:
            for reg in registrars:
                if reg in txt.lower():
                    hints.append(reg.title())

        return hints if hints else ['Unknown']

    # =========================================================
    # TAMBAHAN BARU — VULN MARKING (tidak ubah kode di atas)
    # =========================================================

    def enrich_with_vuln(self) -> List[Dict]:
        """
        Analisis hasil DNS dan return list of findings dengan vuln_key.
        Dipanggil SETELAH run().
        
        Returns:
            List of dict dengan format:
            {'subdomain': str, 'vuln_key': str, 'detail': str}
            Format 'subdomain' dipakai agar kompatibel dengan
            _process_and_save_results() di scanner_engine.py
        """
        findings = []
        txt_records = self.results.get('TXT', [])
        a_records = self.results.get('A', [])
        cname_records = self.results.get('CNAME', [])
        ns_records = self.results.get('NS', [])
        email_sec = self._analyze_email_security(txt_records)

        # 1. General DNS disclosure (selalu ada jika DNS resolve berhasil)
        if a_records:
            findings.append({
                'subdomain': self.domain,
                'vuln_key': 'DNS_LOOKUP',
                'detail': f"A records terekspos: {', '.join(a_records)}"
            })

        # 2. SPF missing
        if not email_sec['spf']:
            findings.append({
                'subdomain': self.domain,
                'vuln_key': 'DNS_SPF_MISSING',
                'detail': 'SPF record tidak ditemukan pada domain ini'
            })

        # 3. DMARC missing
        if not email_sec['dmarc']:
            findings.append({
                'subdomain': self.domain,
                'vuln_key': 'DNS_DMARC_MISSING',
                'detail': 'DMARC record tidak ditemukan pada domain ini'
            })

        # 4. DKIM missing
        if not email_sec['dkim']:
            findings.append({
                'subdomain': self.domain,
                'vuln_key': 'DNS_DKIM_MISSING',
                'detail': 'DKIM record tidak ditemukan pada domain ini'
            })

        # 5. Internal IP exposed via A record
        internal_ranges = ('10.', '192.168.', '172.16.', '172.17.',
                           '172.18.', '172.19.', '172.20.', '172.21.',
                           '172.22.', '172.23.', '172.24.', '172.25.',
                           '172.26.', '172.27.', '172.28.', '172.29.',
                           '172.30.', '172.31.')
        for ip in a_records:
            if any(ip.startswith(prefix) for prefix in internal_ranges):
                findings.append({
                    'subdomain': self.domain,
                    'vuln_key': 'DNS_INTERNAL_IP_EXPOSED',
                    'detail': f'IP internal RFC1918 terekspos via DNS: {ip}'
                })

        # 6. Wildcard CNAME
        for cname in cname_records:
            if cname.startswith('*'):
                findings.append({
                    'subdomain': self.domain,
                    'vuln_key': 'DNS_WILDCARD_RECORD',
                    'detail': f'Wildcard CNAME record ditemukan: {cname}'
                })

        # 7. Zone Transfer (AXFR) — coba ke semua nameserver
        zone_transfer_result = self._check_zone_transfer(ns_records)
        if zone_transfer_result:
            findings.append({
                'subdomain': self.domain,
                'vuln_key': 'DNS_ZONE_TRANSFER',
                'detail': f'Zone Transfer berhasil via NS: {zone_transfer_result}'
            })

        return findings

    def _check_zone_transfer(self, ns_records: List[str]) -> Optional[str]:
        """
        Coba AXFR (Zone Transfer) ke semua nameserver.
        Return nama NS yang vulnerable, atau None jika semua aman.
        """
        for ns in ns_records:
            ns_clean = ns.rstrip('.')
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_clean, self.domain, timeout=self.timeout)
                )
                if zone:
                    return ns_clean
            except Exception:
                # AXFR ditolak = aman, lanjut ke NS berikutnya
                continue
        return None
