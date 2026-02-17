import dns.resolver
import dns.exception
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
                    self.results[record_type] = future.result()
                    self.query_times[record_type] = time.time() - start_time
                except Exception:
                    self.results[record_type] = []
                    self.query_times[record_type] = 0.0
        
        total_time = time.time() - start_time
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
