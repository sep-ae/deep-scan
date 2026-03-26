import dns.resolver
import dns.exception
import dns.query
import dns.zone
from typing import Dict, List, Any
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class DNSLookup:
    def __init__(self, domain: str, timeout: float = 5.0, max_workers: int = 6):
        self.domain      = domain
        self.timeout     = timeout
        self.max_workers = max_workers
        self.results: Dict[str, List[Any]] = {}
        self.query_times: Dict[str, float] = {}

    def run(self) -> Dict[str, Any]:
        record_types = [
            ('A',     self._get_a_records),
            ('AAAA',  self._get_aaaa_records),
            ('MX',    self._get_mx_records),
            ('NS',    self._get_ns_records),
            ('TXT',   self._get_txt_records),
            ('CNAME', self._get_cname_records),
            ('SOA',   self._get_soa_records),
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
                    if result:
                        self.results[record_type] = result
                    self.query_times[record_type] = time.time() - start_time
                except Exception:
                    self.query_times[record_type] = 0.0

        self.results['metadata'] = {
            'total_queries': len(record_types),
            'total_time':    round(time.time() - start_time, 2),
            'domain':        self.domain,
            'timestamp':     time.time()
        }

        return self.results

    def _get_a_records(self, domain: str, timeout: float) -> List[str]:
        try:
            r = dns.resolver.Resolver()
            r.timeout = r.lifetime = timeout
            return [str(rd) for rd in r.resolve(domain, 'A')]
        except Exception:
            return []

    def _get_aaaa_records(self, domain: str, timeout: float) -> List[str]:
        try:
            r = dns.resolver.Resolver()
            r.timeout = r.lifetime = timeout
            return [str(rd) for rd in r.resolve(domain, 'AAAA')]
        except Exception:
            return []

    def _get_mx_records(self, domain: str, timeout: float) -> List[Dict[str, Any]]:
        try:
            r = dns.resolver.Resolver()
            r.timeout = r.lifetime = timeout
            return [
                {'priority': rd.preference, 'mail_server': str(rd.exchange)}
                for rd in r.resolve(domain, 'MX')
            ]
        except Exception:
            return []

    def _get_ns_records(self, domain: str, timeout: float) -> List[str]:
        try:
            r = dns.resolver.Resolver()
            r.timeout = r.lifetime = timeout
            return [str(rd) for rd in r.resolve(domain, 'NS')]
        except Exception:
            return []

    def _get_txt_records(self, domain: str, timeout: float) -> List[str]:
        try:
            r = dns.resolver.Resolver()
            r.timeout = r.lifetime = timeout
            return [str(rd).strip('"') for rd in r.resolve(domain, 'TXT')]
        except Exception:
            return []

    def _get_cname_records(self, domain: str, timeout: float) -> List[str]:
        try:
            r = dns.resolver.Resolver()
            r.timeout = r.lifetime = timeout
            return [str(rd) for rd in r.resolve(domain, 'CNAME')]
        except Exception:
            return []

    def _get_soa_records(self, domain: str, timeout: float) -> List[Dict[str, Any]]:
        try:
            r   = dns.resolver.Resolver()
            r.timeout = r.lifetime = timeout
            soa = r.resolve(domain, 'SOA')[0]
            return [{
                'mname':   str(soa.mname),
                'rname':   str(soa.rname),
                'serial':  soa.serial,
                'refresh': soa.refresh,
                'retry':   soa.retry,
                'expire':  soa.expire,
                'minimum': soa.minimum
            }]
        except Exception:
            return []

    def get_summary(self) -> Dict[str, int]:
        return {
            'total_records': sum(
                len(v) for v in self.results.values() if isinstance(v, list)
            ),
            'record_counts': {
                k: len(v) for k, v in self.results.items()
                if k != 'metadata' and isinstance(v, list)
            }
        }

    def is_responsive(self) -> bool:
        return bool(self.results.get('A', []))

    def enrich_analysis(self) -> Dict[str, Any]:
        mx_servers = [mx['mail_server'] for mx in self.results.get('MX', [])]
        ns_servers = self.results.get('NS', [])
        txt_records = self.results.get('TXT', [])

        return {
            'email_provider':      self._detect_email_provider(mx_servers),
            'nameserver_provider': self._detect_ns_provider(ns_servers),
            'email_security':      self._analyze_email_security(txt_records),
            'registrar_hints':     self._extract_registrar_hints(txt_records),
        }

    def _detect_email_provider(self, mx_servers: List[str]) -> str:
        providers = {
            'google.com':    'Google Workspace (Gmail)',
            'zoho.com':      'Zoho Mail',
            'outlook.com':   'Microsoft 365',
            'mailgun.org':   'Mailgun',
            'sendgrid.net':  'SendGrid',
            'amazonses.com': 'AWS SES'
        }
        for server in mx_servers:
            for domain, name in providers.items():
                if domain in server.lower():
                    return name
        return 'Custom/Private MX' if mx_servers else 'None'

    def _detect_ns_provider(self, ns_servers: List[str]) -> str:
        providers = {
            'cloudflare.com':   'Cloudflare',
            'aws.com':          'AWS Route53',
            'google.com':       'Google Cloud DNS',
            'azure.com':        'Azure DNS',
            'digitalocean.com': 'DigitalOcean'
        }
        for ns in ns_servers:
            for domain, name in providers.items():
                if domain in ns.lower():
                    return name
        return 'Custom NS'

    def _analyze_email_security(self, txt_records: List[str]) -> Dict[str, bool]:
        spf   = any('v=spf1'  in t.lower() for t in txt_records)
        dkim  = any('v=DKIM1' in t         for t in txt_records)
        dmarc = any('v=DMARC1' in t        for t in txt_records)
        return {'spf': spf, 'dkim': dkim, 'dmarc': dmarc, 'secure': spf and dmarc}

    def _extract_registrar_hints(self, txt_records: List[str]) -> List[str]:
        registrars = ['namecheap', 'godaddy', 'domains.google']
        hints = [
            reg.title()
            for txt in txt_records
            for reg in registrars
            if reg in txt.lower()
        ]
        return hints if hints else ['Unknown']