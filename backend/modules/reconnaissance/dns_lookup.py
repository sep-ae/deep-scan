import dns.resolver
import dns.exception
import dns.query
import dns.zone
import dns.rdatatype
import dns.name
from typing import Dict, List, Any, Optional
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class DNSLookup:
    def __init__(self, domain: str, timeout: float = 5.0, max_workers: int = 10):
        self.domain      = domain.lower().rstrip('.')
        self.timeout     = timeout
        self.max_workers = max_workers
        self.results: Dict[str, Any]   = {}
        self.query_times: Dict[str, float] = {}

    # ── Main run ──────────────────────────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        record_types = [
            ('A',     self._get_a_records),
            ('AAAA',  self._get_aaaa_records),
            ('MX',    self._get_mx_records),
            ('NS',    self._get_ns_records),
            ('TXT',   self._get_txt_records),
            ('CNAME', self._get_cname_records),
            ('SOA',   self._get_soa_records),
            ('CAA',   self._get_caa_records),     
            ('PTR',   self._get_ptr_records),    
            ('SRV',   self._get_srv_records),      
        ]

        global_start = time.time()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_record = {
                executor.submit(self._timed_query, func, rtype): rtype
                for rtype, func in record_types
            }
            for future in as_completed(future_to_record):
                rtype = future_to_record[future]
                try:
                    records, elapsed = future.result()
                    if records:
                        self.results[rtype] = records
                    self.query_times[rtype] = round(elapsed, 3)
                except Exception:
                    self.query_times[rtype] = 0.0

        # Zone transfer — dijalankan setelah NS diketahui
        self.results['ZONE_TRANSFER'] = self._try_zone_transfer()

        # DKIM — query ke subdomain _domainkey.*
        self.results['DKIM'] = self._get_dkim_records()

        self.results['metadata'] = {
            'domain':        self.domain,
            'total_queries': len(record_types),
            'total_time':    round(time.time() - global_start, 2),
            'timestamp':     time.time(),
        }

        return self.results

    def _timed_query(self, func, rtype: str):
        """Wrapper untuk mengukur waktu per query secara akurat."""
        start   = time.time()
        records = func(self.domain, self.timeout)
        elapsed = time.time() - start
        return records, elapsed

    # ── Record queries ────────────────────────────────────────────────────────

    def _get_a_records(self, domain: str, timeout: float) -> List[str]:
        try:
            r = self._resolver(timeout)
            return [str(rd) for rd in r.resolve(domain, 'A')]
        except Exception:
            return []

    def _get_aaaa_records(self, domain: str, timeout: float) -> List[str]:
        try:
            r = self._resolver(timeout)
            return [str(rd) for rd in r.resolve(domain, 'AAAA')]
        except Exception:
            return []

    def _get_mx_records(self, domain: str, timeout: float) -> List[Dict[str, Any]]:
        try:
            r = self._resolver(timeout)
            return sorted(
                [{'priority': rd.preference, 'mail_server': str(rd.exchange)}
                 for rd in r.resolve(domain, 'MX')],
                key=lambda x: x['priority']
            )
        except Exception:
            return []

    def _get_ns_records(self, domain: str, timeout: float) -> List[str]:
        try:
            r = self._resolver(timeout)
            return sorted([str(rd) for rd in r.resolve(domain, 'NS')])
        except Exception:
            return []

    def _get_txt_records(self, domain: str, timeout: float) -> List[str]:
        try:
            r = self._resolver(timeout)
            records = []
            for rd in r.resolve(domain, 'TXT'):
                # TXT bisa multi-string — join dulu
                txt = b''.join(rd.strings).decode('utf-8', errors='replace').strip('"')
                records.append(txt)
            return records
        except Exception:
            return []

    def _get_cname_records(self, domain: str, timeout: float) -> List[str]:
        try:
            r = self._resolver(timeout)
            return [str(rd) for rd in r.resolve(domain, 'CNAME')]
        except Exception:
            return []

    def _get_soa_records(self, domain: str, timeout: float) -> List[Dict[str, Any]]:
        try:
            r   = self._resolver(timeout)
            soa = r.resolve(domain, 'SOA')[0]
            return [{
                'mname':   str(soa.mname),
                'rname':   str(soa.rname).replace('.', '@', 1),  # email format
                'serial':  soa.serial,
                'refresh': soa.refresh,
                'retry':   soa.retry,
                'expire':  soa.expire,
                'minimum': soa.minimum,
            }]
        except Exception:
            return []

    def _get_caa_records(self, domain: str, timeout: float) -> List[Dict[str, Any]]:
        """
        CAA (Certification Authority Authorization) — record yang menentukan
        CA mana yang boleh menerbitkan SSL cert untuk domain ini.
        Tidak ada CAA = siapapun bisa issue cert → risiko keamanan.
        """
        try:
            r = self._resolver(timeout)
            results = []
            for rd in r.resolve(domain, 'CAA'):
                results.append({
                    'flags': rd.flags,
                    'tag':   rd.tag.decode() if isinstance(rd.tag, bytes) else str(rd.tag),
                    'value': rd.value.decode() if isinstance(rd.value, bytes) else str(rd.value),
                })
            return results
        except Exception:
            return []

    def _get_ptr_records(self, domain: str, timeout: float) -> List[str]:
        """
        PTR — reverse DNS lookup dari A record.
        Berguna untuk fingerprinting: lihat apakah IP punya hostname bermakna.
        """
        try:
            a_records = self._get_a_records(domain, timeout)
            if not a_records:
                return []
            r       = self._resolver(timeout)
            results = []
            for ip in a_records[:3]:  # batasi 3 IP
                try:
                    rev  = dns.reversename.from_address(ip)
                    ptrs = [str(rd) for rd in r.resolve(rev, 'PTR')]
                    results.extend([{'ip': ip, 'ptr': p} for p in ptrs])
                except Exception:
                    results.append({'ip': ip, 'ptr': None})
            return results
        except Exception:
            return []

    def _get_srv_records(self, domain: str, timeout: float) -> List[Dict[str, Any]]:
        """
        SRV — service discovery. Cek common services yang mungkin expose.
        """
        common_services = [
            f'_http._tcp.{domain}',
            f'_https._tcp.{domain}',
            f'_smtp._tcp.{domain}',
            f'_imap._tcp.{domain}',
            f'_xmpp-client._tcp.{domain}',
            f'_sip._tcp.{domain}',
        ]
        results = []
        r = self._resolver(timeout)
        for service in common_services:
            try:
                for rd in r.resolve(service, 'SRV'):
                    results.append({
                        'service':  service.split('.')[0],
                        'priority': rd.priority,
                        'weight':   rd.weight,
                        'port':     rd.port,
                        'target':   str(rd.target),
                    })
            except Exception:
                continue
        return results

    # ── DKIM — query ke _domainkey subdomain ──────────────────────────────────

    def _get_dkim_records(self) -> List[Dict[str, Any]]:
        """
        DKIM tidak ada di domain utama — harus query ke:
          {selector}._domainkey.{domain}
        Coba common selectors yang sering dipakai.
        """
        common_selectors = [
            'default', 'mail', 'google', 'k1', 'k2',
            'selector1', 'selector2',   # Microsoft 365
            'dkim', 'smtp', 'email',
            's1', 's2', 'key1', 'key2',
        ]
        found   = []
        r       = self._resolver(self.timeout)

        for selector in common_selectors:
            subdomain = f'{selector}._domainkey.{self.domain}'
            try:
                for rd in r.resolve(subdomain, 'TXT'):
                    txt = b''.join(rd.strings).decode('utf-8', errors='replace')
                    if 'v=dkim1' in txt.lower() or 'p=' in txt.lower():
                        found.append({
                            'selector': selector,
                            'record':   subdomain,
                            'value':    txt[:120] + ('...' if len(txt) > 120 else ''),
                        })
                        break
            except Exception:
                continue

        return found

    # ── Zone Transfer ─────────────────────────────────────────────────────────

    def _try_zone_transfer(self) -> Dict[str, Any]:
        """
        Coba AXFR (zone transfer) ke setiap NS server.
        Kalau berhasil = misconfiguration serius — NS membocorkan seluruh zone.
        """
        ns_servers = self.results.get('NS', [])
        result = {
            'attempted':  len(ns_servers),
            'vulnerable': False,
            'servers':    [],
            'records':    [],
        }

        if not ns_servers:
            return result

        for ns in ns_servers:
            ns_clean = str(ns).rstrip('.')
            entry    = {'ns': ns_clean, 'success': False, 'record_count': 0}
            try:
                # Resolve IP NS server dulu
                r      = self._resolver(self.timeout)
                ns_ips = [str(rd) for rd in r.resolve(ns_clean, 'A')]
                if not ns_ips:
                    entry['error'] = 'NS IP tidak ditemukan'
                    result['servers'].append(entry)
                    continue

                # Coba AXFR
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ips[0], self.domain, timeout=self.timeout)
                )
                # Kalau sampai sini = berhasil
                records = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rd in rdataset:
                            records.append(f'{name} {rdataset.ttl} '
                                           f'{dns.rdatatype.to_text(rdataset.rdtype)} {rd}')

                entry['success']      = True
                entry['record_count'] = len(records)
                result['vulnerable']  = True
                result['records'].extend(records[:50])  # batasi 50 record pertama
                result['servers'].append(entry)

            except dns.exception.FormError:
                entry['error'] = 'AXFR ditolak (FormError)'
                result['servers'].append(entry)
            except dns.query.TransferError:
                entry['error'] = 'AXFR ditolak (TransferError)'
                result['servers'].append(entry)
            except Exception as e:
                entry['error'] = str(e)[:80]
                result['servers'].append(entry)

        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolver(self, timeout: Optional[float] = None) -> dns.resolver.Resolver:
        r = dns.resolver.Resolver()
        t = timeout or self.timeout
        r.timeout  = t
        r.lifetime = t
        return r

    # ── Public methods ────────────────────────────────────────────────────────

    def get_summary(self) -> Dict[str, Any]:
        counts = {
            k: len(v)
            for k, v in self.results.items()
            if k not in ('metadata', 'ZONE_TRANSFER') and isinstance(v, list)
        }
        return {
            'total_records': sum(counts.values()),
            'record_counts': counts,
            'query_times':   self.query_times,
        }

    def is_responsive(self) -> bool:
        return bool(self.results.get('A', []))

    def enrich_analysis(self) -> Dict[str, Any]:
        mx_servers  = [mx['mail_server'] for mx in self.results.get('MX', [])]
        ns_servers  = self.results.get('NS', [])
        txt_records = self.results.get('TXT', [])
        caa_records = self.results.get('CAA', [])
        dkim_records = self.results.get('DKIM', [])
        zt          = self.results.get('ZONE_TRANSFER', {})

        email_sec = self._analyze_email_security(txt_records, dkim_records)

        return {
            'email_provider':      self._detect_email_provider(mx_servers),
            'nameserver_provider': self._detect_ns_provider(ns_servers),
            'email_security':      email_sec,
            'ssl_ca_policy':       self._analyze_caa(caa_records),
            'zone_transfer':       {
                'vulnerable': zt.get('vulnerable', False),
                'attempted':  zt.get('attempted', 0),
            },
            'registrar_hints':     self._extract_registrar_hints(txt_records),
            'security_score':      self._compute_security_score(email_sec, caa_records, zt),
        }

    # ── Analysis helpers ──────────────────────────────────────────────────────

    def _detect_email_provider(self, mx_servers: List[str]) -> str:
        providers = {
            'google.com':      'Google Workspace (Gmail)',
            'googlemail.com':  'Google Workspace (Gmail)',
            'zoho.com':        'Zoho Mail',
            'outlook.com':     'Microsoft 365',
            'protection.outlook.com': 'Microsoft 365',
            'mailgun.org':     'Mailgun',
            'sendgrid.net':    'SendGrid',
            'amazonses.com':   'AWS SES',
            'mailchimp.com':   'Mailchimp',
            'protonmail.ch':   'ProtonMail',
            'yandex.net':      'Yandex Mail',
        }
        for server in mx_servers:
            for key, name in providers.items():
                if key in server.lower():
                    return name
        return 'Custom/Private MX' if mx_servers else 'None'

    def _detect_ns_provider(self, ns_servers: List[str]) -> str:
        """
        Fix: 'aws.com' tidak ada di NS record AWS → pakai 'awsdns'.
        """
        providers = {
            'cloudflare.com':   'Cloudflare',
            'awsdns':           'AWS Route53',        # ← fix dari 'aws.com'
            'google.com':       'Google Cloud DNS',
            'azure-dns.com':    'Azure DNS',          # ← fix dari 'azure.com'
            'azure-dns.net':    'Azure DNS',
            'azure-dns.org':    'Azure DNS',
            'azure-dns.info':   'Azure DNS',
            'digitalocean.com': 'DigitalOcean',
            'nsone.net':        'NS1',
            'dnsimple.com':     'DNSimple',
            'name.com':         'Name.com',
            'domaincontrol.com':'GoDaddy',
        }
        for ns in ns_servers:
            for key, name in providers.items():
                if key in ns.lower():
                    return name
        return 'Custom NS'

    def _analyze_email_security(
        self, txt_records: List[str], dkim_records: List[Dict]
    ) -> Dict[str, Any]:
        spf_record   = next((t for t in txt_records if 'v=spf1' in t.lower()), None)
        dmarc_domain = f'_dmarc.{self.domain}'
        dmarc_record = None

        # DMARC ada di subdomain _dmarc.domain
        try:
            r = self._resolver(self.timeout)
            for rd in r.resolve(dmarc_domain, 'TXT'):
                txt = b''.join(rd.strings).decode('utf-8', errors='replace')
                if 'v=dmarc1' in txt.lower():
                    dmarc_record = txt
                    break
        except Exception:
            pass

        spf_strict   = False
        dmarc_policy = 'none'

        if spf_record:
            spf_strict = '-all' in spf_record.lower()

        if dmarc_record:
            m = __import__('re').search(r'p=(\w+)', dmarc_record, __import__('re').I)
            if m:
                dmarc_policy = m.group(1).lower()

        return {
            'spf':          bool(spf_record),
            'spf_record':   spf_record,
            'spf_strict':   spf_strict,        # -all = strict, ~all = softfail
            'dkim':         len(dkim_records) > 0,
            'dkim_selectors': [d['selector'] for d in dkim_records],
            'dmarc':        bool(dmarc_record),
            'dmarc_record': dmarc_record,
            'dmarc_policy': dmarc_policy,      # none / quarantine / reject
            'secure':       bool(spf_record) and bool(dmarc_record) and len(dkim_records) > 0,
        }

    def _analyze_caa(self, caa_records: List[Dict]) -> Dict[str, Any]:
        if not caa_records:
            return {
                'configured': False,
                'issuers':    [],
                'wildcard_issuers': [],
                'note': 'Tidak ada CAA record — siapapun bisa issue SSL cert',
            }
        issuers   = [r['value'] for r in caa_records if r.get('tag') == 'issue']
        wildcards = [r['value'] for r in caa_records if r.get('tag') == 'issuewild']
        return {
            'configured':       True,
            'issuers':          issuers,
            'wildcard_issuers': wildcards,
            'note':             f"SSL cert hanya bisa di-issue oleh: {', '.join(issuers)}",
        }

    def _compute_security_score(
        self,
        email_sec: Dict,
        caa_records: List,
        zone_transfer: Dict,
    ) -> Dict[str, Any]:
        """
        Hitung security score sederhana 0-100 berdasarkan temuan DNS.
        """
        score  = 100
        issues = []

        if not email_sec.get('spf'):
            score -= 15
            issues.append('SPF tidak ada — domain rentan email spoofing')
        elif not email_sec.get('spf_strict'):
            score -= 5
            issues.append('SPF pakai ~all (softfail), bukan -all (strict)')

        if not email_sec.get('dkim'):
            score -= 15
            issues.append('DKIM tidak ditemukan pada selector umum')

        if not email_sec.get('dmarc'):
            score -= 15
            issues.append('DMARC tidak ada')
        elif email_sec.get('dmarc_policy') == 'none':
            score -= 10
            issues.append('DMARC policy=none — tidak ada enforcement')

        if not caa_records:
            score -= 10
            issues.append('CAA record tidak ada — siapapun bisa issue SSL cert')

        if zone_transfer.get('vulnerable'):
            score -= 30
            issues.append('ZONE TRANSFER berhasil — seluruh DNS zone bocor!')

        score = max(0, score)

        if score >= 80:
            grade = 'A'
        elif score >= 60:
            grade = 'B'
        elif score >= 40:
            grade = 'C'
        else:
            grade = 'D'

        return {
            'score':  score,
            'grade':  grade,
            'issues': issues,
        }

    def _extract_registrar_hints(self, txt_records: List[str]) -> List[str]:
        registrars = [
            'namecheap', 'godaddy', 'domains.google',
            'name.com', 'porkbun', 'cloudflare', 'hover',
        ]
        hints = [
            reg.title()
            for txt in txt_records
            for reg in registrars
            if reg in txt.lower()
        ]
        return list(dict.fromkeys(hints)) or ['Unknown']