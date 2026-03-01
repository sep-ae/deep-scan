import dns.resolver
import requests
import re
import random
import string
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional
from collections import defaultdict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SubdomainFinder:
    def __init__(self, domain: str, timeout: float = 5.0):
        self.domain = domain.strip().lower()
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        self.wildcard_ips: Set[str] = set()
        self.wildcard_content_hash: Optional[str] = None
        self.passive_discovered: Set[str] = set()
        self._detect_wildcard_robust()

        self.common_subdomains = [
            'www', 'mail', 'ftp', 'api', 'dev', 'staging', 'test',
            'admin', 'panel', 'blog', 'portal', 'dashboard', 'login',
            'cdn', 'static', 'img', 'absen'
        ]

        self.gambling_subdomains = [
            'slot', 'slots', 'casino', 'bet', 'poker', 'togel', 'jackpot',
            'gacor', 'maxwin', 'promo', 'bonus', 'vip', 'agen', 'agent',
            'member', 'user', 'link', 'alternatif', 'mirror', 'zeus', 'olympus'
        ]

        self.suspicious_subdomains = [
            'verify', 'update', 'confirm', 'secure', 'billing', 'reset',
            'payment', 'invoice', 'account', 'login-secure', 'support',
            'helpdesk', 'backup', 'db', 'config', 'env'
        ]

        self.categories = {
            'Admin Panel':   ['admin', 'panel', 'dashboard', 'portal', 'login', 'masuk', 'signin', 'cpanel'],
            'Development':   ['dev', 'test', 'staging', 'beta', 'uat', 'demo', 'sandbox', 'local'],
            'API & Services':['api', 'ws', 'graphql', 'service', 'backend', 'auth', 'oauth'],
            'Files & Assets':['cdn', 'static', 'assets', 'img', 'files', 'upload', 'media', 'image'],
            'Email & Comms': ['mail', 'smtp', 'pop', 'imap', 'webmail', 'exchange', 'chat', 'support'],
            'Network Infra': ['vpn', 'ns', 'dns', 'router', 'gateway', 'proxy', 'internal', 'intranet']
        }


    def run(self, max_workers=15, use_passive=True, use_active=True, http_verify=True) -> List[Dict]:
        all_subdomains: Set[str] = set()

        if use_passive:
            print("  [>] Running passive enumeration...")
            passive = self._passive_enumeration()
            self.passive_discovered = passive.copy()
            print(f"  [+] Passive found: {len(passive)} candidates")
            all_subdomains.update(passive)

        if use_active:
            print("  [>] Running active enumeration...")
            active = self._active_enumeration(max_workers)
            print(f"  [+] Active found: {len(active)} candidates")
            all_subdomains.update(active)

        all_subdomains.discard(self.domain)

        print(f"  [>] Validating {len(all_subdomains)} unique candidates...")
        validated = self._validate_subdomains_smart(all_subdomains, max_workers, http_verify)

        final_results = []
        for item in validated:
            item['category'] = self._categorize_subdomain(item['subdomain'])
            item['vuln_key']  = self._check_risk_marking(item['subdomain'])
            final_results.append(item)

        print(f"  [+] Total valid: {len(final_results)} subdomains")
        return sorted(final_results, key=lambda x: x['subdomain'])


    def _categorize_subdomain(self, subdomain: str) -> str:
        prefix = subdomain.replace(f".{self.domain}", "")
        for cat_name, keywords in self.categories.items():
            if any(k in prefix for k in keywords):
                return cat_name
        return 'General'

    def _check_risk_marking(self, subdomain: str) -> Optional[str]:
        prefix = subdomain.replace(f".{self.domain}", "")
        if any(k in prefix for k in self.gambling_subdomains):
            return 'SUBDOMAIN_GAMBLING'
        if any(k in prefix for k in ['dev', 'test', 'staging', 'beta', 'uat', 'demo', 'sandbox']):
            return 'SUBDOMAIN_DEV_EXPOSED'
        if any(k in prefix for k in ['admin', 'panel', 'dashboard', 'cpanel']):
            return 'SUBDOMAIN_ADMIN_EXPOSED'
        if any(k in prefix for k in self.suspicious_subdomains):
            return 'SUBDOMAIN_TAKEOVER'
        return None


    def _detect_wildcard_robust(self):
        print("  [>] Detecting wildcard DNS...")
        test_domains = [
            f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=16))}.{self.domain}"
            for _ in range(5)
        ]
        ip_frequency = defaultdict(int)
        test_subdomain = None

        for test_domain in test_domains:
            try:
                answers = self.resolver.resolve(test_domain, 'A')
                ips = [str(r) for r in answers]
                for ip in ips:
                    ip_frequency[ip] += 1
                if test_subdomain is None:
                    test_subdomain = test_domain
            except Exception:
                continue

        self.wildcard_ips = {ip for ip, count in ip_frequency.items() if count >= 4}

        if self.wildcard_ips:
            print(f"  [!] Wildcard detected: {', '.join(sorted(self.wildcard_ips))}")
            if test_subdomain:
                self.wildcard_content_hash = self._get_content_hash(test_subdomain)
        else:
            print("  [+] No wildcard detected")

    def _get_content_hash(self, subdomain: str) -> Optional[str]:
        try:
            resp = requests.get(
                f"http://{subdomain}", timeout=3, verify=False,
                allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'}
            )
            return str(hash(f"{resp.status_code}{len(resp.content)}{resp.text[:500]}"))
        except Exception:
            return None

    def _is_likely_wildcard(self, subdomain: str, ips: List[str]) -> bool:
        if subdomain in self.passive_discovered or not self.wildcard_ips:
            return False
        return any(ip in self.wildcard_ips for ip in ips)

    def _verify_with_http(self, subdomain: str) -> bool:
        if not self.wildcard_content_hash:
            return True
        content_hash = self._get_content_hash(subdomain)
        return content_hash is None or content_hash != self.wildcard_content_hash


    def _passive_enumeration(self) -> Set[str]:
        subdomains: Set[str] = set()
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(src)
                for src in [self._query_crtsh, self._query_hackertarget, self._query_wayback]
            ]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        subdomains.update(result)
                except Exception:
                    pass
        return subdomains

    def _query_crtsh(self) -> Set[str]:
        subdomains: Set[str] = set()
        try:
            resp = requests.get(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=15, verify=False)
            if resp.status_code == 200:
                for entry in resp.json():
                    for line in entry.get('name_value', '').split('\n'):
                        sd = line.strip().lower().replace('*.', '')
                        if sd.endswith(self.domain) and len(sd) > len(self.domain):
                            subdomains.add(sd)
            if subdomains:
                print(f"    [crt.sh] Found {len(subdomains)}")
        except requests.exceptions.Timeout:
            print("    [crt.sh] Timeout (skipped)")
        except requests.exceptions.RequestException as e:
            print(f"    [crt.sh] Error: {type(e).__name__} (skipped)")
        return subdomains

    def _query_hackertarget(self) -> Set[str]:
        subdomains: Set[str] = set()
        try:
            resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}", timeout=10)
            if resp.status_code == 200 and 'error' not in resp.text.lower():
                for line in resp.text.splitlines():
                    if ',' in line:
                        sd = line.split(',')[0].strip().lower()
                        if sd.endswith(self.domain):
                            subdomains.add(sd)
            if subdomains:
                print(f"    [HackerTarget] Found {len(subdomains)}")
        except requests.exceptions.Timeout:
            print("    [HackerTarget] Timeout (skipped)")
        except requests.exceptions.RequestException as e:
            print(f"    [HackerTarget] Error: {type(e).__name__} (skipped)")
        return subdomains

    def _query_wayback(self) -> Set[str]:
        subdomains: Set[str] = set()
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                for entry in resp.json()[1:]:
                    match = re.search(
                        r'([a-z0-9\-]+\.)+' + re.escape(self.domain),
                        entry[2], re.IGNORECASE
                    )
                    if match:
                        sd = match.group(0).lower().rstrip('.')
                        if sd.endswith(self.domain):
                            subdomains.add(sd)
            if subdomains:
                print(f"    [Wayback] Found {len(subdomains)}")
        except requests.exceptions.Timeout:
            print("    [Wayback] Timeout (skipped)")
        except requests.exceptions.RequestException as e:
            print(f"    [Wayback] Error: {type(e).__name__} (skipped)")
        return subdomains


    def _active_enumeration(self, max_workers: int) -> Set[str]:
        wordlist = list(set(
            self.common_subdomains + self.gambling_subdomains + self.suspicious_subdomains
        ))
        found: Set[str] = set()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._resolve_candidate, sub): sub for sub in wordlist}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        found.add(result)
                except Exception:
                    pass
        return found

    def _resolve_candidate(self, sub: str) -> Optional[str]:
        full_domain = f"{sub}.{self.domain}"
        try:
            answers = self.resolver.resolve(full_domain, 'A')
            ips = [str(r) for r in answers]
            if not self._is_likely_wildcard(full_domain, ips):
                return full_domain
        except Exception:
            pass
        return None


    def _validate_subdomains_smart(self, subdomains: Set[str], max_workers: int, http_verify: bool) -> List[Dict]:
        validated: List[Dict] = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._resolve_final_smart, sd, http_verify): sd
                for sd in subdomains
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        validated.append(result)
                except Exception:
                    pass
        return validated

    def _resolve_final_smart(self, subdomain: str, http_verify: bool) -> Optional[Dict]:
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            ips = [str(r) for r in answers]
            is_wildcard = self._is_likely_wildcard(subdomain, ips)

            if subdomain in self.passive_discovered or not is_wildcard:
                return {'subdomain': subdomain, 'ip': ips[0], 'all_ips': ips}

            if http_verify and self.wildcard_content_hash:
                return {'subdomain': subdomain, 'ip': ips[0], 'all_ips': ips} \
                    if self._verify_with_http(subdomain) else None

            return {'subdomain': subdomain, 'ip': ips[0], 'all_ips': ips}
        except Exception:
            return None


