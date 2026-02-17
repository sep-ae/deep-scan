import dns.resolver
import requests
import re
import random
import string
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional
from collections import defaultdict

# DISABLE SSL WARNINGS (untuk scanning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SubdomainFinder:
    """
    Subdomain enumeration dengan advanced wildcard filtering.
    Passive sources + Active brute-force (tanpa pattern generation).
    """

    def __init__(self, domain: str, timeout: float = 5.0):
        self.domain = domain.strip().lower()
        self.timeout = timeout

        # DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2

        # Wildcard detection
        self.wildcard_ips: Set[str] = set()
        self.wildcard_content_hash: Optional[str] = None
        
        # Known subdomains dari passive sources (trusted)
        self.passive_discovered: Set[str] = set()
        
        # Detect wildcard
        self._detect_wildcard_robust()

        # Wordlist
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'api', 'dev', 'staging',
            'test', 'admin', 'panel', 'blog',
            'portal', 'dashboard', 'login',
            'cdn', 'static', 'img', 'absen'
        ]

        self.gambling_subdomains = [
            'slot', 'slots', 'casino', 'bet', 'poker',
            'togel', 'jackpot', 'gacor', 'maxwin',
            'promo', 'bonus', 'vip',
            'agen', 'agent', 'member', 'user',
            'link', 'alternatif', 'mirror'
        ]

        self.suspicious_subdomains = [
            'verify', 'update', 'confirm',
            'secure', 'billing', 'reset',
            'payment', 'invoice', 'account',
            'login-secure', 'support', 'helpdesk'
        ]

    # =================================================
    # MAIN RUNNER
    # =================================================

    def run(
        self,
        max_workers: int = 15,
        use_passive: bool = True,
        use_active: bool = True,
        http_verify: bool = True
    ) -> List[Dict]:
        """
        Enumerasi subdomain dengan advanced wildcard filtering.
        """
        all_subdomains: Set[str] = set()

        if use_passive:
            print("  [>] Running passive enumeration...")
            passive = self._passive_enumeration()
            self.passive_discovered = passive.copy()
            print(f"  [+] Passive found: {len(passive)} candidates (trusted)")
            all_subdomains.update(passive)

        if use_active:
            print("  [>] Running active enumeration...")
            active = self._active_enumeration(max_workers)
            print(f"  [+] Active found: {len(active)} candidates")
            all_subdomains.update(active)

        all_subdomains.discard(self.domain)

        print(f"  [>] Validating {len(all_subdomains)} unique candidates...")
        validated = self._validate_subdomains_smart(
            all_subdomains, 
            max_workers,
            http_verify
        )
        print(f"  [+] Total valid: {len(validated)} subdomains")

        return sorted(validated, key=lambda x: x['subdomain'])

    # =================================================
    # ROBUST WILDCARD DETECTION
    # =================================================

    def _detect_wildcard_robust(self):
        """
        Deteksi wildcard dengan 5 random test + majority voting.
        """
        print("  [>] Detecting wildcard DNS...")
        
        test_domains = []
        for _ in range(5):
            random_sub = ''.join(
                random.choices(string.ascii_lowercase + string.digits, k=16)
            )
            test_domains.append(f"{random_sub}.{self.domain}")

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

        threshold = 4
        self.wildcard_ips = {
            ip for ip, count in ip_frequency.items() 
            if count >= threshold
        }

        if self.wildcard_ips:
            print(f"  [!] Wildcard detected: {', '.join(sorted(self.wildcard_ips))}")
            
            if test_subdomain:
                self.wildcard_content_hash = self._get_content_hash(test_subdomain)
                if self.wildcard_content_hash:
                    print(f"      Wildcard content hash captured")
        else:
            print("  [+] No wildcard detected")

    def _get_content_hash(self, subdomain: str) -> Optional[str]:
        """
        Ambil hash dari HTTP response content untuk wildcard comparison.
        """
        try:
            url = f"http://{subdomain}"
            resp = requests.get(
                url, 
                timeout=3, 
                verify=False,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            
            content_signature = (
                f"{resp.status_code}"
                f"{len(resp.content)}"
                f"{resp.text[:500]}"
            )
            
            return str(hash(content_signature))
        except Exception:
            return None

    def _is_likely_wildcard(self, subdomain: str, ips: List[str]) -> bool:
        """
        Smart wildcard check.
        """
        if subdomain in self.passive_discovered:
            return False
        
        if not self.wildcard_ips:
            return False
        
        if not any(ip in self.wildcard_ips for ip in ips):
            return False
        
        return True

    def _verify_with_http(self, subdomain: str) -> bool:
        """
        Verifikasi subdomain dengan HTTP content check.
        Return True jika subdomain VALID (bukan wildcard).
        """
        if not self.wildcard_content_hash:
            return True
        
        content_hash = self._get_content_hash(subdomain)
        
        if content_hash is None:
            return True
        
        return content_hash != self.wildcard_content_hash

    # =================================================
    # PASSIVE ENUMERATION
    # =================================================

    def _passive_enumeration(self) -> Set[str]:
        """Passive enumeration dari 3 sumber (paralel)."""
        subdomains: Set[str] = set()

        sources = [
            self._query_crtsh,
            self._query_hackertarget,
            self._query_wayback
        ]

        with ThreadPoolExecutor(max_workers=len(sources)) as executor:
            futures = [executor.submit(src) for src in sources]

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        subdomains.update(result)
                except Exception:
                    pass

        return subdomains

    def _query_crtsh(self) -> Set[str]:
        """Certificate Transparency - crt.sh"""
        subdomains: Set[str] = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=15, verify=False)

            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for line in name_value.split('\n'):
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
        """HackerTarget API"""
        subdomains: Set[str] = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            resp = requests.get(url, timeout=10)

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
        """Wayback Machine"""
        subdomains: Set[str] = set()
        try:
            url = (
                f"http://web.archive.org/cdx/search/cdx"
                f"?url=*.{self.domain}/*&output=json&collapse=urlkey"
            )
            resp = requests.get(url, timeout=10)

            if resp.status_code == 200:
                data = resp.json()
                for entry in data[1:]:
                    url_str = entry[2]
                    match = re.search(
                        r'([a-z0-9\-]+\.)+' + re.escape(self.domain),
                        url_str,
                        re.IGNORECASE
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

    # =================================================
    # ACTIVE ENUMERATION
    # =================================================

    def _active_enumeration(self, max_workers: int) -> Set[str]:
        """
        Brute-force DNS dengan wordlist statis (tanpa pattern generation).
        """
        # Gabungkan semua wordlist
        wordlist = (
            self.common_subdomains +
            self.gambling_subdomains +
            self.suspicious_subdomains
        )

        # Hapus duplikat
        wordlist = list(set(wordlist))

        found: Set[str] = set()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._resolve_candidate, sub): sub
                for sub in wordlist
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        found.add(result)
                except Exception:
                    pass

        return found

    def _resolve_candidate(self, sub: str):
        """Resolve kandidat subdomain untuk active enumeration."""
        full_domain = f"{sub}.{self.domain}"
        try:
            answers = self.resolver.resolve(full_domain, 'A')
            ips = [str(r) for r in answers]

            if self._is_likely_wildcard(full_domain, ips):
                pass

            return full_domain
        except Exception:
            return None

    # =================================================
    # SMART VALIDATION
    # =================================================

    def _validate_subdomains_smart(
        self,
        subdomains: Set[str],
        max_workers: int,
        http_verify: bool
    ) -> List[Dict]:
        """
        Validasi dengan smart wildcard filtering + HTTP verification.
        """
        validated: List[Dict] = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    self._resolve_final_smart, 
                    sd, 
                    http_verify
                ): sd
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
        """
        Resolve final dengan smart wildcard check + HTTP verification.
        """
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            ips = [str(r) for r in answers]

            is_wildcard = self._is_likely_wildcard(subdomain, ips)
            
            if subdomain in self.passive_discovered:
                return {
                    'subdomain': subdomain,
                    'ip': ips[0],
                    'all_ips': ips
                }
            
            if not is_wildcard:
                return {
                    'subdomain': subdomain,
                    'ip': ips[0],
                    'all_ips': ips
                }
            
            if http_verify and self.wildcard_content_hash:
                if self._verify_with_http(subdomain):
                    return {
                        'subdomain': subdomain,
                        'ip': ips[0],
                        'all_ips': ips
                    }
                else:
                    return None
            else:
                return {
                    'subdomain': subdomain,
                    'ip': ips[0],
                    'all_ips': ips
                }

        except Exception:
            return None


# ==========================================
# USAGE
# ==========================================

if __name__ == "__main__":
    finder = SubdomainFinder('madiunkab.go.id')
    results = finder.run(
        max_workers=20,
        use_passive=True,
        use_active=True,
        http_verify=True
    )

    print(f"\n=== {len(results)} LIVE SUBDOMAINS FOUND ===\n")
    for item in results:
        print(f"{item['subdomain']:50} → {item['ip']}")
