# modules/web_vulnerabilities/open_redirect.py
import requests
import urllib3
from typing import Dict, Any, List
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REDIRECT_PARAMS = [
    'next', 'redirect', 'redirect_to', 'redirect_url',
    'return', 'return_to', 'returnurl', 'return_url',
    'url', 'goto', 'target', 'destination', 'dest',
    'forward', 'continue', 'back', 'link', 'location',
    'to', 'go', 'ref', 'reference',
]

REDIRECT_PATHS = [
    '/login', '/logout', '/signin', '/signout',
    '/auth/login', '/auth/logout',
    '/redirect', '/go', '/out', '/external',
    '/',
]

EVIL_URL    = 'https://evil-redirect-test.com'
EVIL_DOMAIN = 'evil-redirect-test.com'

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept':     'text/html,application/xhtml+xml,*/*',
}


class OpenRedirectChecker:
    def __init__(self, url: str, timeout: float = 8.0):
        self.base_url = url.rstrip('/')
        self.timeout  = timeout

    def run(self) -> Dict[str, Any]:
        results = {
            'vulnerable':       False,
            'vulnerable_urls':  [],
            'total_tested':     0,
            'findings':         [],
            'error':            None
        }

        try:
            print(f"    [*] Open Redirect check pada {self.base_url} ...")

            for path in REDIRECT_PATHS:
                base_path_url = urljoin(self.base_url, path)

                for param in REDIRECT_PARAMS:
                    test_url = f"{base_path_url}?{param}={EVIL_URL}"
                    results['total_tested'] += 1

                    try:
                        r = requests.get(
                            test_url,
                            headers=HEADERS,
                            timeout=self.timeout,
                            verify=False,
                            allow_redirects=False  # ← wajib False agar cek Location manual
                        )

                        # Cek apakah Location header mengarah ke evil domain
                        location = r.headers.get('Location', '')
                        if r.status_code in [301, 302, 303, 307, 308] and location:
                            parsed_loc = urlparse(location)
                            # Pastikan redirect ke domain luar (bukan domain sendiri)
                            if EVIL_DOMAIN in location or (
                                parsed_loc.netloc and
                                parsed_loc.netloc not in urlparse(self.base_url).netloc
                            ):
                                vuln_info = f"{test_url} → {location}"
                                print(f"    [!] Open Redirect: {vuln_info}")
                                results['vulnerable_urls'].append(vuln_info)

                        # Cek juga di body (meta refresh / JS redirect)
                        elif r.status_code == 200:
                            body_lower = r.text.lower()
                            if EVIL_DOMAIN in body_lower and any(k in body_lower for k in [
                                'window.location', 'meta http-equiv="refresh"',
                                'location.href', 'location.replace'
                            ]):
                                vuln_info = f"{test_url} → JS/Meta redirect"
                                results['vulnerable_urls'].append(vuln_info)

                    except Exception:
                        pass

            if results['vulnerable_urls']:
                results['vulnerable'] = True
                results['findings'].append(
                    f"Open Redirect ditemukan pada {len(results['vulnerable_urls'])} endpoint."
                )
                for v in results['vulnerable_urls']:
                    results['findings'].append(f"  → {v}")
            else:
                results['findings'].append("Tidak ditemukan Open Redirect.")

        except Exception as e:
            results['error'] = str(e)

        return results