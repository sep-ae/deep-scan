import re
import json
import threading
import logging
import urllib3
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers.http_client import HttpClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
logging.getLogger("charset_normalizer").setLevel(logging.WARNING)

def _info(msg: str): print(f"  [*] {msg}")
def _ok(msg: str):   print(f"  [+] {msg}")
def _warn(msg: str): print(f"  [!] {msg}")
def _step(n: int, total: int, msg: str): print(f"\n  [{n}/{total}] {msg}")

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept':     'text/html,application/xhtml+xml,*/*',
}

JSON_HEADERS = {
    'User-Agent':   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept':       'application/json, */*',
    'Content-Type': 'application/json',
}

REDIRECT_PATHS = [
    '/', '/login', '/logout', '/signin', '/signout', '/register',
    '/api/auth/login', '/api/auth/logout', '/api/auth/redirect',
    '/api/auth/callback', '/api/auth/signin', '/api/auth/signout',
    '/api/login', '/api/logout', '/api/redirect',
    '/api/v1/auth/login', '/api/v1/auth/redirect',
    '/auth/login', '/auth/logout', '/auth/callback', '/auth/redirect',
    '/redirect', '/go', '/out', '/external', '/link',
    '/sso', '/oauth', '/oauth/callback', '/callback',
    '/account/login', '/user/login', '/admin/login',
]

REDIRECT_PARAMS = [
    'next', 'redirect', 'redirect_to', 'redirect_url',
    'return', 'return_to', 'returnurl', 'return_url',
    'url', 'goto', 'target', 'destination',
]

EVIL_URL = 'https://evil-deepscan-test.com'
EVIL_DOMAIN = 'evil-deepscan-test.com'

BYPASS_PAYLOADS = [
    EVIL_URL,
    '//evil-deepscan-test.com',
    'https://trusted.com@evil-deepscan-test.com',
]

SECOND_LEVEL_TLDS = {
    'my.id', 'co.id', 'web.id', 'sch.id', 'ac.id', 'net.id',
    'co.uk', 'com.au', 'co.nz', 'co.za', 'com.br', 'com.mx',
}

SEVERITY_VULN_KEY = {
    'HIGH':   'OPEN_REDIRECT_HIGH',
    'MEDIUM': 'OPEN_REDIRECT_MEDIUM',
    'LOW':    'OPEN_REDIRECT_LOW',
}


class OpenRedirectChecker:
    def __init__(
        self,
        url: str,
        timeout: float = 8.0,
        cookies: Optional[Dict] = None,
        extra_paths: Optional[List[str]] = None,
        stop_on_first: bool = False,
        max_workers: int = 10,
        max_paths: int = 25,
    ):
        self.base_url = url.rstrip('/')
        self.timeout = int(timeout)
        self.cookies = cookies or {}
        self.extra_paths = extra_paths or []
        self.stop_on_first = stop_on_first
        self.max_workers = max_workers
        self.max_paths = max_paths
        self._lock = threading.Lock()
        self._vuln_found = threading.Event()
        self._found_keys: set = set()
        self._all_bases: List[str] = []

        self._client_no_redirect = HttpClient(
            timeout=self.timeout,
            headers=HEADERS,
            cookies=self.cookies,
            verify=False,
            retries=1,
            allow_redirects=False,
        )
        self._client_follow = HttpClient(
            timeout=self.timeout,
            headers=HEADERS,
            cookies=self.cookies,
            verify=False,
            retries=1,
            allow_redirects=True,
        )

    def _get_own_domain(self) -> str:
        return urlparse(self.base_url).netloc

    def _get_root_domain(self, netloc: str) -> str:
        parts = netloc.split('.')
        if len(parts) >= 3:
            candidate = '.'.join(parts[-2:])
            if candidate in SECOND_LEVEL_TLDS:
                return '.'.join(parts[-3:])
        return '.'.join(parts[-2:]) if len(parts) >= 2 else netloc

    def _discover_bases(self) -> List[str]:
        bases = [self.base_url]
        parsed_main = urlparse(self.base_url)
        main_root = self._get_root_domain(parsed_main.netloc)

        try:
            r = self._client_follow.get(self.base_url, headers=HEADERS)
            if not r or not r.ok:
                return bases

            js_texts = [r.text]
            for m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', r.text):
                js_url = urljoin(self.base_url, m.group(1))
                jr = self._client_follow.get(js_url)
                if jr and jr.ok:
                    js_texts.append(jr.text)

            all_text = '\n'.join(js_texts)

            for found_url in re.findall(r'["\`](https?://[a-zA-Z0-9._:-]+)["\`/]', all_text):
                p = urlparse(found_url)
                if not p.netloc or p.netloc == parsed_main.netloc:
                    continue
                if self._get_root_domain(p.netloc) != main_root:
                    continue
                base = f"{p.scheme}://{p.netloc}"
                if base not in bases:
                    bases.append(base)
                    _info(f"Subdomain ditemukan: {base}")

        except Exception:
            pass

        return bases

    def _is_external_redirect(self, location: str) -> bool:
        if not location:
            return False

        loc = location.strip()

        if loc.startswith('//') or loc.startswith('\\/'):
            netloc = loc.lstrip('/\\').split('/')[0].split('?')[0].lower()
            return EVIL_DOMAIN in netloc

        try:
            parsed = urlparse(loc)
            netloc = parsed.netloc.lower().split('@')[-1]
            if not netloc:
                return False
            for base in self._all_bases:
                if urlparse(base).netloc.lower() == netloc:
                    return False
            own = self._get_own_domain().lower()
            return EVIL_DOMAIN in netloc or (own not in netloc and netloc not in own)
        except Exception:
            return False

    def _check_body_redirect(self, body: str) -> bool:
        body_lower = body.lower()
        if EVIL_DOMAIN not in body_lower:
            return False

        if re.search(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*'
            + re.escape(EVIL_DOMAIN),
            body_lower
        ):
            return True

        for pattern in [
            r'window\.location\s*=\s*["\'].*' + re.escape(EVIL_DOMAIN),
            r'window\.location\.href\s*=\s*["\'].*' + re.escape(EVIL_DOMAIN),
            r'window\.location\.replace\s*\(["\'].*' + re.escape(EVIL_DOMAIN),
            r'location\.href\s*=\s*["\'].*' + re.escape(EVIL_DOMAIN),
        ]:
            if re.search(pattern, body_lower):
                return True

        return False

    def _classify_severity(self, path: str, method: str, location: str, redirect_type: str) -> str:
        path_lower = path.lower()

        if redirect_type == 'Header Redirect' and any(k in path_lower for k in ['login', 'signin', 'auth', 'oauth', 'callback']):
            return 'HIGH'

        if method == 'POST' and any(k in path_lower for k in ['login', 'signin', 'auth']):
            return 'HIGH'

        if redirect_type == 'JS/Meta Redirect':
            return 'MEDIUM'

        return 'LOW'

    def _crawl_paths(self, start_url: str, depth: int = 2) -> List[str]:
        visited = set()
        found = set()
        own_domain = self._get_own_domain()

        def crawl(url: str, level: int):
            if level > depth or url in visited or len(found) >= self.max_paths:
                return

            visited.add(url)

            try:
                r = self._client_follow.get(url, headers=HEADERS)
                if not r or not r.ok:
                    return

                ct = r.headers.get('Content-Type', '')
                if 'html' in ct:
                    for m in re.finditer(r'action=["\']([^"\'?#]+)', r.text, re.I):
                        p = m.group(1)
                        if p.startswith('/'):
                            found.add(p)

                    for m in re.finditer(r'href=["\']([^"\'#]+)["\']', r.text, re.I):
                        href = m.group(1)
                        p = urlparse(href)
                        if p.netloc in ('', own_domain) and p.path:
                            found.add(p.path)
                            if level < depth and len(found) < self.max_paths:
                                crawl(urljoin(start_url, p.path), level + 1)

                elif 'json' in ct:
                    for m in re.finditer(r'"(/[a-zA-Z0-9/_\-]+)"', r.text):
                        found.add(m.group(1))

            except Exception:
                pass

        crawl(start_url, 1)

        extras = set()
        for p in found:
            parts = p.strip('/').split('/')
            for i in range(1, len(parts) + 1):
                extras.add('/' + '/'.join(parts[:i]))

        return list(found | extras)[:self.max_paths]

    def _discover_paths(self) -> List[str]:
        active = list(REDIRECT_PATHS)
        _info("Crawling target untuk menemukan path tambahan ...")
        crawled = self._crawl_paths(self.base_url, depth=1)
        _info(f"Ditemukan {len(crawled)} path dari crawling")

        for p in crawled + self.extra_paths:
            if p not in active:
                active.append(p)

        return [p for p in dict.fromkeys(active) if len(p) < 150][:self.max_paths]

    def _register_vuln(self, results: Dict, entry: Dict, key: str):
        with self._lock:
            if key in self._found_keys:
                return

            self._found_keys.add(key)
            _warn(f"Open Redirect [{entry['type']}] method={entry['method']} param={entry['param']}")
            _warn(f"  URL      : {entry['url']}")
            _warn(f"  Location : {entry['location']}")
            results['vulnerable_paths'].append(entry)

            if self.stop_on_first:
                self._vuln_found.set()

    def _test_get(self, base: str, path: str, param: str, payload: str, results: Dict):
        if self.stop_on_first and self._vuln_found.is_set():
            return

        full_url = base.rstrip('/') + '/' + path.lstrip('/')
        test_url = f"{full_url}?{param}={quote(payload, safe=':/@%')}"

        try:
            with self._lock:
                results['total_tested'] += 1

            r = self._client_no_redirect.get(test_url, headers=HEADERS)
            if not r:
                return

            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get('Location', '')
                if self._is_external_redirect(location):
                    severity = self._classify_severity(path, 'GET', location, 'Header Redirect')
                    self._register_vuln(results, {
                        'url': test_url,
                        'param': param,
                        'payload': payload,
                        'type': 'Header Redirect',
                        'location': location,
                        'method': 'GET',
                        'status_code': r.status_code,
                        'base': base,
                        'path': path,
                        'severity': severity,
                        'vuln_key': SEVERITY_VULN_KEY.get(severity),
                        'file_count': 0,
                        'dir_count': 0,
                        'notable_files': [],
                        'is_nested': False,
                    }, f"GET:{base}:{path}:{param}:{payload[:30]}")
                return

            if r.status_code == 200 and self._check_body_redirect(r.text):
                severity = self._classify_severity(path, 'GET', 'body', 'JS/Meta Redirect')
                self._register_vuln(results, {
                    'url': test_url,
                    'param': param,
                    'payload': payload,
                    'type': 'JS/Meta Redirect',
                    'location': 'body',
                    'method': 'GET',
                    'status_code': 200,
                    'base': base,
                    'path': path,
                    'severity': severity,
                    'vuln_key': SEVERITY_VULN_KEY.get(severity),
                    'file_count': 0,
                    'dir_count': 0,
                    'notable_files': [],
                    'is_nested': False,
                }, f"GET_BODY:{base}:{path}:{param}:{payload[:30]}")

        except Exception:
            pass

    def _test_post(self, base: str, path: str, param: str, payload: str, results: Dict):
        if self.stop_on_first and self._vuln_found.is_set():
            return

        is_auth_path = any(kw in path.lower() for kw in [
            'login', 'signin', 'auth', 'redirect',
            'logout', 'callback', 'signout'
        ])
        if not is_auth_path:
            return

        full_url = base.rstrip('/') + '/' + path.lstrip('/')
        test_url = f"{full_url}?{param}={quote(payload, safe=':/@%')}"

        try:
            with self._lock:
                results['total_tested'] += 1

            r = self._client_no_redirect.post(
                test_url,
                data=json.dumps({"email": "test@test.com", "password": "test"}),
                headers=JSON_HEADERS,
            )
            if r and r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get('Location', '')
                if self._is_external_redirect(location):
                    severity = self._classify_severity(path, 'POST', location, 'Header Redirect')
                    self._register_vuln(results, {
                        'url': test_url,
                        'param': param,
                        'payload': payload,
                        'type': 'Header Redirect',
                        'location': location,
                        'method': 'POST',
                        'status_code': r.status_code,
                        'base': base,
                        'path': path,
                        'severity': severity,
                        'vuln_key': SEVERITY_VULN_KEY.get(severity),
                        'file_count': 0,
                        'dir_count': 0,
                        'notable_files': [],
                        'is_nested': False,
                    }, f"POST:{base}:{path}:{param}:{payload[:30]}")

        except Exception:
            pass

    def _test_path_on_base(self, base: str, path: str, results: Dict):
        if self.stop_on_first and self._vuln_found.is_set():
            return

        full_url = base.rstrip('/') + '/' + path.lstrip('/')

        try:
            probe = self._client_no_redirect.get(full_url, headers=HEADERS)
            status = probe.status_code if probe else 0
            if status == 404 and path not in REDIRECT_PATHS:
                return
        except Exception:
            return

        for param in REDIRECT_PARAMS:
            for payload in BYPASS_PAYLOADS:
                if self.stop_on_first and self._vuln_found.is_set():
                    return
                self._test_get(base, path, param, payload, results)
                self._test_post(base, path, param, payload, results)

    def run(self) -> Dict[str, Any]:
        results = {
            'vulnerable': False,
            'vulnerable_paths': [],
            'total_tested': 0,
            'findings': [],
            'error': None,
            'summary': {},
        }

        try:
            _step(1, 3, "Mengumpulkan target & path kandidat ...")
            _info(f"Base URL: {self.base_url}")

            all_bases = self._discover_bases()
            self._all_bases = all_bases
            _info(f"Total bases: {len(all_bases)} → {', '.join(all_bases)}")

            paths = self._discover_paths()
            _info(f"Total {len(paths)} path | {len(REDIRECT_PARAMS)} param | {len(BYPASS_PAYLOADS)} payload")

            _step(2, 3, f"Testing Open Redirect ({len(all_bases)} base × {len(paths)} path) ...")

            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = [
                    ex.submit(self._test_path_on_base, base, path, results)
                    for base in all_bases
                    for path in paths
                ]
                for f in as_completed(futures):
                    if self.stop_on_first and self._vuln_found.is_set():
                        for rem in futures:
                            rem.cancel()
                        break
                    try:
                        f.result()
                    except Exception:
                        pass

            _step(3, 3, "Finalisasi hasil ...")

            if results['vulnerable_paths']:
                results['vulnerable'] = True
                count = len(results['vulnerable_paths'])

                sev_count = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                for vp in results['vulnerable_paths']:
                    sev = vp.get('severity', 'LOW')
                    sev_count[sev] = sev_count.get(sev, 0) + 1

                results['summary'] = {
                    'total_vulnerable_paths': count,
                    'severity_breakdown': {k: v for k, v in sev_count.items() if v > 0},
                }

                results['findings'].append(f"Open Redirect ditemukan pada {count} endpoint.")
                for v in results['vulnerable_paths']:
                    results['findings'].append(
                        f"  → [{v['severity']}] [{v['type']}] [{v['method']}] param={v['param']} base={v['base']}"
                    )
                    results['findings'].append(f"      URL: {v['url']}")
                    results['findings'].append(f"      Location: {v['location']}")

                _ok(
                    f"Total: {count} Open Redirect ditemukan | "
                    f"HIGH={sev_count.get('HIGH', 0)} "
                    f"MEDIUM={sev_count.get('MEDIUM', 0)} "
                    f"LOW={sev_count.get('LOW', 0)}"
                )
            else:
                results['findings'].append("Tidak ditemukan Open Redirect.")
                _info("Tidak ditemukan Open Redirect.")

        except Exception as e:
            results['error'] = str(e)
        finally:
            self._client_no_redirect.close()
            self._client_follow.close()

        return results