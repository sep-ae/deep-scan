import re
import json
import threading
import logging
import urllib3
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers.http_client import HttpClient, HostDeadException
from helpers.waf_checker import WAFChecker
from helpers.scope import is_in_scope

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
logging.getLogger("charset_normalizer").setLevel(logging.WARNING)

def _safe_print(msg: str):
    try:
        print(msg)
    except Exception:
        pass

def _info(msg: str):  _safe_print(f"  [*] {msg}")
def _ok(msg: str):    _safe_print(f"  [+] {msg}")
def _warn(msg: str):  _safe_print(f"  [!] {msg}")
def _step(n: int, total: int, msg: str): _safe_print(f"\n  [{n}/{total}] {msg}")

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
    f'//{EVIL_DOMAIN}',
    f'https://{EVIL_DOMAIN}',
    f'https:{EVIL_DOMAIN}',
    f'/%5C{EVIL_DOMAIN}',
    f'/%0D/{EVIL_DOMAIN}',
    f'https://{EVIL_DOMAIN}%3B@trusted.com',
    f'////{EVIL_DOMAIN}',
    f'https://{EVIL_DOMAIN}%5C@trusted.com',
    f'https%3A%2F%2F{EVIL_DOMAIN}',
    f'https://trusted.com@{EVIL_DOMAIN}',
    f'https://{EVIL_DOMAIN}%00.trusted.com',
    f'https://{EVIL_DOMAIN}%23.trusted.com',
    f'//{EVIL_DOMAIN}/%2F..',
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
        scope_mode: str = 'wildcard',
        discovered: Optional[Dict] = None,
    ):
        self.base_url = url.rstrip('/')
        self.timeout = int(timeout) if timeout else 5
        self.cookies = cookies or {}
        self.extra_paths = extra_paths or []
        self.stop_on_first = stop_on_first
        self.max_workers = max_workers
        self.max_paths = max_paths
        self.scope_mode = scope_mode
        self.discovered = discovered or {}
        
        self._lock = threading.Lock()
        self._vuln_found = threading.Event()
        self._found_keys: set = set()
        self._waf_detected = self.discovered.get('waf_detected', False)
        self._waf_info = self.discovered.get('waf_info', {})
        self._is_spa = self.discovered.get('is_spa', False)
        self._playwright_used = self.discovered.get('playwright_used', False)

        self._all_bases: List[str] = [self.base_url]
        for base in self.discovered.get('api_bases', []):
            if base not in self._all_bases:
                self._all_bases.append(base)

        self._client_no_redirect = HttpClient(
            timeout=self.timeout,
            headers=HEADERS,
            cookies=self.cookies,
            verify=False,
            retries=0,
            allow_redirects=False,
        )

    def _get_own_domain(self) -> str:
        return urlparse(self.base_url).netloc

    def _is_external_redirect(self, location: str) -> bool:
        if not location:
            return False

        loc = location.strip()
        from urllib.parse import unquote
        loc = unquote(loc)

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

    def _discover_paths(self) -> List[str]:
        active = list(REDIRECT_PATHS)
        
        # Merge with discovered endpoints
        endpoints = self.discovered.get('endpoints', [])
        for p in endpoints:
            if not p.startswith('http'):
                active.append(p)
                
        for p in self.extra_paths:
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

        if path.startswith(urlparse(base).path) and urlparse(base).path != '/':
            # Avoid doubling paths like /api/api/auth/login
            full_url = base.rstrip('/')[:-len(urlparse(base).path)] + '/' + path.lstrip('/')
        else:
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

        except HostDeadException:
            raise
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

        if path.startswith(urlparse(base).path) and urlparse(base).path != '/':
            full_url = base.rstrip('/')[:-len(urlparse(base).path)] + '/' + path.lstrip('/')
        else:
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

        except HostDeadException:
            raise
        except Exception:
            pass

    def _test_path_on_base(self, base: str, path: str, results: Dict, all_params: list):
        if self.stop_on_first and self._vuln_found.is_set():
            return

        if path.startswith(urlparse(base).path) and urlparse(base).path != '/':
            full_url = base.rstrip('/')[:-len(urlparse(base).path)] + '/' + path.lstrip('/')
        else:
            full_url = base.rstrip('/') + '/' + path.lstrip('/')

        try:
            probe = self._client_no_redirect.get(full_url, headers=HEADERS)
            status = probe.status_code if probe else 0
            if status == 404 and path not in REDIRECT_PATHS:
                return
        except HostDeadException:
            raise
        except Exception:
            return

        # Determine if endpoint is completely static/not reflecting
        response_sigs = []

        def _task(param: str, payload: str):
            if self.stop_on_first and self._vuln_found.is_set():
                return
            self._test_get(base, path, param, payload, results)
            self._test_post(base, path, param, payload, results)

        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = []
            for param in all_params:
                # If we have 3 identical responses without redirect, skip remaining params
                # This prevents wasting time on static files/endpoints
                if len(response_sigs) >= 3 and len(set(response_sigs)) == 1:
                    break
                    
                # We do sequential payload submission to allow smart skip to catch on, 
                # but param checking is somewhat parallelized
                for payload in BYPASS_PAYLOADS:
                    if self.stop_on_first and self._vuln_found.is_set():
                        break
                    futures.append(ex.submit(_task, param, payload))
            
            for f in as_completed(futures):
                if self.stop_on_first and self._vuln_found.is_set():
                    for rem in futures:
                        rem.cancel()
                    break
                try:
                    f.result()
                except Exception:
                    pass

    def run(self) -> Dict[str, Any]:
        results = {
            'vulnerable': False,
            'vulnerable_paths': [],
            'total_tested': 0,
            'findings': [],
            'error': None,
            'summary': {},
            'waf_detected': self._waf_detected,
            'waf_info': self._waf_info,
            'spa_detected': self._is_spa,
            'playwright_used': self._playwright_used,
        }

        try:
            _step(1, 3, "Mengumpulkan target & path kandidat ...")
            _info(f"Base URL: {self.base_url}")

            all_bases = self._all_bases
            _info(f"Total bases: {len(all_bases)} -> {', '.join(all_bases)}")

            paths = self._discover_paths()
            all_params = list(dict.fromkeys(REDIRECT_PARAMS + self.discovered.get('params', [])))
            _info(f"Total {len(paths)} path | {len(all_params)} param | {len(BYPASS_PAYLOADS)} payload")

            _step(2, 3, f"Testing Open Redirect ({len(all_bases)} base × {len(paths)} path) ...")

            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = [
                    ex.submit(self._test_path_on_base, base, path, results, all_params)
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
                    except HostDeadException:
                        _warn("Target mati/tarpit terdeteksi, membatalkan sisa request...")
                        for rem in futures:
                            rem.cancel()
                        break
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
                        f"  -> [{v['severity']}] [{v['type']}] [{v['method']}] param={v['param']} base={v['base']}"
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

        return results