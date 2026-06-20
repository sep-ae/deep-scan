# checker/xss.py — XSSChecker v2
import re
import threading
import requests
import urllib3
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin, quote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers.http_client import HttpClient, HostDeadException
from helpers.waf_checker import WAFChecker
from helpers.spa_crawler import SPACrawler
from helpers.scope import is_in_scope
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


# ── Payloads ──────────────────────────────────────────────────────────────────

XSS_MARKER = 'DEEPSCANXSS7x9z'

XSS_PAYLOADS = [
    f'<script>alert("{XSS_MARKER}")</script>',
    f'"><script>alert("{XSS_MARKER}")</script>',
    f'<img src=x onerror=alert("{XSS_MARKER}")>',
    f'<svg onload=alert("{XSS_MARKER}")>',
    f'<ScRiPt>alert("{XSS_MARKER}")</ScRiPt>',
]

WAF_BYPASS_PAYLOADS = [
    f'%3Cscript%3Ealert%28%22{XSS_MARKER}%22%29%3C%2Fscript%3E',
    f'<details/open/ontoggle=alert("{XSS_MARKER}")>',
    f'<input onfocus=alert("{XSS_MARKER}") autofocus>',
]

TEST_ENDPOINTS = [
    '/search', '/q', '/find',
    '/comment', '/feedback', '/contact',
    '/api/search', '/', '/posts/preview', '/api/posts/preview'
]

TEST_PARAMS = [
    'q', 'search', 'query', 'keyword', 's',
    'name', 'message', 'comment',
    'url', 'redirect',
    'content', 'body', 'text', 'title', 'html', 'data', 'input', 'value', 'msg', 'description'
]


# ── Severity ──────────────────────────────────────────────────────────────────

SEVERITY_VULN_KEY: dict[str, str] = {
    'CRITICAL': 'XSS_CRITICAL',
    'HIGH':     'XSS_HIGH',
    'MEDIUM':   'XSS_MEDIUM',
    'LOW':      'XSS_LOW',
}

# Parameter sensitif yang langsung eksekusi di browser -> CRITICAL
_CRITICAL_PARAMS = {'redirect', 'url', 'next', 'return', 'callback', 'target'}

# Path auth-sensitive -> naikkan ke CRITICAL
_AUTH_PATHS = {'login', 'signin', 'auth', 'oauth', 'register', 'admin', 'account'}

# Payload berbahaya tinggi (script/event handler langsung) -> HIGH
_HIGH_PAYLOAD_MARKERS = {'<script', '<svg', '<body', '<img', 'onerror', 'onload'}


def _classify_severity(url: str, param: str, payload: str, method: str) -> str:
    parsed_path = urlparse(url).path.lower()
    is_auth     = any(kw in parsed_path for kw in _AUTH_PATHS)
    is_critical_param = param.lower() in _CRITICAL_PARAMS
    payload_lower     = payload.lower()

    # Redirect/open-redirect param + XSS -> CRITICAL
    if is_critical_param:
        return 'CRITICAL'

    # Auth endpoint + XSS -> CRITICAL
    if is_auth:
        return 'CRITICAL'

    # Script injection atau event handler langsung -> HIGH
    if any(marker in payload_lower for marker in _HIGH_PAYLOAD_MARKERS):
        return 'HIGH'

    # Attribute injection atau JS context -> MEDIUM
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
        discovered: Optional[Dict] = None,
    ):
        self.base_url    = url.rstrip('/')
        self.timeout     = int(timeout)
        self.cookies     = cookies or {}
        self.extra_paths = extra_paths or []
        self.scope_mode  = scope_mode
        self.discovered  = discovered or {}
        self._lock       = threading.Lock()
        self._vuln_found = threading.Event()
        self._found_keys: set = set()
        
        self._waf_detected   = self.discovered.get('waf_detected', False)
        self._waf_info       = self.discovered.get('waf_info', {})
        self._api_bases: List = self.discovered.get('api_bases', [])

        self._client = HttpClient(
            timeout=5,
            headers=HEADERS,
            cookies=self.cookies,
            verify=False,
            retries=0,  # Tidak retry — jika timeout berarti di-tarpit oleh WAF
        )

    # ── Utils ─────────────────────────────────────────────────────────────────

    def _is_cloudflare_page(self, text: str) -> bool:
        return WAFChecker.is_cloudflare_page(text)

    def _is_reflected(self, body: str, payload: str, content_type: str = '') -> bool:
        if XSS_MARKER not in body:
            return False

        # Jangan tolak HTML secara ketat, kalau application/json kita tetap cek
        # karena bisa saja API return JSON tapi browser akan render HTML.

        from urllib.parse import unquote
        decoded_payload = unquote(payload).lower()
        body_lower = body.lower()
        
        # Cek apakah payload asli (unencoded) benar-benar terefleksi di body
        if decoded_payload in body_lower:
            return True

        return False

    # ── Endpoint discovery ────────────────────────────────────────────────────

    def _get_active_endpoints(self) -> List[str]:
        active = []
        # Tambahkan endpoints dari CrawlerHelper
        for ep in self.discovered.get('endpoints', []):
            if ep not in active:
                active.append(ep)
                
        # Tetap gunakan hardcoded sebagai fallback
        for base in self._api_bases + [self.base_url]:
            for path in TEST_ENDPOINTS:
                url = f"{base.rstrip('/')}{path}"
                if url not in active:
                    active.append(url)

        for path in self.extra_paths:
            full = normalize_url(path, self.base_url)
            if full not in active:
                active.append(full)

        return list(dict.fromkeys(active))

    # ── Core scan ─────────────────────────────────────────────────────────────

    def _scan_url_params(self, url: str, results: Dict):
        payloads = XSS_PAYLOADS + (WAF_BYPASS_PAYLOADS if self._waf_detected else [])
        
        # Merge discovered params dengan TEST_PARAMS
        all_params = list(dict.fromkeys(TEST_PARAMS + self.discovered.get('params', [])))

        for param in all_params:
            for payload in payloads:
                with self._lock:
                    results['total_tested'] += 1

                test_url = f"{url}?{param}={quote(payload, safe='')}"
                try:
                    r = self._client.get(test_url, headers=HEADERS)
                    if not r or self._is_cloudflare_page(r.text):
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
                            severity = _classify_severity(url, param, payload, 'GET')
                            parsed   = urlparse(url)

                            _warn(f"Reflected XSS [{severity}] -> param={param} | {url}")
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
                        continue

                except HostDeadException:
                    raise
                except Exception:
                    pass

    def _scan_forms(self, results: Dict):
        forms = self.discovered.get('forms', [])
        if not forms:
            return

        _info(f"Ditemukan {len(forms)} form, testing XSS ...")

        for form in forms:
            for inp in form['inputs']:
                param  = inp['name']
                action = form['action']

                for payload in XSS_PAYLOADS[:6]:
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

                        ct = r.headers.get('Content-Type', '').lower()
                        if self._is_reflected(r.text, payload, ct):
                            key = f"form:{action}:{param}"
                            registered = False
                            with self._lock:
                                if key not in self._found_keys:
                                    self._found_keys.add(key)
                                    registered = True

                            if registered:
                                method = form['method'].upper()
                                severity = _classify_severity(action, param, payload, method)
                                parsed   = urlparse(action)
                                vuln_url = (f"{action}?{param}={payload}"
                                            if form['method'] == 'get' else action)

                                _warn(f"Reflected XSS (form {method}) [{severity}] -> "
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
                                continue

                    except HostDeadException:
                        raise
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
            'waf_detected':     self._waf_detected,
        }

        try:
            results['waf_info']     = self._waf_info
            
            _step(1, 3, "Mengumpulkan endpoint ...")
            endpoints = self._get_active_endpoints()
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
                    try: f.result()
                    except HostDeadException:
                        for remaining in futures:
                            remaining.cancel()
                        break
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
                        f"  -> [{v['type']}][{v.get('severity','?')}] [{v['method']}] "
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