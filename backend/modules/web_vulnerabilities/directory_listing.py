# checker/directory_listing.py
import re
import threading
import urllib3
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers.http_client import HttpClient, HostDeadException
from helpers.waf_checker import WAFChecker
from helpers.scope import is_in_scope

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _info(msg: str):  print(f"  [*] {msg}")
def _ok(msg: str):    print(f"  [+] {msg}")
def _warn(msg: str):  print(f"  [!] {msg}")
def _step(n: int, total: int, msg: str): print(f"\n  [{n}/{total}] {msg}")


# ── Constants 

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept':     'text/html,application/xhtml+xml,*/*',
}

DIRECTORY_PATHS = [
    # Upload & media
    '/uploads/', '/upload/', '/images/', '/img/', '/files/', '/file/',
    '/media/', '/assets/', '/static/', '/storage/',
    # Backup & sensitive
    '/backup/', '/backups/', '/bak/', '/logs/', '/log/',
    '/data/', '/database/', '/db/', '/sql/', '/dump/',
    '/export/', '/import/', '/old/', '/archive/',
    # Dev & config
    '/temp/', '/tmp/', '/cache/', '/test/', '/dev/',
    '/config/', '/conf/', '/includes/', '/inc/',
    '/scripts/', '/js/', '/css/',
    # Admin & private
    '/admin/', '/private/', '/secret/', '/hidden/',
    '/docs/', '/documents/', '/downloads/',
    '/public/', '/public/uploads/',
    # API paths
    '/api/', '/api/uploads/', '/api/files/', '/api/media/',
    '/api/storage/', '/api/static/',
]

# Signature Apache, Nginx, IIS, Python SimpleHTTP, lighttpd
LISTING_SIGNATURES = [
    'index of /',
    'directory listing for',
    'parent directory',
    '[to parent directory]',
    'directory: /',
    '<title>index of',
    'last modified</a>',
    'description</a>',
    '?c=n&amp;o=a',
    '?c=d&amp;o=a',
    'name</a>',
    'size</a>',
    '<pre>',
    '?c=n&o=a',
    '<img src="/icons/',
    'apache server at',
]

FALSE_POSITIVE_SIGNATURES = [
    '<meta name="description"',
    '<meta property="og:',
    '<meta name="viewport"',
    'window.__nuxt',
    'window.__initial_state__',
    'window.__next_data__',
    '<div id="app"',
    '<div id="root"',
    '<div id="__next"',
    '__webpack_require__',
    'reactdom.render',
    'vue.createapp',
    'ng-version=',
    'data-reactroot',
]

# File ekstensi yang dianggap sensitif (untuk severity HIGH)
SENSITIVE_EXTENSIONS = {
    '.sql', '.db', '.sqlite', '.bak', '.backup', '.tar', '.tar.gz',
    '.zip', '.rar', '.7z', '.env', '.config', '.conf', '.cfg',
    '.pem', '.key', '.crt', '.p12', '.pfx', '.log', '.dump',
    '.csv', '.xlsx', '.xls', '.json', '.xml', '.yaml', '.yml',
}

# Path yang dianggap kritis (severity CRITICAL)
CRITICAL_PATHS = {
    '/backup/', '/backups/', '/bak/', '/database/', '/db/', '/sql/',
    '/dump/', '/config/', '/conf/', '/secret/', '/private/', '/admin/',
    '/export/', '/.git/', '/.env',
}

SEVERITY_VULN_KEY: dict[str, str] = {
    'CRITICAL': 'DIR_LISTING_CRITICAL',
    'HIGH':     'DIR_LISTING_HIGH',
    'MEDIUM':   'DIR_LISTING_MEDIUM',
    'LOW':      'DIR_LISTING_LOW',
}

# ── Severity helper 

def _classify_severity(path: str, files: List[str]) -> str:

    path_lower = path.lower()

    for cp in CRITICAL_PATHS:
        if cp in path_lower:
            return 'CRITICAL'

    # Ada file sensitif di dalamnya → HIGH
    for f in files:
        ext = '.' + f.split('.')[-1].lower() if '.' in f else ''
        if ext in SENSITIVE_EXTENSIONS:
            return 'HIGH'

    # Uploads/media → MEDIUM (mungkin file user yang tidak seharusnya publik)
    if any(kw in path_lower for kw in ['upload', 'media', 'storage', 'files']):
        return 'MEDIUM'

    return 'LOW'


# ── File enumerator 

def _enumerate_directory(body: str, base_url: str) -> List[Dict]:
    from bs4 import BeautifulSoup
    items = []
    seen: Set[str] = set()

    try:
        soup = BeautifulSoup(body, 'html.parser')

        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            name = a.get_text(strip=True)

            # Skip navigasi
            if href in ('/', '../', '..', '#', '?') or href.startswith('?'):
                continue
            if name in ('Parent Directory', '..', '[To Parent Directory]', ''):
                continue
            # Skip absolute ke domain lain
            if href.startswith('http') and base_url not in href:
                continue

            if href in seen:
                continue
            seen.add(href)

            is_dir = href.endswith('/')
            full_url = urljoin(base_url, href) if not href.startswith('http') else href

            items.append({
                'name':     name or href,
                'href':     href,
                'full_url': full_url,
                'is_dir':   is_dir,
            })
    except Exception:
        pass

    return items


# ── Main class ────────────────────────────────────────────────────────────────

class DirectoryListingChecker:
    def __init__(
        self,
        url: str,
        timeout: float = 8.0,
        cookies: Optional[Dict] = None,
        extra_paths: Optional[List[str]] = None,
        max_depth: int = 2,       
        enumerate_contents: bool = True,
        scope_mode: str = 'wildcard',
    ):
        self.base_url            = url.rstrip('/')
        self.timeout             = int(timeout)
        self.cookies             = cookies or {}
        self.extra_paths         = extra_paths or []
        self.max_depth           = max_depth
        self.enumerate_contents  = enumerate_contents
        self.scope_mode          = scope_mode
        self._lock               = threading.Lock()
        self._all_bases: List[str] = []
        self._probed_urls: Set[str] = set()   

        self._client = HttpClient(
            timeout=self.timeout,
            headers=HEADERS,
            cookies=self.cookies,
            verify=False,
            retries=0,
        )

    # ── Utils ─────────────────────────────────────────────────────────────────

    def _get_root_domain(self, netloc: str) -> str:
        parts = netloc.split('.')
        SECOND_LEVEL_TLDS = {
            'my.id', 'co.id', 'web.id', 'sch.id', 'ac.id', 'net.id',
            'co.uk', 'com.au', 'co.nz', 'co.za', 'com.br', 'com.mx',
        }
        if len(parts) >= 3:
            candidate = '.'.join(parts[-2:])
            if candidate in SECOND_LEVEL_TLDS:
                return '.'.join(parts[-3:]) if len(parts) >= 3 else netloc
        return '.'.join(parts[-2:]) if len(parts) >= 2 else netloc

    def _discover_bases(self) -> List[str]:
        bases = [self.base_url]
        parsed_main = urlparse(self.base_url)
        main_root = self._get_root_domain(parsed_main.netloc)

        try:
            r = self._client.get(self.base_url, headers=HEADERS)
            if not r or not r.ok:
                return bases

            js_texts = [r.text]
            for m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', r.text):
                js_url = urljoin(self.base_url, m.group(1))
                jr = self._client.get(js_url)
                if jr and jr.ok:
                    js_texts.append(jr.text)

            all_text = '\n'.join(js_texts)
            found_urls = re.findall(
                r'["\`](https?://[a-zA-Z0-9._:-]+)["\`/]', all_text
            )

            for found_url in found_urls:
                p = urlparse(found_url)
                if not p.netloc or p.netloc == parsed_main.netloc:
                    continue
                found_root = self._get_root_domain(p.netloc)
                if found_root != main_root:
                    continue
                base = f"{p.scheme}://{p.netloc}"
                if base not in bases and is_in_scope(base, self.base_url, self.scope_mode):
                    bases.append(base)
                    _info(f"Subdomain ditemukan: {base}")

        except Exception:
            pass

        return bases

    def _is_directory_listing(self, body: str) -> bool:
        body_lower = body.lower()
        has_listing = any(sig in body_lower for sig in LISTING_SIGNATURES)
        if not has_listing:
            return False
        has_fp = any(sig in body_lower for sig in FALSE_POSITIVE_SIGNATURES)
        return not has_fp

    # ── Recursive enumerate ───────────────────────────────────────────────────

    def _enumerate_recursive(
        self,
        url: str,
        body: str,
        depth: int,
        results: Dict,
    ):
        """
        Enumerate isi direktori yang terbuka, rekursif sampai max_depth.
        Semua file/folder yang ditemukan disimpan di results.
        """
        if depth > self.max_depth:
            return

        items = _enumerate_directory(body, url)
        if not items:
            return

        file_names = [i['name'] for i in items if not i['is_dir']]
        dir_names  = [i['name'] for i in items if i['is_dir']]

        _info(f"  └─ {url} → {len(file_names)} file, {len(dir_names)} subdirektori")

        # Simpan ke results
        with self._lock:
            # Cari entry yang sudah ada untuk URL ini
            for vp in results['vulnerable_paths']:
                if vp['url'] == url:
                    vp['contents'] = items
                    vp['file_count'] = len(file_names)
                    vp['dir_count']  = len(dir_names)
                    severity       = _classify_severity(url, [i['name'] for i in items])
                    vp['severity'] = severity
                    vp['vuln_key'] = SEVERITY_VULN_KEY.get(severity) 
                    vp['notable_files'] = [
                        i['full_url'] for i in items
                        if not i['is_dir'] and any(
                            i['name'].lower().endswith(ext)
                            for ext in SENSITIVE_EXTENSIONS
                        )
                    ]
                    break

        # Rekursif ke subdirektori
        for item in items:
            if not item['is_dir']:
                continue
            sub_url = item['full_url'].rstrip('/')
            with self._lock:
                if sub_url in self._probed_urls:
                    continue
                self._probed_urls.add(sub_url)

            try:
                r = self._client.get(sub_url + '/', headers=HEADERS)
                if r and r.status_code == 200 and self._is_directory_listing(r.text):
                    _warn(f"Sub-direktori terbuka: {sub_url}/")
                    with self._lock:
                        results['vulnerable_paths'].append({
                            'url':          sub_url + '/',
                            'status_code':  r.status_code,
                            'path':         item['href'],
                            'base':         url,
                            'contents':     [],
                            'file_count':   0,
                            'dir_count':    0,
                            'severity':     'UNKNOWN',
                            'vuln_key':     None,  
                            'notable_files': [],
                            'is_nested':    True,
                        })
                    self._enumerate_recursive(sub_url + '/', r.text, depth + 1, results)
            except Exception:
                pass

    # ── Probe ─────────────────────────────────────────────────────────────────

    def _probe(self, base: str, path: str, results: Dict):
        url = f"{base}/{path.lstrip('/')}"

        with self._lock:
            if url in self._probed_urls:
                return
            self._probed_urls.add(url)

        try:
            r = self._client.get(url, headers=HEADERS)
            with self._lock:
                results['total_tested'] += 1

            if not r or r.status_code != 200:
                return

            if not self._is_directory_listing(r.text):
                return

            with self._lock:
                existing = [v['url'] for v in results['vulnerable_paths']]
                if url in existing:
                    return
                _warn(f"Directory listing aktif: {url}")
                results['vulnerable_paths'].append({
                    'url':          url,
                    'status_code':  r.status_code,
                    'path':         path,
                    'base':         base,
                    'contents':     [],
                    'file_count':   0,
                    'dir_count':    0,
                    'severity':     'UNKNOWN',
                    'vuln_key':     None, 
                    'notable_files': [],
                    'is_nested':    False,
                })

            # Enumerate isi direktori
            if self.enumerate_contents:
                self._enumerate_recursive(url, r.text, depth=1, results=results)

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
            'waf_detected':     False,
            'waf_info':         {},
        }

        try:
            # Step 1 — WAF Detection & Discover base URLs
            _step(1, 4, "Mengumpulkan target ...")
            _info(f"Base URL: {self.base_url}")

            # Minimal WAF detection (informatif)
            waf = WAFChecker(self.base_url, self._client, HEADERS)
            waf_detected = waf.detect()
            results['waf_detected'] = waf_detected
            results['waf_info']     = waf.get_info()
            if waf_detected:
                waf_name = waf.get_waf_name() or 'Unknown'
                _info(f"WAF terdeteksi: {waf_name} (beberapa path mungkin di-block)")
            else:
                _info("WAF tidak terdeteksi")

            all_bases = self._discover_bases()
            self._all_bases = all_bases
            _info(f"Total bases: {len(all_bases)} → {', '.join(all_bases)}")

            # Step 2 — Probe semua kombinasi
            all_paths = list(dict.fromkeys(DIRECTORY_PATHS + self.extra_paths))
            total = len(all_bases) * len(all_paths)
            _step(2, 4, f"Probing {total} direktori "
                        f"({len(all_bases)} base × {len(all_paths)} path) ...")

            with ThreadPoolExecutor(max_workers=15) as ex:
                futures = [
                    ex.submit(self._probe, base, path, results)
                    for base in all_bases
                    for path in all_paths
                ]
                for f in as_completed(futures):
                    try:
                        f.result()
                    except HostDeadException:
                        for rem in futures:
                            rem.cancel()
                        break
                    except Exception:
                        pass

            # Step 3 — Finalisasi & summary
            _step(3, 4, "Finalisasi hasil ...")

            if results['vulnerable_paths']:
                results['vulnerable'] = True
                count = len(results['vulnerable_paths'])

                # Severity summary
                severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
                total_files    = 0
                total_notable  = 0

                for vp in results['vulnerable_paths']:
                    sev = vp.get('severity', 'UNKNOWN')
                    severity_count[sev] = severity_count.get(sev, 0) + 1
                    total_files   += vp.get('file_count', 0)
                    total_notable += len(vp.get('notable_files', []))

                results['summary'] = {
                    'total_vulnerable_paths': count,
                    'total_files_exposed':    total_files,
                    'total_notable_files':    total_notable,
                    'severity_breakdown':     {k: v for k, v in severity_count.items() if v > 0},
                }

                results['findings'].append(
                    f"Directory listing aktif pada {count} path."
                )

                for vp in results['vulnerable_paths']:
                    sev     = vp.get('severity', '?')
                    n_files = vp.get('file_count', 0)
                    nested  = ' [nested]' if vp.get('is_nested') else ''
                    results['findings'].append(
                        f"  → [{sev}] [HTTP {vp['status_code']}] {vp['url']}"
                        f" ({n_files} file){nested}"
                    )
                    for nf in vp.get('notable_files', []):
                        results['findings'].append(f"      ⚠ File sensitif: {nf}")

                _ok(f"Total: {count} path rentan | "
                    f"CRITICAL={severity_count['CRITICAL']} "
                    f"HIGH={severity_count['HIGH']} "
                    f"MEDIUM={severity_count['MEDIUM']}")

            else:
                results['findings'].append(
                    "Tidak ditemukan directory listing yang aktif."
                )
                _info("Tidak ditemukan directory listing.")

        except Exception as e:
            results['error'] = str(e)
        finally:
            self._client.close()

        return results