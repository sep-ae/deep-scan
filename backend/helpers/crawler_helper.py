import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from .http_client import HttpClient
from .waf_checker import WAFChecker
from .spa_crawler import SPACrawler
from .parsers import (
    extract_links,
    extract_forms,
    extract_script_srcs,
    extract_paths_from_js,
    normalize_url
)
from .scope import is_in_scope

def _info(msg: str):  print(f"  [*] {msg}")
def _warn(msg: str):  print(f"  [!] {msg}")
def _ok(msg: str):    print(f"  [+] {msg}")
def _step(i: int, total: int, msg: str): print(f"\n  [{i}/{total}] {msg}")

class CrawlerHelper:
    """
    Centralized crawler yang melakukan:
    1. WAF Detection
    2. HTML Link & Form Crawling (depth 2)
    3. JS source parsing (cari API path)
    4. SPA Crawling (jika terdeteksi SPA)
    
    Hasilnya (DiscoveredAssets) dipakai oleh semua module web_vulnerabilities.
    """
    def __init__(self, base_url: str, cookies: Optional[Dict] = None, scope_mode: str = 'wildcard'):
        self.base_url = base_url.rstrip('/')
        self.cookies = cookies or {}
        self.scope_mode = scope_mode
        self.client = HttpClient(
            timeout=8.0,
            cookies=self.cookies,
            verify=False,
            retries=1
        )
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/json,*/*',
        }
        
    def crawl(self) -> Dict[str, Any]:
        result = {
            'endpoints': [],
            'forms': [],
            'api_bases': [],
            'params': [],
            'is_spa': False,
            'waf_detected': False,
            'waf_info': {},
            'error': None
        }
        
        try:
            # 1. Detect WAF
            _step(1, 4, "Mendeteksi WAF...")
            waf = WAFChecker(self.base_url, self.client, self.headers)
            result['waf_detected'] = waf.detect()
            result['waf_info'] = waf.get_info()
            waf_name = result['waf_info'].get('waf_name', '?')
            waf_status = f"terdeteksi ({waf_name})" if result['waf_detected'] else "tidak terdeteksi"
            _info(f"WAF: {waf_status}")
            
            # 2. SPA Crawler (also fetches root page)
            _step(2, 4, "Menjalankan SPA/JS Scanner...")
            spa = SPACrawler(self.base_url, self.client, cookies=self.cookies, scope_mode=self.scope_mode)
            spa_result = spa.crawl()
            
            result['is_spa'] = spa_result['is_spa']
            result['api_bases'].extend(spa_result.get('api_bases', []))
            
            raw_html = spa_result.get('html', '')
            pw_used = spa_result.get('playwright_used', False)
            _info(f"SPA Detected: {result['is_spa']} | Playwright Used: {pw_used}")
            
            # Collect paths from SPA result
            for p in spa_result.get('paths', []):
                full_path = normalize_url(p, self.base_url)
                if is_in_scope(full_path, self.base_url, self.scope_mode):
                    if full_path not in result['endpoints']:
                        result['endpoints'].append(full_path)
            
            # 3. HTML Forms & Links
            _step(3, 4, "Mengekstrak HTML Forms & Links...")
            if raw_html:
                # Extract root forms
                forms = extract_forms(raw_html, self.base_url)
                for f in forms:
                    action = f.get('action')
                    if is_in_scope(action, self.base_url, self.scope_mode):
                        result['forms'].append(f)
                        if action and action not in result['endpoints']:
                            result['endpoints'].append(action)
                        for inp in f.get('inputs', []):
                            pname = inp.get('name')
                            if pname and pname not in result['params']:
                                result['params'].append(pname)
                
                # Extract root links (depth 1)
                links = extract_links(raw_html, self.base_url)
                valid_links = [lnk for lnk in links if is_in_scope(lnk, self.base_url, self.scope_mode)]
                
                _info(f"Ditemukan {len(valid_links)} link di halaman utama.")
                
                # Crawl Depth 2 (limit to 10 to avoid too long scan)
                for link in valid_links[:10]:
                    if link not in result['endpoints']:
                        result['endpoints'].append(link)
                    
                    try:
                        r = self.client.get(link, headers=self.headers)
                        if r and r.ok and 'text/html' in r.headers.get('Content-Type', '').lower():
                            sub_forms = extract_forms(r.text, self.base_url)
                            for f in sub_forms:
                                action = f.get('action')
                                if is_in_scope(action, self.base_url, self.scope_mode):
                                    if f not in result['forms']:
                                        result['forms'].append(f)
                                    if action and action not in result['endpoints']:
                                        result['endpoints'].append(action)
                                    for inp in f.get('inputs', []):
                                        pname = inp.get('name')
                                        if pname and pname not in result['params']:
                                            result['params'].append(pname)
                    except Exception:
                        pass
                        
            # 4. Probe endpoints untuk memastikan response dan content type
            _step(4, 4, f"Memvalidasi {len(result['endpoints'])} endpoints...")
            valid_endpoints = []
            for ep in result['endpoints']:
                try:
                    r = self.client.get(ep, headers=self.headers)
                    # We accept 200, 201, 403 (might be WAF), 405 (method not allowed)
                    if r and r.status_code not in (404, 410):
                        if not WAFChecker.is_cloudflare_page(r.text):
                            valid_endpoints.append(ep)
                except Exception:
                    pass
                    
            result['endpoints'] = list(dict.fromkeys(valid_endpoints))
            _ok(f"Selesai! {len(result['endpoints'])} endpoints, {len(result['forms'])} forms, {len(result['params'])} params valid.")

        except Exception as e:
            result['error'] = str(e)
            _warn(f"Crawler error: {e}")
        finally:
            self.client.close()
            
        return result
