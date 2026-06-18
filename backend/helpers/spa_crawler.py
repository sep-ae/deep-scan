# helpers/spa_crawler.py — Universal SPA Crawling Helper
"""
Modul universal untuk mendeteksi SPA (Single Page Application) dan
melakukan crawling via Playwright. Bisa dipakai oleh semua scanner module.

Penggunaan:
    from helpers.spa_crawler import SPACrawler

    spa = SPACrawler(base_url, http_client, cookies=cookies, scope_mode='wildcard')
    result = spa.crawl()

    if result['is_spa']:
        paths    = result['paths']
        html     = result['html']
        api_bases = result['api_bases']
"""
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from helpers.parsers import (
    spa_confidence,
    extract_all_js_paths,
    extract_paths_from_js,
    normalize_url,
)
from helpers.scope import is_in_scope

# Lazy import: browser.py requires playwright at module level
try:
    from helpers.browser import crawl_spa
except ImportError:
    crawl_spa = None


def _info(msg: str):  print(f"  [*] {msg}")
def _warn(msg: str):  print(f"  [!] {msg}")


def _extract_js_srcs(html: str, base_url: str = '') -> List[str]:
    """Extract semua JavaScript source URLs dari HTML."""
    try:
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
    except ImportError:
        # bs4 tidak tersedia, fallback ke regex
        srcs = []
        for m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html):
            srcs.append(normalize_url(m.group(1), base_url))
        return list(dict.fromkeys(srcs))


class SPACrawler:
    """
    Universal SPA detector + crawler yang bisa dipakai semua vulnerability scanner.

    Flow:
        1. Fetch halaman utama
        2. Cek SPA confidence
        3. Jika SPA -> crawl dengan Playwright (jika tersedia)
        4. Fallback ke JS parsing jika Playwright tidak tersedia
        5. Extract paths, API bases, dan cookies
    """

    def __init__(
        self,
        base_url: str,
        http_client,
        cookies: Optional[Dict] = None,
        scope_mode: str = 'wildcard',
        headers: Optional[Dict] = None,
    ):
        self.base_url    = base_url.rstrip('/')
        self._client     = http_client
        self.cookies     = cookies or {}
        self.scope_mode  = scope_mode
        self._headers    = headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,*/*',
        }

    def crawl(self) -> Dict[str, Any]:
        """
        Main entry point — detect SPA dan crawl.

        Returns:
            {
                'is_spa':          bool,
                'playwright_used': bool,
                'html':            str,     # rendered HTML (atau raw HTML jika bukan SPA)
                'paths':           list,    # paths yang ditemukan
                'api_bases':       list,    # external API base URLs
                'cookies':         dict,    # cookies dari browser context
                'error':           str|None,
            }
        """
        result = {
            'is_spa':          False,
            'playwright_used': False,
            'html':            '',
            'paths':           [],
            'api_bases':       [],
            'cookies':         {},
            'error':           None,
        }

        try:
            r = self._client.get(self.base_url, headers=self._headers)
            if not r or not r.ok:
                result['error'] = 'Failed to fetch base URL'
                return result

            raw_html   = r.text
            confidence = spa_confidence(raw_html)

            if confidence >= 2:
                result['is_spa'] = True
                _info("SPA terdeteksi, crawling dengan Playwright ...")

                if PLAYWRIGHT_AVAILABLE:
                    try:
                        pw_result = self._crawl_with_playwright()
                        result['playwright_used'] = True
                        result['html']            = pw_result.get('html', raw_html)
                        result['cookies']         = pw_result.get('cookies', {})

                        # Extract paths dari Playwright result
                        paths = []
                        for call in pw_result.get('api_calls', []):
                            path = call['url'].replace(self.base_url, '') \
                                        .split('?')[0].split('#')[0]
                            if path and path != '/' and not path.startswith('http'):
                                paths.append(path)

                        paths.extend(extract_all_js_paths(result['html']))

                        # Extract dari JS sources
                        js_srcs = _extract_js_srcs(result['html'], self.base_url)
                        api_bases = []
                        for js_url in js_srcs:
                            js_r = self._client.get(js_url)
                            if js_r and js_r.ok:
                                paths.extend(extract_paths_from_js(js_r.text))
                                api_bases.extend(
                                    self._extract_api_bases_from_text(js_r.text)
                                )

                        result['paths']     = list(set(paths))
                        result['api_bases'] = list(dict.fromkeys(api_bases))

                    except Exception as e:
                        _warn(f"Playwright gagal ({e}), fallback ke JS parsing")
                        result['playwright_used'] = False
                        result['html'] = raw_html
                        self._fallback_js_crawl(raw_html, result)
                else:
                    _info("Playwright tidak tersedia, fallback ke JS parsing")
                    result['html'] = raw_html
                    self._fallback_js_crawl(raw_html, result)
            else:
                # Bukan SPA — tetap extract paths dari JS
                result['html'] = raw_html
                self._fallback_js_crawl(raw_html, result)

        except Exception as e:
            result['error'] = str(e)

        return result

    def _crawl_with_playwright(self) -> Dict:
        """Crawl SPA dengan Playwright browser."""
        if crawl_spa is None:
            raise ImportError("Playwright/browser helper not available")

        initial_cookies = None
        if self.cookies:
            initial_cookies = [
                {"name": k, "value": v, "url": self.base_url}
                for k, v in self.cookies.items()
            ]

        return crawl_spa(
            self.base_url,
            block_images=True,
            initial_cookies=initial_cookies,
        )

    def _fallback_js_crawl(self, html: str, result: Dict):
        """Fallback: extract paths dari JS source files tanpa Playwright."""
        paths     = []
        api_bases = []

        js_srcs = _extract_js_srcs(html, self.base_url)
        for js_url in js_srcs:
            js_r = self._client.get(js_url)
            if js_r and js_r.ok:
                paths.extend(extract_paths_from_js(js_r.text))
                api_bases.extend(
                    self._extract_api_bases_from_text(js_r.text)
                )

        paths.extend(extract_all_js_paths(html))

        result['paths']     = list(set(result.get('paths', []) + paths))
        result['api_bases'] = list(dict.fromkeys(
            result.get('api_bases', []) + api_bases
        ))

    def _extract_api_bases_from_text(self, text: str) -> List[str]:
        """Extract API base URLs dari teks JavaScript."""
        bases = []

        # Full URLs (https://api.example.com/api/...)
        for api_url in re.findall(
            r'["`](https?://[a-zA-Z0-9._-]+/api(?:/[a-zA-Z0-9_/-]*)?)["`]',
            text
        ):
            base = api_url.rstrip('/')
            if is_in_scope(base, self.base_url, self.scope_mode):
                bases.append(base)

        # Relative API paths (/api/v1, /api/users, etc.)
        for base in re.findall(
            r'["`](/api/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)?)["`]',
            text
        ):
            parts = base.strip('/').split('/')
            if len(parts) >= 2:
                normalized = '/' + '/'.join(parts[:2])
                if normalized not in bases:
                    bases.append(normalized)

        return bases

    # ── Static utilities ──────────────────────────────────────────────────────

    @staticmethod
    def is_available() -> bool:
        """Check apakah Playwright tersedia."""
        return PLAYWRIGHT_AVAILABLE

    @staticmethod
    def check_spa(html: str) -> bool:
        """Quick check apakah HTML adalah SPA."""
        return spa_confidence(html) >= 2
