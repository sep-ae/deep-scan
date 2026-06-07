import requests
import re
import time
import urllib3
import hashlib
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TechFingerprint:
    """
    Modul fingerprinting teknologi web.

    Mendeteksi stack teknologi target melalui beberapa teknik:
    - Favicon hash matching (bypass CDN/WAF)
    - Config file mining (composer.json, package.json)
    - HTTP header analysis (Server, X-Powered-By, Set-Cookie)
    - HTML content pattern matching (meta generator, script src, inline markers)
    - Cookie-based framework identification
    """

    def __init__(self, url: str, timeout: float = 10.0, max_endpoints: int = 10):
        self.url = url if url.startswith('http') else f'https://{url}'
        self.timeout = timeout
        self.max_endpoints = max_endpoints
        self.all_responses: List[Dict[str, Any]] = []
        self.start_time = time.time()

        # Cache untuk menghindari repeated join
        self._cached_content: Optional[str] = None
        self._cached_headers: Optional[str] = None
        self._cached_cookies: Optional[Dict[str, str]] = None

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/124.0.0.0 Safari/537.36'
            ),
            'Accept': (
                'text/html,application/xhtml+xml,application/json,'
                'image/webp,*/*;q=0.8'
            ),
        })

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        print(f"[*] Tech Fingerprint: Scanning {self.url} ...")
        self._crawl_endpoints()

        if not self.all_responses:
            return {'error': 'Tidak ada endpoint yang dapat dijangkau'}

        technologies = {
            'favicon_signature':   self._detect_favicon_framework(),
            'server_os':           self._detect_os(),
            'web_server':          self._detect_web_server(),
            'language':            self._detect_programming_language(),
            'backend_framework':   self._detect_backend_framework(),
            'cms':                 self._detect_cms(),
            'frontend_framework':  self._detect_frontend_framework(),
            'javascript_libs':     self._detect_js_libs(),
            'css_frameworks':      self._detect_css_frameworks(),
            'cdn':                 self._detect_cdn(),
            'security':            self._detect_security(),
            'analytics':           self._detect_analytics(),
            'meta_generator':      self._detect_meta_generator(),
            'database_hints':      self._detect_database_hints(),
        }

        return {k: v for k, v in technologies.items() if v}

    # ── Crawling ──────────────────────────────────────────────────────────────

    def _crawl_endpoints(self) -> None:
        """Mengumpulkan response dari endpoint-endpoint umum."""
        base_url = self.url.rstrip('/')
        endpoints = [
            '',
            '/favicon.ico',
            '/robots.txt',
            '/sitemap.xml',
            '/login',
            '/admin',
            '/wp-json/',
            '/wp-login.php',
            '/composer.json',
            '/package.json',
            '/manifest.json',
        ]

        for path in endpoints[:self.max_endpoints]:
            target_url = f"{base_url}{path}"
            try:
                resp = self.session.get(
                    target_url, timeout=self.timeout,
                    verify=False, allow_redirects=True,
                )

                content_text = ""
                try:
                    content_text = resp.text[:100_000]
                except (UnicodeDecodeError, AttributeError):
                    pass

                self.all_responses.append({
                    'url': target_url,
                    'path': path,
                    'status': resp.status_code,
                    'headers': {k.lower(): v for k, v in resp.headers.items()},
                    'content': content_text,
                    'raw_content': resp.content,
                    'cookies': resp.cookies.get_dict(),
                })
            except requests.RequestException:
                continue

    # ── Helpers (dengan cache) ────────────────────────────────────────────────

    def _get_combined_content(self) -> str:
        if self._cached_content is None:
            self._cached_content = '\n'.join(
                r['content'] for r in self.all_responses
            )
        return self._cached_content

    def _get_combined_headers(self) -> str:
        if self._cached_headers is None:
            self._cached_headers = '\n'.join(
                str(r['headers']) for r in self.all_responses
            )
        return self._cached_headers

    def _get_all_cookies(self) -> Dict[str, str]:
        if self._cached_cookies is None:
            self._cached_cookies = {}
            for r in self.all_responses:
                self._cached_cookies.update(r['cookies'])
        return self._cached_cookies

    def _extract_version(self, pattern: str, text: str) -> Optional[str]:
        match = re.search(pattern, text, re.IGNORECASE)
        if match and match.groups():
            return match.group(1)
        return None

    def _header_value(self, keys: List[str]) -> Optional[str]:
        """Ambil nilai header pertama yang ditemukan dari semua response."""
        for r in self.all_responses:
            for key in keys:
                val = r['headers'].get(key)
                if val:
                    return val
        return None

    # ── Detection Modules ─────────────────────────────────────────────────────

    def _detect_favicon_framework(self) -> Optional[str]:
        """Deteksi framework melalui MD5 hash favicon.ico."""
        for r in self.all_responses:
            if 'favicon.ico' in r['url'] and r['status'] == 200:
                try:
                    md5_hash = hashlib.md5(r['raw_content']).hexdigest()

                    signatures = {
                        # PHP Frameworks
                        '69c728902a9f997cb956c36798a28796': 'Laravel',
                        'd41d8cd98f00b204e9800998ecf8427e': 'Empty Favicon',
                        # Java
                        '050519992d9d924cb956c36798a28796': 'Spring Boot',
                        # JavaScript Frameworks
                        '88081f2150495f327e573715694a1131': 'React (Create React App)',
                        'e3ee45445209c15858604928b577005c': 'Vue.js (Vue CLI)',
                        '20e8b153b6f937d53243f7736f875323': 'Angular',
                        # CMS
                        '06e3917a2bf1cf76dc1b73a51297dd9e': 'WordPress',
                        '3e4b418ff5e58b5138e0f786a6e2f701': 'Joomla',
                        # Platforms
                        'f3415a6e29783f9828236780360a0494': 'Docker Default',
                        '1ba2ae710d927f13d483fd5d1e548c9b': 'Grafana',
                        '2b7e5e94cda6ce76cf5c7a47a6d5e95f': 'GitLab',
                        'a61e09aafa53a953f7e530bf0b0c0cfe': 'Jenkins',
                        '4c80c80bec80e3f5b3c1aca4efb8de9a': 'Kibana',
                    }

                    result = signatures.get(md5_hash)
                    if result:
                        return f"{result} (favicon: {md5_hash[:12]})"
                except (ValueError, TypeError):
                    pass
        return None

    def _detect_web_server(self) -> Optional[str]:
        """Deteksi web server dari header Server dan X-Powered-By."""
        server = self._header_value(['server', 'x-powered-by'])
        if not server:
            return None

        known_servers = {
            'nginx': 'Nginx',
            'apache': 'Apache',
            'cloudflare': 'Cloudflare',
            'litespeed': 'LiteSpeed',
            'microsoft-iis': 'Microsoft IIS',
            'gws': 'Google Web Server',
            'openresty': 'OpenResty',
            'caddy': 'Caddy',
            'gunicorn': 'Gunicorn',
            'uvicorn': 'Uvicorn',
            'kestrel': 'Kestrel',
        }

        server_lower = server.lower()
        for key, name in known_servers.items():
            if key in server_lower:
                version = self._extract_version(
                    rf'{key}/?([\d.]+)', server
                )
                return f"{name} {version}" if version else name
        return server

    def _detect_os(self) -> Optional[str]:
        """Deteksi sistem operasi dari header HTTP."""
        headers = self._get_combined_headers().lower()
        os_map = [
            ('ubuntu', 'Ubuntu'),
            ('debian', 'Debian'),
            ('centos', 'CentOS'),
            ('red hat', 'Red Hat'),
            ('fedora', 'Fedora'),
            ('win32', 'Windows Server'),
            ('win64', 'Windows Server'),
            ('asp.net', 'Windows Server'),
        ]
        for marker, os_name in os_map:
            if marker in headers:
                return os_name
        return None

    def _detect_programming_language(self) -> List[str]:
        """Deteksi bahasa pemrograman dari header, cookie, dan konten."""
        langs = set()
        headers = self._get_combined_headers().lower()
        cookie_keys = [c.lower() for c in self._get_all_cookies().keys()]
        content = self._get_combined_content().lower()

        checks = [
            ('PHP', lambda: (
                'x-powered-by: php' in headers
                or 'phpsessid' in cookie_keys
                or '.php' in content
            )),
            ('ASP.NET', lambda: (
                'asp.net' in headers
                or 'asp.net_sessionid' in cookie_keys
                or '__viewstate' in content
            )),
            ('Java', lambda: (
                'jsessionid' in cookie_keys
                or 'x-powered-by: servlet' in headers
            )),
            ('Python', lambda: (
                'x-powered-by: python' in headers
                or 'gunicorn' in headers
                or 'uvicorn' in headers
                or 'werkzeug' in headers
                or 'wsgiserver' in headers
            )),
            ('Ruby', lambda: (
                '_session_id' in cookie_keys
                or 'x-powered-by: phusion' in headers
                or 'x-runtime' in headers
            )),
            ('Node.js', lambda: (
                'x-powered-by: express' in headers
                or 'connect.sid' in cookie_keys
            )),
            ('Go', lambda: (
                'x-powered-by: go' in headers
            )),
        ]

        for lang, check_fn in checks:
            if check_fn():
                langs.add(lang)

        return list(langs)

    def _detect_backend_framework(self) -> List[str]:
        """Deteksi framework backend dari cookie, header, dan config files."""
        frameworks = set()
        cookies = self._get_all_cookies()
        headers = self._get_combined_headers().lower()
        content = self._get_combined_content()

        # Config file mining
        for r in self.all_responses:
            if 'composer.json' in r['url'] and r['status'] == 200:
                c = r['content'].lower()
                if '"laravel/framework"' in c:
                    frameworks.add('Laravel (Confirmed via Composer)')
                if '"codeigniter' in c:
                    frameworks.add('CodeIgniter (Confirmed via Composer)')
                if '"symfony/' in c:
                    frameworks.add('Symfony (Confirmed via Composer)')

        # Cookie signatures
        cookie_map = {
            'laravel_session': 'Laravel',
            'XSRF-TOKEN': 'Laravel',
            'ci_session': 'CodeIgniter',
            'csrftoken': 'Django',
            'django_session': 'Django',
            'sessionid': 'Django',
            '_rails_session': 'Ruby on Rails',
            'connect.sid': 'Express.js',
            'phoenix': 'Phoenix (Elixir)',
            'CraftSessionId': 'Craft CMS',
            'flask': 'Flask',
            'session': 'Generic Session',
        }

        for cookie_name, framework in cookie_map.items():
            if any(cookie_name.lower() in c.lower() for c in cookies.keys()):
                if framework != 'Generic Session':
                    frameworks.add(framework)

        # Header-based detection
        header_checks = [
            ('x-powered-by: express', 'Express.js'),
            ('x-powered-by: next.js', 'Next.js'),
            ('x-powered-by: nuxt', 'Nuxt.js'),
            ('x-powered-by: php', 'PHP'),
            ('x-powered-by: asp.net', 'ASP.NET'),
            ('werkzeug', 'Flask'),
            ('gunicorn', 'Python WSGI'),
            ('uvicorn', 'FastAPI / Starlette'),
        ]
        for marker, fw in header_checks:
            if marker in headers:
                frameworks.add(fw)

        # Content-based detection
        content_lower = content.lower()
        if 'whoops! there was an error' in content_lower:
            frameworks.add('Laravel (Debug Mode)')
        if 'djangoproject.com' in content_lower:
            frameworks.add('Django')
        if '__next_data__' in content_lower:
            frameworks.add('Next.js')
        if '__nuxt__' in content_lower:
            frameworks.add('Nuxt.js')

        return list(frameworks)

    def _detect_cms(self) -> List[str]:
        """Deteksi Content Management System."""
        cms_list = set()
        content = self._get_combined_content()

        # API probing
        for r in self.all_responses:
            if 'wp-json' in r['url'] and r['status'] == 200:
                cms_list.add('WordPress (API Exposed)')
            if 'wp-login.php' in r['url'] and r['status'] == 200:
                cms_list.add('WordPress')

        signatures = [
            ('WordPress', r'wp-content|wp-includes|/wp-json/'),
            ('Joomla', r'content="Joomla!|/media/jui/'),
            ('Drupal', r'Drupal|sites/all/modules|drupal\.js'),
            ('OpenCart', r'catalog/view/theme'),
            ('PrestaShop', r'prestashop|/themes/default-bootstrap/'),
            ('Wix', r'wix-site|static\.wixstatic\.com'),
            ('Shopify', r'shopify\.com|cdn\.shopify'),
            ('Squarespace', r'squarespace\.com|static1\.squarespace'),
            ('Ghost', r'ghost-(?:url|version)|content/themes'),
            ('Moodle', r'moodle|/theme/boost/'),
        ]

        for name, pattern in signatures:
            if re.search(pattern, content, re.IGNORECASE):
                if name == 'WordPress':
                    ver = self._extract_version(
                        r'content="WordPress ([\d.]+)"', content
                    )
                    cms_list.add(f"WordPress {ver}" if ver else "WordPress")
                else:
                    cms_list.add(name)

        return list(cms_list)

    def _detect_frontend_framework(self) -> List[str]:
        """Deteksi frontend framework dari konten HTML/JS."""
        fw = set()
        content = self._get_combined_content()

        patterns = {
            'React':      r'react[\.\-][\d\.]+|react-dom|_reactRootContainer|__react',
            'Vue.js':     r'vue[\.\-][\d\.]+\.js|data-v-[a-f0-9]|__vue_app__',
            'Angular':    r'angular[\.\-][\d\.]+\.js|ng-version|ng-app|zone\.js',
            'Svelte':     r'svelte|__svelte',
            'Next.js':    r'/_next/static|__NEXT_DATA__',
            'Nuxt.js':    r'/_nuxt/|__NUXT__',
            'Remix':      r'remix|__remixContext',
            'Astro':      r'astro-island|astro\.js',
            'Livewire':   r'livewire(?:\.js)?|wire:',
            'Alpine.js':  r'alpine(?:\.js)?|x-data=',
            'HTMX':       r'htmx\.org|hx-get=|hx-post=',
            'Ember.js':   r'ember[\.\-][\d\.]+\.js|ember-view',
            'Gatsby':     r'gatsby-',
        }

        for name, pattern in patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                fw.add(name)
        return list(fw)

    def _detect_js_libs(self) -> List[str]:
        """Deteksi library JavaScript dari package.json dan konten."""
        libs = set()
        content = self._get_combined_content()

        # Config file mining
        for r in self.all_responses:
            if 'package.json' in r['url'] and r['status'] == 200:
                try:
                    data = json.loads(r['content'])
                    deps = {
                        **data.get('dependencies', {}),
                        **data.get('devDependencies', {}),
                    }
                    important_libs = [
                        'react', 'vue', 'angular', 'axios', 'lodash',
                        'moment', 'dayjs', 'bootstrap', 'tailwindcss',
                        'express', 'next', 'nuxt', 'svelte',
                    ]
                    for lib_name, version in deps.items():
                        if any(t in lib_name for t in important_libs):
                            libs.add(f"{lib_name} {version} (package.json)")
                except (json.JSONDecodeError, AttributeError):
                    pass

        # Regex fallback
        patterns = {
            'jQuery':    r'jquery[.-]([\d.]+)',
            'Lodash':    r'lodash[.-]([\d.]+)',
            'Axios':     r'axios[.-]([\d.]+)',
            'Moment.js': r'moment[.-]([\d.]+)',
            'Chart.js':  r'chart[.-]([\d.]+)',
            'D3.js':     r'd3[.-]([\d.]+)',
            'Three.js':  r'three[.-]([\d.]+)',
            'Socket.IO': r'socket\.io[.-]([\d.]+)',
            'SweetAlert': r'sweetalert2?[.-]([\d.]+)',
        }

        for name, regex in patterns.items():
            version = self._extract_version(regex, content)
            if version:
                libs.add(f"{name} v{version}")

        return list(libs)

    def _detect_css_frameworks(self) -> List[str]:
        """Deteksi CSS framework dari konten halaman."""
        css = set()
        content = self._get_combined_content()

        patterns = {
            'Bootstrap':      r'bootstrap(?:[.\-]([\d.]+))?\.(?:min\.)?css',
            'Tailwind CSS':   r'tailwind(?:css)?',
            'Bulma':          r'bulma(?:[.\-]([\d.]+))?\.(?:min\.)?css',
            'Foundation':     r'foundation(?:[.\-]([\d.]+))?\.(?:min\.)?css',
            'Materialize':    r'materialize(?:[.\-]([\d.]+))?\.(?:min\.)?css',
            'Semantic UI':    r'semantic(?:[.\-]([\d.]+))?\.(?:min\.)?css',
        }

        for name, regex in patterns.items():
            match = re.search(regex, content, re.IGNORECASE)
            if match:
                ver = match.group(1) if match.groups() and match.group(1) else ''
                css.add(f"{name} {ver}".strip())
        return list(css)

    def _detect_meta_generator(self) -> Optional[str]:
        """Deteksi meta generator tag dari HTML."""
        content = self._get_combined_content()
        pattern = r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']'
        match = re.search(pattern, content, re.IGNORECASE)
        return match.group(1) if match else None

    def _detect_cdn(self) -> List[str]:
        """Deteksi CDN/Cloud dari header dan konten."""
        cdns = set()
        headers = self._get_combined_headers().lower()
        content = self._get_combined_content().lower()

        cdn_map = {
            'Cloudflare':         ['cf-ray', '__cf_bm', 'cf-cache-status'],
            'Amazon CloudFront':  ['cloudfront', 'amz-cf-id', 'x-amz-cf-pop'],
            'Google Cloud CDN':   ['x-goog-', 'storage.googleapis.com'],
            'Fastly':             ['x-fastly', 'fastly'],
            'Akamai':             ['x-akamai', 'akamai'],
            'Vercel':             ['x-vercel', 'vercel.app'],
            'Netlify':            ['x-nf-', 'netlify'],
            'StackPath':          ['x-sp-', 'stackpath'],
        }

        for name, markers in cdn_map.items():
            if any(m in headers or m in content for m in markers):
                cdns.add(name)
        return list(cdns)

    def _detect_security(self) -> List[str]:
        """Deteksi mekanisme keamanan yang aktif."""
        sec = []
        headers = self._get_combined_headers().lower()

        security_checks = [
            ('cf-ray', 'Cloudflare WAF'),
            ('x-sucuri', 'Sucuri WAF'),
            ('x-fw-protection', 'Firewall Protection'),
            ('content-security-policy', 'CSP Enabled'),
            ('strict-transport-security', 'HSTS Enabled'),
            ('x-frame-options', 'X-Frame-Options'),
            ('x-content-type-options', 'X-Content-Type-Options'),
            ('x-xss-protection', 'X-XSS-Protection'),
            ('permissions-policy', 'Permissions-Policy'),
        ]

        for marker, label in security_checks:
            if marker in headers:
                sec.append(label)
        return sec

    def _detect_analytics(self) -> List[str]:
        """Deteksi layanan analytics dan tracking."""
        content = self._get_combined_content()
        analytics = set()

        checks = [
            (r'UA-\d+-\d+|google-analytics\.com|analytics\.js', 'Google Analytics'),
            (r'G-[A-Z0-9]{5,}|googletagmanager\.com|gtag\(', 'Google GA4 / GTM'),
            (r'facebook\.com/tr|fbq\(', 'Facebook Pixel'),
            (r'hotjar\.com|hj\(', 'Hotjar'),
            (r'clarity\.ms', 'Microsoft Clarity'),
            (r'plausible\.io', 'Plausible Analytics'),
            (r'matomo\.js|piwik\.js', 'Matomo'),
        ]

        for pattern, name in checks:
            if re.search(pattern, content, re.IGNORECASE):
                analytics.add(name)
        return list(analytics)

    def _detect_database_hints(self) -> List[str]:
        """Deteksi petunjuk database dari error message dan header leak."""
        hints = set()
        content = self._get_combined_content().lower()
        headers = self._get_combined_headers().lower()

        db_signatures = [
            (r'mysql|mariadb', 'MySQL/MariaDB'),
            (r'postgresql|pgsql', 'PostgreSQL'),
            (r'microsoft sql server|mssql', 'Microsoft SQL Server'),
            (r'sqlite', 'SQLite'),
            (r'mongodb', 'MongoDB'),
            (r'redis', 'Redis'),
            (r'elasticsearch', 'Elasticsearch'),
            (r'oracle database|ora-\d+', 'Oracle Database'),
        ]

        combined = content + '\n' + headers
        for pattern, db_name in db_signatures:
            if re.search(pattern, combined, re.IGNORECASE):
                hints.add(db_name)

        return list(hints)


# ── Main (untuk testing mandiri) ──────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "madiunkab.go.id"

    print(f"--- Technology Fingerprinter ---")
    tf = TechFingerprint(target)
    result = tf.run()

    print(json.dumps(result, indent=4))