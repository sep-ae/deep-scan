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
    - Favicon hash matching dengan cross-validation
    - Config file mining (composer.json, package.json)
    - HTTP header analysis (Server, X-Powered-By, Set-Cookie)
    - HTML content pattern matching (meta generator, script src, inline markers)
    - Cookie-based framework identification
    - SPA fallback detection untuk menghindari false positive
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
        self._cached_homepage_content: Optional[str] = None

        # Fingerprint homepage untuk SPA fallback detection
        self._homepage_fingerprint: Optional[str] = None

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
            'build_tools':         self._detect_build_tools(),
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

                # Simpan fingerprint homepage untuk SPA fallback detection
                if path == '' and resp.status_code == 200:
                    self._homepage_fingerprint = self._compute_content_fingerprint(content_text)

            except requests.RequestException:
                continue

    # ── Helpers (dengan cache) ────────────────────────────────────────────────

    def _compute_content_fingerprint(self, content: str) -> str:
        """Buat fingerprint singkat dari konten untuk perbandingan SPA fallback."""
        # Ambil <title> dan beberapa marker kunci, bukan seluruh konten
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else ''
        # Hash dari bagian body yang signifikan
        body_match = re.search(r'<body[^>]*>(.*?)</body>', content, re.IGNORECASE | re.DOTALL)
        body_snippet = (body_match.group(1)[:500] if body_match else content[:500]).strip()
        return hashlib.md5(f"{title}|{body_snippet}".encode()).hexdigest()

    def _is_spa_fallback(self, response: Dict[str, Any]) -> bool:
        """
        Cek apakah response dari non-root endpoint adalah SPA fallback
        (halaman yang sama persis dengan homepage, bukan konten asli endpoint).
        """
        if not self._homepage_fingerprint:
            return False
        if response['path'] == '':
            return False
        if response['status'] != 200:
            return False
        fp = self._compute_content_fingerprint(response['content'])
        return fp == self._homepage_fingerprint

    def _get_homepage_content(self) -> str:
        """Ambil konten hanya dari homepage (root endpoint)."""
        if self._cached_homepage_content is None:
            for r in self.all_responses:
                if r['path'] == '' and r['status'] == 200:
                    self._cached_homepage_content = r['content']
                    break
            if self._cached_homepage_content is None:
                self._cached_homepage_content = ''
        return self._cached_homepage_content

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

    def _get_content_type(self, response: Dict[str, Any]) -> str:
        """Ambil content-type dari response headers."""
        return response['headers'].get('content-type', '').lower()

    # ── Detection Modules ─────────────────────────────────────────────────────

    def _detect_favicon_framework(self) -> Optional[str]:
        """
        Deteksi framework melalui MD5 hash favicon.ico.
        Cross-validate dengan konten homepage untuk menghindari false positive
        dari CDN/WAF yang menyajikan favicon default atau cached.
        """
        for r in self.all_responses:
            if 'favicon.ico' not in r['url'] or r['status'] != 200:
                continue

            content_type = self._get_content_type(r)
            # Pastikan response benar-benar favicon/image, bukan HTML fallback
            if content_type and 'html' in content_type:
                continue

            # Skip jika ukuran terlalu kecil (empty/invalid) atau terlalu besar (bukan favicon)
            raw_size = len(r['raw_content'])
            if raw_size < 100 or raw_size > 500_000:
                continue

            try:
                md5_hash = hashlib.md5(r['raw_content']).hexdigest()

                # Signatures dengan cross-validation markers
                # Format: hash -> (name, [homepage_markers_for_validation])
                signatures = {
                    # PHP Frameworks
                    '69c728902a9f997cb956c36798a28796': (
                        'Laravel',
                        ['laravel', 'csrf-token', 'app.js']
                    ),
                    'd41d8cd98f00b204e9800998ecf8427e': (
                        'Empty Favicon',
                        []  # Tidak perlu validasi, selalu benar
                    ),
                    # Java
                    '050519992d9d924cb956c36798a28796': (
                        'Spring Boot',
                        ['spring', 'whitelabel']
                    ),
                    # JavaScript Frameworks
                    '88081f2150495f327e573715694a1131': (
                        'React (Create React App)',
                        ['react', 'root', 'bundle.js']
                    ),
                    'e3ee45445209c15858604928b577005c': (
                        'Vue.js (Vue CLI)',
                        ['vue', 'app', '__vue']
                    ),
                    '20e8b153b6f937d53243f7736f875323': (
                        'Angular',
                        ['angular', 'ng-', 'zone.js']
                    ),
                    # CMS
                    '06e3917a2bf1cf76dc1b73a51297dd9e': (
                        'WordPress',
                        ['wp-content', 'wp-includes', 'wordpress']
                    ),
                    '3e4b418ff5e58b5138e0f786a6e2f701': (
                        'Joomla',
                        ['joomla', '/media/jui/']
                    ),
                    # Platforms — perlu cross-validation ketat
                    'f3415a6e29783f9828236780360a0494': (
                        'Docker Default',
                        ['docker', 'container']
                    ),
                    '1ba2ae710d927f13d483fd5d1e548c9b': (
                        'Grafana',
                        ['grafana', 'grafana-app', 'dashboard']
                    ),
                    '2b7e5e94cda6ce76cf5c7a47a6d5e95f': (
                        'GitLab',
                        ['gitlab', 'gl-']
                    ),
                    'a61e09aafa53a953f7e530bf0b0c0cfe': (
                        'Jenkins',
                        ['jenkins', 'hudson']
                    ),
                    '4c80c80bec80e3f5b3c1aca4efb8de9a': (
                        'Kibana',
                        ['kibana', 'elastic']
                    ),
                }

                match = signatures.get(md5_hash)
                if not match:
                    continue

                name, validators = match

                # Empty favicon tidak perlu validasi
                if name == 'Empty Favicon':
                    return f"{name} (favicon: {md5_hash[:12]})"

                # Cross-validate: cek apakah homepage punya marker terkait
                if validators:
                    homepage = self._get_homepage_content().lower()
                    confirmed = any(v in homepage for v in validators)
                    if confirmed:
                        return f"{name} (favicon: {md5_hash[:12]})"
                    else:
                        # Hash cocok tapi tidak ada marker di homepage — skip
                        # Kemungkinan CDN/WAF menyajikan favicon lain
                        print(
                            f"[!] Favicon hash matches {name} "
                            f"but no supporting evidence in homepage content. "
                            f"Skipping to avoid false positive."
                        )
                        continue
                else:
                    return f"{name} (favicon: {md5_hash[:12]})"

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
                    rf'{key}/?([\\d.]+)', server
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
        content = self._get_homepage_content().lower()

        checks = [
            ('PHP', lambda: (
                'x-powered-by: php' in headers
                or 'phpsessid' in cookie_keys
                or re.search(r'\.php[\s\?"\'/>]', content) is not None
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
        content = self._get_homepage_content()

        # Config file mining — hanya jika content-type JSON
        for r in self.all_responses:
            if 'composer.json' in r['url'] and r['status'] == 200:
                ct = self._get_content_type(r)
                if 'json' not in ct and 'text/plain' not in ct:
                    # Bukan JSON asli, mungkin HTML fallback
                    if not r['content'].strip().startswith('{'):
                        continue
                try:
                    data = json.loads(r['content'])
                    if not isinstance(data, dict):
                        continue
                    c = r['content'].lower()
                    if '"laravel/framework"' in c:
                        frameworks.add('Laravel (Confirmed via Composer)')
                    if '"codeigniter' in c:
                        frameworks.add('CodeIgniter (Confirmed via Composer)')
                    if '"symfony/' in c:
                        frameworks.add('Symfony (Confirmed via Composer)')
                except (json.JSONDecodeError, AttributeError):
                    pass

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

        # Content-based detection (hanya dari homepage)
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
        """
        Deteksi Content Management System.

        Perbaikan akurasi:
        - API probing (wp-json, wp-login) memvalidasi isi konten, bukan hanya
          status code, untuk menghindari false positive dari SPA fallback
          atau Cloudflare custom error pages.
        - Content-based detection hanya dari homepage.
        """
        cms_list = set()
        homepage_content = self._get_homepage_content()

        # API probing dengan validasi konten
        for r in self.all_responses:
            # WordPress REST API: validasi bahwa response benar-benar JSON WordPress
            if 'wp-json' in r['url'] and r['status'] == 200:
                ct = self._get_content_type(r)
                content = r['content'].strip()

                # Harus JSON content-type DAN berisi WordPress REST API markers
                if 'json' in ct or content.startswith('{'):
                    try:
                        data = json.loads(content)
                        if isinstance(data, dict):
                            # WordPress REST API selalu punya key 'namespaces' atau 'routes'
                            wp_markers = ['namespaces', 'routes', 'authentication', 'name', 'description']
                            has_wp_keys = sum(1 for k in wp_markers if k in data) >= 2
                            # Juga cek apakah ada 'wp' namespace
                            namespaces = data.get('namespaces', [])
                            has_wp_namespace = any('wp' in str(ns) for ns in namespaces) if namespaces else False

                            if has_wp_keys and has_wp_namespace:
                                cms_list.add('WordPress (API Exposed)')
                    except (json.JSONDecodeError, AttributeError):
                        pass

                # Jika bukan JSON valid, cek apakah ini SPA fallback
                elif self._is_spa_fallback(r):
                    # SPA fallback — bukan WordPress
                    pass

            # WordPress Login: validasi bahwa response berisi form login WordPress
            if 'wp-login.php' in r['url'] and r['status'] == 200:
                content_lower = r['content'].lower()
                # WordPress login page memiliki marker spesifik
                wp_login_markers = [
                    'wp-login',
                    'wp-submit',
                    'user_login',
                    'user_pass',
                    'loginform',
                ]
                matches = sum(1 for m in wp_login_markers if m in content_lower)
                if matches >= 3:
                    cms_list.add('WordPress')
                elif self._is_spa_fallback(r):
                    pass

        # Content-based CMS detection — hanya dari homepage content
        signatures = [
            ('WordPress', r'wp-content/(?:themes|plugins)|wp-includes/js/', [
                # Extra validation: harus ada beberapa marker, bukan cuma satu
            ]),
            ('Joomla', r'content="Joomla!|/media/jui/', []),
            ('Drupal', r'Drupal\.settings|sites/all/modules|drupal\.js', []),
            ('OpenCart', r'catalog/view/theme', []),
            ('PrestaShop', r'prestashop|/themes/default-bootstrap/', []),
            ('Wix', r'wix-site|static\.wixstatic\.com', []),
            ('Shopify', r'cdn\.shopify\.com|shopify\.com/s/', []),
            ('Squarespace', r'squarespace\.com|static1\.squarespace', []),
            ('Ghost', r'ghost-(?:url|version)|content/themes/.*ghost', []),
            ('Moodle', r'moodle|/theme/boost/', []),
        ]

        for name, pattern, _extra in signatures:
            if re.search(pattern, homepage_content, re.IGNORECASE):
                if name == 'WordPress':
                    # WordPress perlu multiple indicators dari homepage
                    wp_indicators = 0
                    if re.search(r'wp-content/', homepage_content, re.IGNORECASE):
                        wp_indicators += 1
                    if re.search(r'wp-includes/', homepage_content, re.IGNORECASE):
                        wp_indicators += 1
                    if re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress', homepage_content, re.IGNORECASE):
                        wp_indicators += 2  # Strong signal
                    if re.search(r'wp-emoji', homepage_content, re.IGNORECASE):
                        wp_indicators += 1

                    if wp_indicators >= 2:
                        ver = self._extract_version(
                            r'content="WordPress ([\d.]+)"', homepage_content
                        )
                        cms_list.add(f"WordPress {ver}" if ver else "WordPress")
                else:
                    cms_list.add(name)

        return list(cms_list)

    def _detect_frontend_framework(self) -> List[str]:
        """Deteksi frontend framework dari konten HTML/JS."""
        fw = set()
        content = self._get_homepage_content()

        patterns = {
            'React':      r'react[\.\-][\d\.]+|react-dom|_reactRootContainer|__react',
            'Vue.js':     r'vue[\.\-][\d\.]+\.js|data-v-[a-f0-9]|__vue_app__|/assets/index.*\.js.*type=["\']module["\']',
            'Angular':    r'angular[\.\-][\d\.]+\.js|ng-version|ng-app|zone\.js',
            'Svelte':     r'svelte|__svelte',
            'Next.js':    r'/_next/static|__NEXT_DATA__',
            'Nuxt.js':    r'/_nuxt/|__NUXT__',
            'Vite App':   r'<script\s+type=["\']module["\']\s+.*?/assets/.*\.js|/@vite/client',
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

    def _detect_build_tools(self) -> List[str]:
        """Deteksi build tools / bundlers dari konten homepage."""
        tools = set()
        content = self._get_homepage_content()
        title = ''
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()

        # Vite: script type=module dengan /assets/ pattern, atau title "Vite App"
        if re.search(r'/@vite/client', content):
            tools.add('Vite (Dev Mode)')
        elif re.search(r'<script\s+type=["\']module["\']\s+.*?/assets/index[\w.-]*\.js', content):
            tools.add('Vite')
        elif title.lower() == 'vite app':
            tools.add('Vite')

        # Webpack
        if re.search(r'webpackJsonp|webpack|__webpack_require__|/static/js/main\.\w+\.js', content):
            tools.add('Webpack')

        # Parcel
        if re.search(r'/parcel|parcelRequire', content):
            tools.add('Parcel')

        # Turbopack
        if re.search(r'turbopack', content, re.IGNORECASE):
            tools.add('Turbopack')

        return list(tools)

    def _detect_js_libs(self) -> List[str]:
        """Deteksi library JavaScript dari package.json dan konten."""
        libs = set()
        content = self._get_homepage_content()

        # Config file mining — hanya jika benar-benar JSON
        for r in self.all_responses:
            if 'package.json' in r['url'] and r['status'] == 200:
                ct = self._get_content_type(r)
                content_stripped = r['content'].strip()

                # Validasi bahwa ini benar-benar JSON, bukan HTML fallback
                if not ('json' in ct or content_stripped.startswith('{')):
                    continue
                if self._is_spa_fallback(r):
                    continue

                try:
                    data = json.loads(content_stripped)
                    if not isinstance(data, dict):
                        continue
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

        # Regex fallback dari homepage content
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
        content = self._get_homepage_content()

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
        """Deteksi meta generator tag dari HTML homepage."""
        content = self._get_homepage_content()
        pattern = r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']'
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1)
        # Cek juga format terbalik (content sebelum name)
        pattern2 = r'<meta\s+content=["\']([^"\']+)["\']\s+name=["\']generator["\']'
        match2 = re.search(pattern2, content, re.IGNORECASE)
        return match2.group(1) if match2 else None

    def _detect_cdn(self) -> List[str]:
        """Deteksi CDN/Cloud dari header dan konten."""
        cdns = set()
        headers = self._get_combined_headers().lower()
        content = self._get_homepage_content().lower()

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
        content = self._get_homepage_content()
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
        content = self._get_homepage_content().lower()
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