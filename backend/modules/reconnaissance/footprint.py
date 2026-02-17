import requests
import re
import time
import urllib3
import hashlib
import codecs
import json
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse

# Disable SSL warnings for scanning purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TechFingerprint:
    """
    Production-grade web technology fingerprinting (Enhanced).
    Fitur Baru:
    - Favicon Hash Detection (Bypass Cloudflare)
    - JSON Config Mining (package.json/composer.json parsing)
    - Deep Cookie Analysis
    """

    def __init__(self, url: str, timeout: float = 10.0, max_endpoints: int = 8):
        self.url = url if url.startswith('http') else f'https://{url}'
        self.timeout = timeout
        self.max_endpoints = max_endpoints
        self.all_responses: List[Dict[str, Any]] = []
        self.start_time = time.time()
        self.detected_versions: Dict[str, str] = {}
        # Session untuk performa & cookie tracking yg konsisten
        self.session = requests.Session()
        self.session.headers.update({
             'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
             'Accept': 'text/html,application/xhtml+xml,application/json,image/webp,*/*;q=0.8'
        })

    def run(self) -> Dict[str, Any]:
        """Eksekusi pemindaian stack teknologi."""
        print(f"[*] Scanning {self.url} ...")
        self._crawl_endpoints()
        
        if not self.all_responses:
            return {'error': 'No endpoints reachable'}

        # Urutan prioritas: Favicon (Paling Jujur) -> Config Files -> Header -> Cookie -> Content
        technologies = {
            'framework_signature': self._detect_favicon_framework(), # <--- FITUR BARU
            'server_os': self._detect_os(),
            'web_server': self._detect_web_server(),
            'language': self._detect_programming_language(),
            'backend_framework': self._detect_backend_framework(),
            'cms': self._detect_cms(),
            'frontend_framework': self._detect_frontend_framework(),
            'javascript_libs': self._detect_js_libs(),
            'css_frameworks': self._detect_css_frameworks(),
            'cdn': self._detect_cdn(),
            'security': self._detect_security(),
            'analytics': self._detect_analytics(),
            'meta_generator': self._detect_meta_generator()
        }
        
        # Bersihkan nilai kosong & gabungkan hasil
        clean_results = {k: v for k, v in technologies.items() if v}
        return clean_results

    # ================= CRAWLING ENGINE =================

    def _crawl_endpoints(self) -> None:
        """Crawling cerdas pada endpoint umum."""
        base_url = self.url.rstrip('/')
        # Ditambahkan favicon.ico untuk hashing
        endpoints = [
            '',               
            '/favicon.ico',   # PENTING: Untuk bypass Cloudflare
            '/admin',         
            '/login',         
            '/robots.txt',    
            '/sitemap.xml',
            '/wp-json/',      
            '/composer.json', # PHP Config
            '/package.json'   # JS Config
        ]
        
        for path in endpoints[:self.max_endpoints]:
            target_url = f"{base_url}{path}"
            try:
                # Stream=True untuk favicon agar tidak berat
                resp = self.session.get(target_url, timeout=self.timeout, verify=False, allow_redirects=True)
                
                # Simpan respons
                content_text = ""
                try:
                    content_text = resp.text[:100000] # Scan 100kb pertama
                except:
                    pass # Ignore binary content decoding errors

                self.all_responses.append({
                    'url': target_url,
                    'path': path,
                    'status': resp.status_code,
                    'headers': {k.lower(): v for k, v in resp.headers.items()},
                    'content': content_text,
                    'raw_content': resp.content, # Simpan raw untuk hashing gambar
                    'cookies': resp.cookies.get_dict()
                })
            except Exception:
                pass

    # ================= HELPERS =================

    def _get_combined_content(self) -> str:
        return '\n'.join([r['content'] for r in self.all_responses])

    def _get_combined_headers(self) -> str:
        return '\n'.join([str(r['headers']) for r in self.all_responses])

    def _get_all_cookies(self) -> Dict[str, str]:
        cookies = {}
        for r in self.all_responses:
            cookies.update(r['cookies'])
        return cookies

    def _extract_version(self, pattern: str, text: str) -> Optional[str]:
        match = re.search(pattern, text, re.IGNORECASE)
        if match and match.groups():
            return match.group(1)
        return None

    # ================= DETECTION MODULES (ENHANCED) =================

    def _detect_favicon_framework(self) -> Optional[str]:
        """
        [NEW] Menghitung Hash MD5 dari favicon.ico.
        Sangat efektif mendeteksi Laravel/Spring/React dibalik Cloudflare.
        """
        for r in self.all_responses:
            if 'favicon.ico' in r['url'] and r['status'] == 200:
                try:
                    # Hitung MD5 Hash
                    md5_hash = hashlib.md5(r['raw_content']).hexdigest()
                    
                    # Database Signature (Bisa diperbanyak)
                    signatures = {
                        '69c728902a9f997cb956c36798a28796': 'Laravel Default',
                        '050519992d9d924151b6982f6e91f692': 'Spring Boot',
                        '88081f2150495f327e573715694a1131': 'React App',
                        'e3ee45445209c15858604928b577005c': 'Vue.js App',
                        '20e8b153b6f937d53243f7736f875323': 'Angular',
                        'f3415a6e29783f9828236780360a0494': 'Docker Container'
                    }
                    if md5_hash in signatures:
                        return signatures[md5_hash]
                except:
                    pass
        return None

    def _detect_web_server(self) -> Optional[str]:
        server = self._detect_server_header_helper(['server', 'x-powered-by'])
        if not server: return None
        
        known_servers = ['nginx', 'apache', 'cloudflare', 'litespeed', 'microsoft-iis', 'gws']
        for s in known_servers:
            if s in server.lower():
                version = self._extract_version(rf'{s}/([\d.]+)', server)
                return f"{s.title()} {version}" if version else s.title()
        return server
    
    def _detect_server_header_helper(self, keys: List[str]) -> Optional[str]:
        for r in self.all_responses:
            for key in keys:
                val = r['headers'].get(key)
                if val: return val
        return None

    def _detect_os(self) -> Optional[str]:
        headers = self._get_combined_headers().lower()
        if 'ubuntu' in headers: return 'Ubuntu'
        if 'debian' in headers: return 'Debian'
        if 'centos' in headers: return 'CentOS'
        if 'windows' in headers or 'asp.net' in headers: return 'Windows Server'
        return None

    def _detect_programming_language(self) -> List[str]:
        langs = set()
        headers = self._get_combined_headers().lower()
        cookies = self._get_all_cookies().keys()
        content = self._get_combined_content()

        if 'php' in headers or 'phpsessid' in [c.lower() for c in cookies] or '.php' in content:
            langs.add('PHP')
        if 'asp.net' in headers or 'asp.net_sessionid' in [c.lower() for c in cookies]:
            langs.add('ASP.NET')
        if 'jsessionid' in [c.lower() for c in cookies]:
            langs.add('Java')
        
        return list(langs)

    def _detect_backend_framework(self) -> List[str]:
        frameworks = set()
        cookies = self._get_all_cookies()
        headers = self._get_combined_headers().lower()
        content = self._get_combined_content()

        # 1. Active Config Mining (Jika composer.json terbuka)
        for r in self.all_responses:
            if 'composer.json' in r['url'] and r['status'] == 200:
                if '"laravel/framework"' in r['content']: frameworks.add('Laravel (Confirmed via Composer)')
                if '"codeigniter/framework"' in r['content']: frameworks.add('CodeIgniter (Confirmed via Composer)')

        # 2. Cookie Signatures (Expanded)
        cookie_signatures = {
            'laravel_session': 'Laravel',
            'XSRF-TOKEN': 'Laravel', # Sangat umum di Laravel
            'ci_session': 'CodeIgniter',
            'csrftoken': 'Django',
            '_rails_session': 'Ruby on Rails',
            'connect.sid': 'Node.js (Express)',
            'phoenix': 'Phoenix',
            'CraftSessionId': 'Craft CMS'
        }

        for cookie_name, framework in cookie_signatures.items():
            if any(cookie_name.lower() in c.lower() for c in cookies.keys()):
                frameworks.add(framework)

        # 3. Header/Body Fallback
        if 'x-content-type-options' in headers and 'XSRF-TOKEN' in cookies: frameworks.add('Laravel') # Kombinasi umum
        if 'whoops! there was an error' in content.lower(): frameworks.add('Laravel (Debug Mode)')
        
        return list(frameworks)

    def _detect_cms(self) -> List[str]:
        cms_list = set()
        content = self._get_combined_content()
        
        # 1. API Probing (WP-JSON)
        for r in self.all_responses:
            if 'wp-json' in r['url'] and r['status'] == 200:
                cms_list.add('WordPress (API Exposed)')

        # 2. Regex Pattern
        signatures = [
            ('WordPress', r'wp-content|wp-includes|/wp-json/'),
            ('Joomla', r'content="Joomla!'),
            ('Drupal', r'Drupal|sites/all/modules'),
            ('OpenCart', r'catalog/view/theme'),
            ('Wix', r'wix-site'),
            ('Shopify', r'shopify\.com')
        ]

        for name, pattern in signatures:
            if re.search(pattern, content, re.IGNORECASE):
                if name == 'WordPress':
                    ver = self._extract_version(r'content="WordPress ([\d.]+)"', content)
                    cms_list.add(f"WordPress {ver}" if ver else "WordPress")
                else:
                    cms_list.add(name)
        return list(cms_list)

    def _detect_frontend_framework(self) -> List[str]:
        fw = set()
        content = self._get_combined_content()

        patterns = {
            'React': r'(react[\.\-][\d\.]+|react-dom|_reactRootContainer)',
            'Vue.js': r'(vue[\.\-][\d\.]+\.js|data-v-)',
            'Angular': r'(angular[\.\-][\d\.]+\.js|ng-version|ng-app)',
            'Next.js': r'/_next/static|__NEXT_DATA__',
            'Nuxt.js': r'/_nuxt/|__NUXT__',
            'Livewire': r'livewire(?:\.js)?', # Laravel Livewire
            'Alpine.js': r'alpine(?:\.js)?|x-data='
        }

        for name, pattern in patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                fw.add(name)
        return list(fw)

    def _detect_js_libs(self) -> List[str]:
        libs = set()
        content = self._get_combined_content()

        # 1. Active Config Mining (Jika package.json terbuka)
        for r in self.all_responses:
            if 'package.json' in r['url'] and r['status'] == 200:
                try:
                    data = json.loads(r['content'])
                    deps = data.get('dependencies', {})
                    # Ambil library penting saja
                    targets = ['react', 'vue', 'axios', 'lodash', 'moment', 'bootstrap', 'tailwindcss']
                    for lib in deps:
                        if any(t in lib for t in targets):
                            libs.add(f"{lib} v{deps[lib]} (from package.json)")
                except:
                    pass

        # 2. Regex Fallback
        patterns = {
            'jQuery': r'jquery[.-]([\d.]+)',
            'Lodash': r'lodash[.-]([\d.]+)',
            'Axios': r'axios[.-]([\d.]+)',
            'Chart.js': r'chart[.-]([\d.]+)'
        }

        for name, regex in patterns.items():
            version = self._extract_version(regex, content)
            if version:
                libs.add(f"{name} v{version}")
        
        return list(libs)

    def _detect_css_frameworks(self) -> List[str]:
        css = set()
        content = self._get_combined_content()
        patterns = {
            'Bootstrap': (r'bootstrap(?:[\.-]([\d.]+))?\.css', 'Bootstrap'),
            'Tailwind': (r'tailwind', 'Tailwind CSS'),
            'Bulma': (r'bulma(?:[\.-]([\d.]+))?\.css', 'Bulma')
        }
        for key, (regex, name) in patterns.items():
            match = re.search(regex, content, re.IGNORECASE)
            if match:
                ver = match.group(1) if match.groups() else ""
                css.add(f"{name} {ver}".strip())
        return list(css)

    def _detect_meta_generator(self) -> Optional[str]:
        content = self._get_combined_content()
        pattern = r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']'
        match = re.search(pattern, content, re.IGNORECASE)
        return match.group(1) if match else None

    def _detect_cdn(self) -> List[str]:
        cdns = set()
        headers = self._get_combined_headers().lower()
        content = self._get_combined_content().lower()
        cdn_map = {
            'Cloudflare': ['cf-ray', '__cf_bm'],
            'Amazon Cloudfront': ['cloudfront', 'amz-cf-id'],
            'Google Cloud': ['storage.googleapis.com']
        }
        for name, markers in cdn_map.items():
            if any(m in headers or m in content for m in markers):
                cdns.add(name)
        return list(cdns)

    def _detect_security(self) -> List[str]:
        sec = []
        headers = self._get_combined_headers().lower()
        if 'cf-ray' in headers: sec.append('Cloudflare WAF')
        if 'content-security-policy' in headers: sec.append('CSP Enabled')
        return sec
    
    def _detect_analytics(self) -> List[str]:
        content = self._get_combined_content()
        analytics = set()
        if re.search(r'ua-\d+-\d+', content, re.IGNORECASE) or 'google-analytics.com' in content:
            analytics.add('Google Analytics')
        if re.search(r'G-[A-Z0-9]{5,}', content) or 'googletagmanager' in content:
            analytics.add('Google GA4 / GTM')
        return list(analytics)

# ================= MAIN EXECUTION =================
if __name__ == "__main__":
    import json
    
    target = "madiunkab.go.id" 
    
    print(f"--- Technology Fingerprinter v3.0 (Enhanced) ---")
    tf = TechFingerprint(target)
    result = tf.run()
    
    print(json.dumps(result, indent=4))