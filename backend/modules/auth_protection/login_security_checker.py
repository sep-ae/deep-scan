import re
import time
import requests
import urllib3
from typing import Dict, Any, Optional, Tuple, List
from urllib.parse import urljoin, unquote, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept':          'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection':      'keep-alive',
}

WEAK_PASSWORDS = [
    '123456', '12345678', '123456789', '12345', '111111', '000000',
    'password', 'password123', 'admin', 'admin123', 'root', 'user',
    'qwerty', 'welcome', 'login', 'pass', 'guest',
    '2023', '2024', '2025', '2026'
]

DEFAULT_CREDENTIALS = [
    ('superadmin@gmail.com', 'djakarta321'),
    ('septito2k21@gmail.com', 'DeepScan@2026!'),
    ('septito2k21@gmail.com', '12345678'),
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', '123456'),
    ('administrator', 'password'),
    ('root', 'root'),
    ('root', 'toor'),
    ('user', 'user'),
    ('user', '123456'),
    ('test', 'test'),
    ('guest', 'guest'),
    ('admin@example.com', 'password'),
    ('admin@test.com', '123456'),
]

# Login paths di base domain
LOGIN_PATHS = [
    '/login', '/signin', '/auth/login',
    '/admin/login', '/user/login',
    '/accounts/login/',
    '/users/sign_in',
    '/auth/local',
    '/wp-login.php',
    '/administrator',
    '/api/auth/login', '/api/login', '/api/v1/auth/login',
    '/api/auth/signin', '/api/v1/login', '/api/user/login',
]

# Prefix subdomain admin yang umum
ADMIN_SUBDOMAIN_PREFIXES = [
    'admin', 'panel', 'cp', 'dashboard',
    'manage', 'cms', 'backend', 'app',
    'portal', 'staff', 'office', 'console',
    'secure', 'my', 'account', 'accounts',
]

# Login paths khusus di admin subdomain
ADMIN_LOGIN_PATHS = [
    '/login', '/signin', '/auth/login',
    '/wp-login.php',
    '/administrator',
    '/auth/local',
]

WARMUP_PATHS = {
    'universal':  ['/', '/login'],
    'sanctum':    ['/sanctum/csrf-cookie'],
    'django':     ['/accounts/login/'],
    'rails':      ['/users/sign_in'],
    'wordpress':  ['/wp-login.php'],
    'joomla':     ['/administrator'],
}

CSRF_COOKIE_MAP = {
    'XSRF-TOKEN':  ('X-XSRF-TOKEN', True),
    'csrftoken':   ('X-CSRFToken',   False),
    'csrf_token':  ('X-CSRF-Token',  False),
    '_csrf':       ('X-CSRF-Token',  False),
    'CSRF-TOKEN':  ('X-CSRF-TOKEN',  False),
}


class LoginSecurityChecker:
    def __init__(self, url: str, timeout: float = 10.0):
        self.url             = url if url.startswith('http') else f'https://{url}'
        self.base_url        = self.url.rstrip('/')
        self.timeout         = timeout
        self.session         = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify  = False
        self._detected_stack = 'unknown'
        self._login_endpoint = None
        self._login_method   = None
        self._field_names    = {'user': 'email', 'pass': 'password'}
        self._active_base    = self.base_url 


    def run(self) -> Dict[str, Any]:
        results = {
            'login_endpoint':           None,
            'method_detected':          None,
            'csrf_protection':          False,
            'captcha_detected':         False,
            'weak_password_allowed':    False,
            'default_creds_allowed':    False,
            'account_lockout_detected': False,
            'findings':                 [],
            'error':                    None
        }

        try:
            print(f"    [*] Menganalisa Login Security pada {self.base_url} ...")

            self._warm_up_session()
            print(f"    [*] Stack terdeteksi  : {self._detected_stack}")
            print(f"    [*] Active base URL   : {self._active_base}")

            endpoint, method, field_names = self._discover_login_mechanism()

            if not endpoint:
                results['findings'].append("Gagal mendeteksi endpoint login yang valid.")
                return results

            self._login_endpoint = endpoint
            self._login_method   = method
            self._field_names    = field_names

            results['login_endpoint']  = endpoint
            results['method_detected'] = method

            token_data = self._get_fresh_token()
            results['csrf_protection'] = bool(token_data)

            if token_data:
                results['findings'].append(
                    f"CSRF Token ditemukan ({token_data.get('type')}: {token_data.get('name')})."
                )
            else:
                results['findings'].append("PERINGATAN: Tidak ada CSRF Token.")

            # ── Weak Password — Session 1 ──
            print("    [>] Menguji Weak Password...")
            for i, pwd in enumerate(WEAK_PASSWORDS[:6]):
                success, lockout, msg = self._attempt_login(
                    endpoint, method, 'admin@example.com', pwd, field_names
                )
                if lockout:
                    results['account_lockout_detected'] = True
                    results['findings'].append(
                        f"Rate Limit/Lockout aktif setelah percobaan ke-{i+1}: {msg}"
                    )
                    break
                if success:
                    results['weak_password_allowed'] = True
                    results['findings'].append(
                        f"BAHAYA: Login berhasil dengan password lemah: admin@example.com:{pwd}"
                    )
                    break
                time.sleep(0.5)

            # ── Reset session sebelum default creds ──
            print("    [>] Reset session untuk Default Credentials...")
            time.sleep(2)
            self._reset_session()

            # ── Default Credentials — Session 2 (Fresh) ──
            print("    [>] Menguji Default Credentials...")
            for user, pwd in DEFAULT_CREDENTIALS:
                success, lockout, msg = self._attempt_login(
                    endpoint, method, user, pwd, field_names
                )
                if lockout:
                    if not results['account_lockout_detected']:
                        results['account_lockout_detected'] = True
                        results['findings'].append(
                            f"Rate Limit/Lockout aktif pada Default Creds: {msg}"
                        )
                    break
                if success:
                    results['default_creds_allowed'] = True
                    results['findings'].append(
                        f"BAHAYA: Credential default valid: {user}:{pwd}"
                    )
                    break
                time.sleep(0.8)

            if not results['account_lockout_detected']:
                results['findings'].append(
                    "Tidak terdeteksi Account Lockout setelah percobaan gagal."
                )

        except Exception as e:
            results['error'] = str(e)

        return results

 
    def _discover_admin_subdomain(self) -> Optional[str]:
        """
        Detect admin panel di subdomain berbeda.
        Contoh: inicompany.my.id → admin.inicompany.my.id/login
        Return: base URL subdomain kalau ketemu, None kalau tidak.
        """
        parsed   = urlparse(self.base_url)
        hostname = parsed.hostname
        scheme   = parsed.scheme

        # Kalau sudah subdomain (admin.xxx.my.id), skip — cegah infinite detect
        parts = hostname.split('.')
        if len(parts) > 2:
            # Kalau sudah 3 level (admin.domain.tld), tidak perlu cari lagi
            return None

        print(f"    [*] Mencari admin subdomain untuk {hostname}...")

        for prefix in ADMIN_SUBDOMAIN_PREFIXES:
            candidate_base = f"{scheme}://{prefix}.{hostname}"
            for path in ADMIN_LOGIN_PATHS:
                try:
                    r = self.session.get(
                        f"{candidate_base}{path}",
                        timeout=5,
                        allow_redirects=False,
                        verify=False
                    )
                    if r.status_code == 200:
                        print(f"    [+] Admin panel ditemukan: {candidate_base}{path}")
                        # Warm-up session ke subdomain ini
                        self._warmup_subdomain(candidate_base)
                        return candidate_base
                    # 302 redirect ke /login juga valid (sudah ada panel-nya)
                    if r.status_code == 302:
                        loc = r.headers.get('Location', '')
                        if 'login' in loc.lower() or prefix in loc.lower():
                            print(f"    [+] Admin panel ditemukan (redirect): {candidate_base}")
                            self._warmup_subdomain(candidate_base)
                            return candidate_base
                except Exception:
                    pass

        print(f"    [-] Tidak ada admin subdomain ditemukan.")
        return None

    def _warmup_subdomain(self, subdomain_base: str):
        """Warm-up session ke admin subdomain untuk dapat cookies."""
        for path in ['/', '/login']:
            try:
                self.session.get(f"{subdomain_base}{path}", timeout=5, verify=False)
            except Exception:
                pass
        # Coba sanctum csrf-cookie di subdomain
        try:
            self.session.get(f"{subdomain_base}/sanctum/csrf-cookie", timeout=5, verify=False)
        except Exception:
            pass

    # ══════════════════════════════════════════
    # PRIVATE — Session Management
    # ══════════════════════════════════════════
    def _reset_session(self):
        """Buat session baru — hindari rate limit carry-over."""
        self.session.close()
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False

        # Warm-up ke active base (bisa subdomain)
        for path in ['/', '/login']:
            try:
                self.session.get(urljoin(self._active_base, path), timeout=5)
            except Exception:
                pass

        if 'laravel' in self._detected_stack.lower():
            try:
                self.session.get(
                    urljoin(self._active_base, '/sanctum/csrf-cookie'), timeout=5
                )
            except Exception:
                pass

    def _warm_up_session(self):
        # Universal warm-up ke base
        for path in WARMUP_PATHS['universal']:
            try:
                r = self.session.get(urljoin(self.base_url, path), timeout=5)
                self._detect_stack_from_response(r)
            except Exception:
                pass

        for path in WARMUP_PATHS['sanctum']:
            try:
                r = self.session.get(urljoin(self.base_url, path), timeout=5)
                if r.status_code == 200:
                    self._detected_stack = 'Laravel Sanctum/SPA'
            except Exception:
                pass

        for framework, paths in WARMUP_PATHS.items():
            if framework in ('universal', 'sanctum'):
                continue
            for path in paths:
                try:
                    r = self.session.get(urljoin(self.base_url, path), timeout=5)
                    if r.status_code == 200:
                        self._detect_stack_from_response(r)
                except Exception:
                    pass

        # ✅ Detect admin subdomain — update _active_base kalau ketemu
        admin_base = self._discover_admin_subdomain()
        if admin_base:
            self._active_base = admin_base
        # else: _active_base tetap base_url

    def _detect_stack_from_response(self, response):
        cookies = self.session.cookies.get_dict()
        headers = {k.lower(): v for k, v in response.headers.items()}
        body    = response.text.lower()[:2000]

        if 'XSRF-TOKEN' in cookies and self._detected_stack == 'unknown':
            self._detected_stack = 'Laravel/Vue SPA'
        elif 'csrftoken' in cookies:
            self._detected_stack = 'Django'
        elif 'ci_session' in cookies:
            self._detected_stack = 'CodeIgniter'
        elif 'wordpress_logged_in' in str(cookies):
            self._detected_stack = 'WordPress'

        server = headers.get('x-powered-by', '') + headers.get('server', '')
        if 'express' in server.lower():
            self._detected_stack = 'Node.js/Express'
        elif 'php' in server.lower() and self._detected_stack == 'unknown':
            self._detected_stack = 'PHP (Generic)'

        if 'csrfmiddlewaretoken' in body or 'django' in body:
            self._detected_stack = 'Django'
        elif 'authenticity_token' in body or 'rails' in body:
            self._detected_stack = 'Ruby on Rails'
        elif 'wp-login' in body or 'wordpress' in body:
            self._detected_stack = 'WordPress'
        elif 'joomla' in body:
            self._detected_stack = 'Joomla'
        elif 'strapi' in body:
            self._detected_stack = 'Strapi'
        elif ('laravel' in body or 'laravel_session' in str(cookies)) \
                and self._detected_stack == 'unknown':
            self._detected_stack = 'Laravel'

    # ══════════════════════════════════════════
    # PRIVATE — Token
    # ══════════════════════════════════════════
    def _get_fresh_token(self) -> Optional[Dict]:
        cookies = self.session.cookies.get_dict()

        for cookie_name, (header_name, needs_decode) in CSRF_COOKIE_MAP.items():
            if cookie_name in cookies:
                value = unquote(cookies[cookie_name]) if needs_decode else cookies[cookie_name]
                return {'type': 'header', 'name': header_name, 'value': value}

        # Scrape dari HTML — gunakan _active_base
        try:
            r    = self.session.get(
                f"{self._active_base}/login",
                timeout=5,
                headers={'Referer': self._active_base}
            )
            html = r.text

            patterns = [
                (r'name="(_token)"\s+value="([^"]+)"',                     'form', '_token'),
                (r'name="(csrfmiddlewaretoken)"\s+value="([^"]+)"',        'form', 'csrfmiddlewaretoken'),
                (r'name="(authenticity_token)"\s+value="([^"]+)"',         'form', 'authenticity_token'),
                (r'name="(__RequestVerificationToken)"\s+value="([^"]+)"', 'form', '__RequestVerificationToken'),
                (r'name="(_csrf)"\s+value="([^"]+)"',                      'form', '_csrf'),
                (r'name="(csrf_token)"\s+value="([^"]+)"',                 'form', 'csrf_token'),
                (r'"([a-f0-9]{32})":1',                                    'form', 'form_token'),
            ]
            for pattern, tok_type, name in patterns:
                match = re.search(pattern, html)
                if match:
                    val = match.group(2) if tok_type == 'form' else match.group(1)
                    return {'type': tok_type, 'name': name, 'value': val}

            match = re.search(
                r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)', html
            )
            if match:
                return {'type': 'header', 'name': 'X-CSRF-TOKEN', 'value': match.group(1)}

            for h in ['X-CSRF-Token', 'X-XSRF-TOKEN']:
                if h in r.headers:
                    return {'type': 'header', 'name': h, 'value': r.headers[h]}

        except Exception:
            pass

        return None

    def _build_request_headers(self, token_data: Optional[Dict] = None,
                                base: Optional[str] = None) -> Dict:
        """Build headers — Referer & Origin menyesuaikan active base."""
        active = base or self._active_base
        headers = {
            'Content-Type':     'application/json',
            'Accept':           'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'Referer':          f"{active}/login",
            'Origin':           active,
        }

        cookies = self.session.cookies.get_dict()
        for cookie_name, (header_name, needs_decode) in CSRF_COOKIE_MAP.items():
            if cookie_name in cookies:
                headers[header_name] = unquote(cookies[cookie_name]) if needs_decode \
                                       else cookies[cookie_name]
                break

        if token_data and token_data['type'] == 'header' \
                and token_data['name'] not in headers:
            headers[token_data['name']] = token_data['value']

        return headers

    # ══════════════════════════════════════════
    # PRIVATE — Discovery
    # ══════════════════════════════════════════
    def _discover_login_mechanism(self) -> Tuple[Optional[str], str, Dict]:
        """
        Coba semua kandidat login endpoint.
        Prioritas: _active_base (subdomain kalau ada) → base_url.
        """
        token_data = self._get_fresh_token()

        # Buat daftar base yang akan dicoba
        search_bases: List[str] = []
        if self._active_base != self.base_url:
            search_bases.append(self._active_base)  # subdomain duluan
        search_bases.append(self.base_url)

        for base in search_bases:
            paths = ADMIN_LOGIN_PATHS if base != self.base_url else LOGIN_PATHS

            for path in paths:
                url = f"{base.rstrip('/')}{path}"

                # ── JSON / SPA ──
                try:
                    headers = self._build_request_headers(token_data, base)
                    r = self.session.post(
                        url,
                        json={'email': 'probe@test.com', 'password': 'wrongpassword_probe123!'},
                        headers=headers,
                        timeout=5,
                        allow_redirects=False
                    )
                    is_json     = 'application/json' in r.headers.get('Content-Type', '')
                    valid_codes = r.status_code in [400, 401, 422, 429]

                    is_fortify = False
                    if r.status_code == 200 and is_json:
                        try:
                            if 'two_factor' in r.json():
                                is_fortify = True
                        except Exception:
                            pass

                    if valid_codes or is_fortify or (r.status_code == 200 and is_json):
                        fields = self._detect_field_names(r.text)
                        print(f"    [+] Endpoint JSON: {url} [{r.status_code}]")
                        # Update active base ke subdomain kalau endpoint ketemu di sana
                        self._active_base = base
                        return url, 'json', fields

                except Exception:
                    pass

                # ── Form POST ──
                try:
                    form_payload = {
                        'email':    'probe@test.com',
                        'password': 'wrongpassword_probe123!'
                    }
                    if token_data and token_data['type'] == 'form':
                        form_payload[token_data['name']] = token_data['value']

                    if 'wp-login' in path:
                        form_payload = {
                            'log':       'probe',
                            'pwd':       'wrongpassword_probe123!',
                            'wp-submit': 'Log+In',
                        }

                    r = self.session.post(
                        url, data=form_payload,
                        headers={
                            'Referer':      f"{base}/login",
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Accept':       'text/html,application/xhtml+xml',
                        },
                        timeout=5,
                        allow_redirects=False
                    )
                    if r.status_code in [302, 401, 422]:
                        fields = self._detect_field_names_form(path)
                        print(f"    [+] Endpoint Form: {url} [{r.status_code}]")
                        self._active_base = base
                        return url, 'form', fields

                except Exception:
                    pass

        return None, 'unknown', {'user': 'email', 'pass': 'password'}

    def _detect_field_names(self, response_text: str) -> Dict:
        fields     = {'user': 'email', 'pass': 'password'}
        text_lower = response_text.lower()

        if '"username"' in text_lower:
            fields['user'] = 'username'
        elif '"identifier"' in text_lower:
            fields['user'] = 'identifier'
        elif '"phone"' in text_lower or '"mobile"' in text_lower:
            fields['user'] = 'phone'
        elif '"login"' in text_lower and '"email"' not in text_lower:
            fields['user'] = 'login'

        return fields

    def _detect_field_names_form(self, path: str) -> Dict:
        if 'wp-login' in path:
            return {'user': 'log', 'pass': 'pwd'}
        if 'sign_in' in path:
            return {'user': 'user[email]', 'pass': 'user[password]'}
        if 'administrator' in path:
            return {'user': 'username', 'pass': 'passwd'}
        return {'user': 'email', 'pass': 'password'}

    # ══════════════════════════════════════════
    # PRIVATE — Attempt Login
    # ══════════════════════════════════════════
    def _attempt_login(
        self, url: str, method: str,
        user: str, pwd: str, fields: Dict
    ) -> Tuple[bool, bool, str]:
        try:
            token_data = self._get_fresh_token()
            payload    = {fields['user']: user, fields['pass']: pwd}

            if method == 'json':
                headers = self._build_request_headers(token_data)
                r = self.session.post(
                    url, json=payload, headers=headers,
                    timeout=5, allow_redirects=False
                )
            else:
                if token_data and token_data['type'] == 'form':
                    payload[token_data['name']] = token_data['value']
                r = self.session.post(
                    url, data=payload,
                    headers={
                        'Referer':      f"{self._active_base}/login",
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Accept':       'text/html,application/xhtml+xml',
                    },
                    timeout=5, allow_redirects=False
                )

            status     = r.status_code
            text_lower = r.text.lower()

            if status == 429:
                return False, True, "HTTP 429 Too Many Requests"

            if any(k in text_lower for k in [
                'too many attempts', 'too many login', 'throttle',
                'locked out', 'try again later', 'account locked',
                'temporarily blocked', 'account suspended',
                'terlalu banyak', 'coba lagi'
            ]):
                return False, True, "Lockout Message Detected"

            if status == 302:
                location   = r.headers.get('Location', '').lower()
                fail_kw    = ['login', 'signin', 'sign_in', 'error', 'failed', 'invalid']
                success_kw = ['dashboard', 'home', 'admin', 'profile', 'welcome', 'app', 'wp-admin']
                if any(k in location for k in success_kw) and \
                   not any(k in location for k in fail_kw):
                    return True, False, f"Redirect → {location}"
                return False, False, "Redirect kembali ke login"

            if status == 200 and method == 'json':
                try:
                    data = r.json()

                    if 'two_factor' in data:
                        return True, False, "Laravel Fortify Login Success"
                    if any(k in data for k in ['token', 'access_token', 'bearer', 'jwt', 'id_token']):
                        return True, False, "Auth Token Received"
                    if 'user' in data and isinstance(data.get('user'), dict):
                        return True, False, "User Object Received"
                    if isinstance(data.get('data'), dict) and 'user' in data['data']:
                        return True, False, "Nested User Object"
                    if 'jwt' in data and 'user' in data:
                        return True, False, "Strapi JWT Login Success"
                    if data.get('success') is True:
                        return True, False, "JSON success: true"
                    if str(data.get('status', '')).lower() in ['success', 'ok', '200']:
                        return True, False, "JSON status: success"
                    if any(k in text_lower for k in [
                        'login successful', 'berhasil login', 'login berhasil'
                    ]):
                        return True, False, "Success Message"

                    if data.get('success') is False:
                        return False, False, "JSON success: false"
                    if str(data.get('status', '')).lower() in ['error', 'fail', 'failed']:
                        return False, False, "JSON status: error"
                    if any(k in text_lower for k in [
                        'invalid credential', 'wrong password',
                        'email or password', 'incorrect', 'these credentials'
                    ]):
                        return False, False, "Invalid Credentials Message"

                except Exception:
                    pass

            if status == 419:
                print(f"    [!] 419 CSRF mismatch untuk {user}")
                return False, False, "419 CSRF Mismatch"
            if status == 401:
                return False, False, "401 Unauthorized"
            if status == 403:
                return False, False, "403 Forbidden"

            return False, False, f"Login Failed [{status}]"

        except requests.exceptions.Timeout:
            return False, False, "Request Timeout"
        except Exception as e:
            return False, False, str(e)