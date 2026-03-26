import requests
import re
import urllib3
import concurrent.futures
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urljoin, unquote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection':      'keep-alive',
    'X-Requested-With':'XMLHttpRequest'
}

TOKEN_PATTERNS = {
    'Laravel/PHP':  r'name="_token" value="([^"]+)"',
    'ASP.NET':      r'name="__RequestVerificationToken" value="([^"]+)"',
    'Django/Py':    r'name="csrfmiddlewaretoken" value="([^"]+)"',
    'Rails/Ruby':   r'name="authenticity_token" value="([^"]+)"',
    'Java Spring':  r'name="_csrf" value="([^"]+)"',
    'Meta Tag':     r'name="csrf-token" content="([^"]+)"'
}

FORM_FIELD_MAP = {
    'ASP.NET':    '__RequestVerificationToken',
    'Rails/Ruby': 'authenticity_token',
    'Laravel/PHP':'_token',
}


class RateLimitChecker:
    def __init__(self, url: str, timeout: float = 10.0):
        self.url         = url if url.startswith('http') else f'https://{url}'
        self.base_url    = self.url.rstrip('/')
        self.timeout     = timeout
        self.concurrency = 6
        self.max_requests= 30
        self.session     = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False

    def run(self) -> Dict[str, Any]:
        results = {
            'rate_limit_detected':   False,
            'login_endpoint':        None,
            'endpoint_type':         None,
            'requests_before_limit': None,
            'evidence':              [],
            'error':                 None
        }

        try:
            print(f"    [*] Inisialisasi Session & Cookie ke {self.base_url} ...")
            endpoint, token_data, tech = self._profile_target()

            results['login_endpoint'] = endpoint
            results['endpoint_type']  = tech

            if token_data:
                results['evidence'].append(f"XSRF-TOKEN Cookie ditemukan & dipasang di Header.")
            else:
                results['evidence'].append(f"Tidak ada CSRF Token ({tech}).")

            print(f"    [>] Memulai serangan Blind-Cookie ke {endpoint} ...")
            is_limited, count = self._flood_universal(endpoint, token_data)

            if is_limited:
                results['rate_limit_detected']   = True
                results['requests_before_limit'] = count
                results['evidence'].append(f"SUCCESS: Rate Limit (429) tembus setelah {count} requests.")
            else:
                results['evidence'].append(f"Tidak ada rate limiting setelah {count} requests.")

        except Exception as e:
            results['error'] = str(e)

        return results

    def _profile_target(self) -> Tuple[str, Optional[Dict], str]:
        login_url      = urljoin(self.base_url + '/', 'login')
        token_info     = {}
        detected_tech  = "Generic API/Modern Stack"

        try:
            r    = self.session.get(login_url, timeout=5)
            html = r.text
            cookies = self.session.cookies.get_dict()

            if 'XSRF-TOKEN' in cookies:
                return login_url, {
                    'header_name': 'X-XSRF-TOKEN',
                    'value':       unquote(cookies['XSRF-TOKEN'])
                }, "Laravel/Vue (Cookie)"

            if 'csrftoken' in cookies:
                return login_url, {
                    'header_name': 'X-CSRFToken',
                    'value':       cookies['csrftoken'],
                    'form_name':   'csrfmiddlewaretoken'
                }, "Django (Python)"

            for tech, pattern in TOKEN_PATTERNS.items():
                match = re.search(pattern, html)
                if match:
                    token_info['value'] = match.group(1)
                    if tech in FORM_FIELD_MAP:
                        token_info['form_name'] = FORM_FIELD_MAP[tech]
                    return login_url, token_info, tech

        except Exception:
            pass

        return login_url, None, detected_tech

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update(HEADERS)
        s.verify = False
        for cookie in self.session.cookies:
            s.cookies.set(cookie.name, cookie.value)
        return s

    def _flood_worker(self, url: str, token_data: Optional[Dict]) -> int:
        s = self._make_session()
        try:
            payload = {'email': 'flood@test.com', 'password': 'wrong'}

            if token_data and 'header_name' in token_data:
                r = s.post(
                    url, json=payload,
                    headers={
                        token_data['header_name']: token_data['value'],
                        'Content-Type': 'application/json'
                    },
                    allow_redirects=False, timeout=5
                )
            elif token_data and 'form_name' in token_data:
                payload[token_data['form_name']] = token_data['value']
                r = s.post(url, data=payload, allow_redirects=False, timeout=5)
            else:
                r = s.post(url, json=payload, allow_redirects=False, timeout=5)

            return r.status_code
        except Exception:
            return 0

    def _flood_universal(self, url: str, token_data: Optional[Dict]) -> Tuple[bool, int]:
        count    = 0
        detected = False

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {
                executor.submit(self._flood_worker, url, token_data): i
                for i in range(self.max_requests)
            }

            for future in concurrent.futures.as_completed(futures):
                count += 1
                try:
                    status = future.result()
                    if status == 429:
                        detected = True
                        executor.shutdown(wait=False)
                        break
                    if status == 403 and count == 1:
                        print("    [!] 403 Forbidden — CSRF token mungkin tidak valid.")
                except Exception:
                    pass

        return detected, count
