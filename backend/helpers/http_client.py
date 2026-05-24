import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Dict, Optional, Any


class SafeResponse:
    def __init__(self, error: str = ""):
        self.ok = False
        self.status_code = 0
        self.text = ""
        self.content = b""
        self.headers = {}
        self.url = ""
        self.error = error

    def json(self) -> Any:
        return {}

    def __bool__(self):
        return False


class HostDeadException(Exception):
    """Exception khusus jika target terdeteksi mati atau DNS gagal di tengah jalan."""
    pass

class HttpClient:
    def __init__(
        self,
        timeout: int = 8,
        cookies: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        verify: bool = False,
        retries: int = 2,
        backoff_factor: float = 0.3,
        proxy: Optional[str] = None,
        allow_redirects: bool = True,
        pool_size: int = 50,  # fix: default pool besar untuk scanning paralel
    ):
        self.timeout = timeout
        self.verify = verify
        self.allow_redirects = allow_redirects
        self.session = requests.Session()
        
        # Tambahan pengaman untuk Dynamic Abort
        self.consecutive_errors = 0
        self.max_consecutive_errors = 3

        retry = Retry(
            total=retries,
            connect=retries,
            read=retries,
            status=retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 502, 503, 504],
            allowed_methods=frozenset([
                "HEAD", "GET", "POST", "PUT",
                "DELETE", "OPTIONS", "PATCH"
            ]),
            raise_on_status=False,
        )

        # pool_connections=20: jumlah host berbeda yang bisa ditangani sekaligus
        # pool_maxsize=pool_size: max koneksi paralel per host (default 50)
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=20,
            pool_maxsize=pool_size,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.session.verify = verify
        self.session.headers.update(headers or {})
        self.session.cookies.update(cookies or {})

        self.proxies: Dict[str, str] = {}
        if proxy:
            self.proxies = {"http": proxy, "https": proxy}

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        kwargs.setdefault("allow_redirects", self.allow_redirects)
        if self.proxies and "proxies" not in kwargs:
            kwargs["proxies"] = self.proxies
        return self.session.request(method, url, **kwargs)

    def safe_request(self, method: str, url: str, **kwargs):
        if self.consecutive_errors >= self.max_consecutive_errors:
            raise HostDeadException(f"Target Unreachable/Tarpit: {self.max_consecutive_errors}x Error berturut-turut. Request dibatalkan.")
            
        try:
            res = self.request(method, url, **kwargs)
            self.consecutive_errors = 0  # Reset jika sukses
            return res
        except requests.exceptions.Timeout:
            self.consecutive_errors += 1
            return SafeResponse(error="timeout")
        except requests.exceptions.ConnectionError as e:
            self.consecutive_errors += 1
            return SafeResponse(error=f"connection_error: {e}")
        except requests.exceptions.RequestException as e:
            return SafeResponse(error=f"request_error: {e}")

    def get(self, url: str, **kwargs):
        return self.safe_request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.safe_request("POST", url, **kwargs)

    def put(self, url: str, **kwargs):
        return self.safe_request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs):
        return self.safe_request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs):
        return self.safe_request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs):
        return self.safe_request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs):
        return self.safe_request("OPTIONS", url, **kwargs)

    def get_json(self, url: str, **kwargs) -> Any:
        r = self.get(url, **kwargs)
        if r and r.ok:
            try:
                return r.json()
            except Exception:
                return {}
        return {}

    def post_json(self, url: str, json_body: Dict, **kwargs) -> Any:
        r = self.post(url, json=json_body, **kwargs)
        if r and r.ok:
            try:
                return r.json()
            except Exception:
                return {}
        return {}

    def set_cookies(self, cookies: Dict):
        self.session.cookies.update(cookies or {})

    def reset_cookies(self):
        self.session.cookies.clear()

    def set_headers(self, headers: Dict):
        self.session.headers.update(headers or {})

    def reset_headers(self):
        default_keys = list(self.session.headers.keys())
        for k in default_keys:
            if k.lower() not in ("user-agent", "accept-encoding", "accept", "connection"):
                del self.session.headers[k]

    def set_proxy(self, proxy: str):
        self.proxies = {"http": proxy, "https": proxy}

    def clear_proxy(self):
        self.proxies = {}

    def get_cookies(self) -> Dict:
        return dict(self.session.cookies)

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False