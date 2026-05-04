import socket
import logging
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Dict, List, FrozenSet

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logger = logging.getLogger(__name__)


COMMON_PORTS: Dict[int, str] = {
    20:    "FTP-Data",
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    587:   "SMTP-Sub",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    3000:  "Node.js",
    3306:  "MySQL",
    3389:  "RDP",
    5000:  "Flask",
    5432:  "PostgreSQL",
    6379:  "Redis",
    8000:  "HTTP-Alt",
    8080:  "HTTP-Proxy",
    8443:  "HTTPS-Alt",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch-Cluster",
    11211: "Memcached",
    27017: "MongoDB",
}

RISK_MARKING: Dict[int, str] = {
    21:    "PORT_FTP_EXPOSED",
    22:    "PORT_SSH_EXPOSED",
    23:    "PORT_TELNET_EXPOSED",
    25:    "PORT_SMTP_EXPOSED",
    53:    "PORT_DNS_EXPOSED",
    1433:  "PORT_DATABASE_EXPOSED",
    3306:  "PORT_DATABASE_EXPOSED",
    3389:  "PORT_RDP_EXPOSED",
    5432:  "PORT_DATABASE_EXPOSED",
    6379:  "PORT_DATABASE_EXPOSED",
    9200:  "PORT_ELASTICSEARCH_EXPOSED",
    9300:  "PORT_ELASTICSEARCH_EXPOSED",
    11211: "PORT_MEMCACHED_EXPOSED",
    27017: "PORT_DATABASE_EXPOSED",
}

HTTP_PORTS: FrozenSet[int] = frozenset({80, 443, 8000, 8080, 8443, 3000, 5000})
HTTPS_PORTS: FrozenSet[int] = frozenset({443, 8443})


@dataclass
class PortResult:
    port: int
    service: str
    banner: str
    vuln_key: Optional[str] = field(default=None)

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "service": self.service,
            "banner": self.banner,
            "vuln_key": self.vuln_key,
        }


class PortScanner:
    def __init__(
        self,
        target_ip: str,
        domain: Optional[str] = None,
        ports: Optional[Dict[int, str]] = None,
        risk_marking: Optional[Dict[int, str]] = None,
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.ports = ports or COMMON_PORTS
        self.risk_marking = risk_marking or RISK_MARKING

    def run(self, timeout: float = 2.0, max_workers: int = 20) -> List[dict]:
        """Scan semua port secara concurrent, return list dict port yang terbuka."""
        results: List[PortResult] = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._scan_port, port, timeout): port
                for port in self.ports
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result is not None:
                        results.append(result)
                except Exception as exc:
                    port = futures[future]
                    logger.debug("Error scanning port %d: %s", port, exc)

        return [r.to_dict() for r in sorted(results, key=lambda r: r.port)]

    def _scan_port(self, port: int, timeout: float) -> Optional[PortResult]:
        """Coba koneksi ke satu port, return PortResult jika terbuka."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((self.target_ip, port)) != 0:
                    return None

                service = self.ports.get(port, "Unknown")
                banner = self._grab_banner(sock, port, service)

                return PortResult(
                    port=port,
                    service=service,
                    banner=banner,
                    vuln_key=self.risk_marking.get(port),
                )
        except OSError as exc:
            logger.debug("OSError on port %d: %s", port, exc)
            return None

    def _grab_banner(self, sock: socket.socket, port: int, service: str) -> str:
        """Ambil banner dari port yang terbuka."""
        if port in HTTP_PORTS or "HTTP" in service:
            return self._grab_http_banner(port)
        return self._grab_raw_banner(sock)

    @staticmethod
    def _grab_raw_banner(sock: socket.socket) -> str:
        """Baca raw bytes dari socket yang sudah terkoneksi."""
        try:
            sock.settimeout(1.5)
            data = sock.recv(1024)
            if data:
                return data.decode("utf-8", errors="ignore").strip()
        except socket.timeout:
            pass
        except OSError as exc:
            logger.debug("Raw banner read failed: %s", exc)
        return "Open"

    def _grab_http_banner(self, port: int) -> str:
        """Kirim HTTP HEAD request untuk mendapatkan info server."""
        protocol = "https" if port in HTTPS_PORTS else "http"
        # Untuk HTTPS, gunakan domain (SNI) agar Cloudflare tidak reject
        host = self.domain if (self.domain and port in HTTPS_PORTS) else self.target_ip
        url = f"{protocol}://{host}:{port}"
        try:
            resp = requests.head(url, timeout=3, verify=False, allow_redirects=True)
            server = resp.headers.get("Server", "Web Server")
            return f"{server} (Status: {resp.status_code})"
        except requests.RequestException as exc:
            logger.debug("HTTP banner failed for %s: %s", url, exc)
            return "Web Server"