import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class PortScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip

        self.RISK_MARKING = {
            21:    'PORT_FTP_EXPOSED',
            22:    'PORT_SSH_EXPOSED',
            23:    'PORT_TELNET_EXPOSED',
            25:    'PORT_SMTP_EXPOSED',
            53:    'PORT_DNS_EXPOSED',
            1433:  'PORT_DATABASE_EXPOSED',
            3306:  'PORT_DATABASE_EXPOSED',
            3389:  'PORT_RDP_EXPOSED',
            5432:  'PORT_DATABASE_EXPOSED',
            6379:  'PORT_DATABASE_EXPOSED',
            9200:  'PORT_ELASTICSEARCH_EXPOSED',
            9300:  'PORT_ELASTICSEARCH_EXPOSED',
            11211: 'PORT_MEMCACHED_EXPOSED',
            27017: 'PORT_DATABASE_EXPOSED',
        }

        self.common_ports = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 465: 'SMTPS', 587: 'SMTP-Sub', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL',
            3000: 'Node.js', 3306: 'MySQL', 3389: 'RDP', 5000: 'Flask',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8000: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
            9200: 'Elasticsearch',
            9300: 'Elasticsearch-Cluster',
            11211: 'Memcached',
            27017: 'MongoDB',
        }

    def run(self, timeout=2.0, max_workers=20):
        open_ports = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._scan_port, port, timeout): port
                for port in self.common_ports.keys()
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        result['vuln_key'] = self.RISK_MARKING.get(result['port'])
                        open_ports.append(result)
                except Exception:
                    pass

        return sorted(open_ports, key=lambda x: x['port'])

    def _scan_port(self, port, timeout):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target_ip, port))

            if result == 0:
                service_name = self.common_ports.get(port, 'Unknown')
                banner = self._grab_banner(sock, port, service_name)
                return {
                    'port': port,
                    'service': service_name,
                    'banner': banner
                }
        except Exception:
            pass
        finally:
            if sock: sock.close()
        return None

    def _grab_banner(self, sock, port, service_name):
        try:
            if port in [80, 443, 8080, 8443, 8000, 3000, 5000] or 'HTTP' in service_name:
                return self._grab_http_banner(port)

            sock.settimeout(1.5)
            try:
                data = sock.recv(1024)
                if data:
                    return data.decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                pass
            return "Open"
        except Exception:
            return "Open"

    def _grab_http_banner(self, port):
        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{self.target_ip}:{port}"
            resp = requests.head(url, timeout=3, verify=False)
            server = resp.headers.get('Server', 'Web Server')
            return f"{server} (Status: {resp.status_code})"
        except:
            return "Web Server"
