import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

class PortScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP', 
            5432: 'PostgreSQL', 8080: 'HTTP-Alt'
        }
    
    def run(self, timeout=1, max_workers=20):
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
                        open_ports.append(result)
                except Exception:
                    pass
        
        return sorted(open_ports, key=lambda x: x['port'])
    
    def _scan_port(self, port, timeout):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            if result == 0:
                return {
                    'port': port,
                    'service': self.common_ports[port]
                }
        except Exception:
            pass
        return None
