import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

class FootprintModule:
    def __init__(self, target):
        self.target = target
        self.parsed = urlparse(target if '://' in target else 'http://' + target)
        self.hostname = self.parsed.netloc

    def run(self):
        result = {
            "ip": "Unknown",
            "server": "Unknown",
            "title": "Unknown",
            "tech": []
        }

        try:
            result['ip'] = socket.gethostbyname(self.hostname)
        except:
            result['ip'] = "DNS Error"

        try:
            response = requests.get(self.target, timeout=5)
            
            # Server Info
            if 'Server' in response.headers:
                result['server'] = response.headers['Server']
            if 'X-Powered-By' in response.headers:
                result['tech'].append(response.headers['X-Powered-By'])

            # HTML Analysis
            soup = BeautifulSoup(response.text, 'html.parser')
            if soup.title:
                result['title'] = soup.title.string.strip()
            
            meta_gen = soup.find('meta', attrs={'name': 'generator'})
            if meta_gen and meta_gen.get('content'):
                result['tech'].append(f"CMS: {meta_gen['content']}")

        except Exception as e:
            print(f"[-] Footprint Error: {e}")

        return result