import requests
from urllib.parse import urlparse

class SubdomainModule:
    def __init__(self, target):
        self.parsed = urlparse(target if '://' in target else 'http://' + target)
        # Ambil domain utama saja (misal: google.com)
        self.domain = self.parsed.netloc.replace("www.", "")
        self.protocol = self.parsed.scheme

    def run(self):
        found_subdomains = []
        # Wordlist kecil untuk demo cepat
        sub_list = ['www', 'admin', 'dev', 'test', 'api', 'mail', 'blog']

        for sub in sub_list:
            url = f"{self.protocol}://{sub}.{self.domain}"
            try:
                # Timeout super cepat (1 detik) biar demo sat-set
                requests.get(url, timeout=1)
                found_subdomains.append(url)
            except:
                continue
        
        return found_subdomains