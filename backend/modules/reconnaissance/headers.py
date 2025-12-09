import requests

class HeaderScanModule:
    def __init__(self, target):
        self.target = target

    def run(self):
        issues = []
        try:
            response = requests.get(self.target, timeout=5)
            headers = response.headers

            # Daftar Header Wajib Aman
            security_headers = {
                'X-Frame-Options': 'Missing: Rentan Clickjacking',
                'X-Content-Type-Options': 'Missing: Rentan MIME Sniffing',
                'Strict-Transport-Security': 'Missing: HTTP tidak dipaksa ke HTTPS',
                'Content-Security-Policy': 'Missing: Rentan XSS parah'
            }

            for header, msg in security_headers.items():
                if header not in headers:
                    issues.append({"header": header, "risk": "Medium", "info": msg})

        except:
            pass
            
        return issues