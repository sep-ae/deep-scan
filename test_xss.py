import sys
import urllib.parse
sys.path.append(r'd:\Tugas Akhir\deep-scan\backend')
from modules.web_vulnerabilities.xss import XSSChecker

checker = XSSChecker('https://api.septito.my.id/api')
payload = '<script>alert("DEEPSCANXSS7x9z")</script>'
p = urllib.parse.quote(payload)
r = checker._client.get('https://api.septito.my.id/api/posts/preview?text=' + p)

if r:
    print('Response text:', r.text[:200])
    print('_is_reflected returns:', checker._is_reflected(r.text, payload, r.headers.get('Content-Type')))
