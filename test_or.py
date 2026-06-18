import sys
sys.path.append(r'd:\Tugas Akhir\deep-scan\backend')
from modules.web_vulnerabilities.open_redirect import OpenRedirectChecker

checker = OpenRedirectChecker('https://api.septito.my.id/api', max_paths=15)

def mock_get(base, path, param, payload, results):
    from urllib.parse import urlparse, quote
    if path.startswith(urlparse(base).path) and urlparse(base).path != '/':
        full_url = base.rstrip('/')[:-len(urlparse(base).path)] + '/' + path.lstrip('/')
    else:
        full_url = base.rstrip('/') + '/' + path.lstrip('/')
    test_url = f"{full_url}?{param}={quote(payload, safe=':/@%')}"
    if param == 'next' and payload.startswith('//'):
        print(test_url)
        try:
            r = checker._client_no_redirect.get(test_url, headers={'User-Agent': 'test'})
            if r and r.status_code in (301,302,303,307,308):
                print(r.headers.get('Location'))
                print(checker._is_external_redirect(r.headers.get('Location')))
        except Exception as e:
            print('Error:', e)
            
checker._test_get = mock_get
checker.run()
