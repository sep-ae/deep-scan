import time
from .security_headers import analyze_security_headers
from .cors_checker     import check_cors_misconfig

__all__ = [
    'analyze_security_headers',
    'check_cors_misconfig',
    'run_http_security_checks',
]


def run_http_security_checks(url: str) -> dict:
    results = {}

    print("  [>] Security Headers Analysis...")
    results['security_headers'] = analyze_security_headers(url)
    time.sleep(0.5)

    print("  [>] CORS Misconfiguration Check...")
    results['cors'] = check_cors_misconfig(url)

    return results