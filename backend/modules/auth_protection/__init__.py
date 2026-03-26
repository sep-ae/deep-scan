import time
from .waf_detector import WAFDetector
from .rate_limit_checker import RateLimitChecker
from .login_security_checker import LoginSecurityChecker


def run_auth_protection_checks(url: str) -> dict:
    results = {}

    print("  [>] WAF Detection...")
    results['waf'] = WAFDetector(url).run()
    time.sleep(0.5)

    print("  [>] Rate Limit Check...")
    results['rate_limit'] = RateLimitChecker(url).run()
    time.sleep(0.5)

    print("  [>] Login Security Check...")
    results['login'] = LoginSecurityChecker(url).run()

    return results
