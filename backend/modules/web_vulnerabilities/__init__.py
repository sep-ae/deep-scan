import time
from .directory_listing import DirectoryListingChecker
from .open_redirect     import OpenRedirectChecker
from .sqli              import SQLInjectionChecker   
from .xss               import XSSChecker
from .command_injection import CommandInjectionChecker
from .file_upload       import FileUploadChecker

__all__ = [
    'DirectoryListingChecker',
    'OpenRedirectChecker',
    'SQLInjectionChecker',
    'XSSChecker',
    'CommandInjectionChecker',
    'FileUploadChecker',
    'run_web_vulnerability_checks',
]


def run_web_vulnerability_checks(url: str, scope_mode: str = 'wildcard') -> dict:
    results = {}

    print("  [>] Directory Listing Check...")
    results['directory_listing'] = DirectoryListingChecker(url, scope_mode=scope_mode).run()
    time.sleep(0.5)

    print("  [>] Open Redirect Check...")
    results['open_redirect'] = OpenRedirectChecker(url, scope_mode=scope_mode).run()
    time.sleep(0.5)

    print("  [>] SQL Injection Check...")
    results['sql_injection'] = SQLInjectionChecker(url, scope_mode=scope_mode).run()
    time.sleep(0.5)

    print("  [>] XSS Check...")
    results['xss'] = XSSChecker(url, scope_mode=scope_mode).run()
    time.sleep(0.5)

    print("  [>] Command Injection Check...")
    results['command_injection'] = CommandInjectionChecker(url, scope_mode=scope_mode).run()
    time.sleep(0.5)

    print("  [>] File Upload Misconfiguration Check...")
    results['file_upload'] = FileUploadChecker(url, scope_mode=scope_mode).run()

    return results