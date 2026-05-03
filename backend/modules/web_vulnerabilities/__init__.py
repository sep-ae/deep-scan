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


def run_web_vulnerability_checks(url: str) -> dict:
    results = {}

    print("  [>] Directory Listing Check...")
    results['directory_listing'] = DirectoryListingChecker(url).run()
    time.sleep(0.5)

    print("  [>] Open Redirect Check...")
    results['open_redirect'] = OpenRedirectChecker(url).run()
    time.sleep(0.5)

    print("  [>] SQL Injection Check...")
    results['sql_injection'] = SQLInjectionChecker(url).run()
    time.sleep(0.5)

    print("  [>] XSS Check...")
    results['xss'] = XSSChecker(url).run()
    time.sleep(0.5)

    print("  [>] Command Injection Check...")
    results['command_injection'] = CommandInjectionChecker(url).run()
    time.sleep(0.5)

    print("  [>] File Upload Misconfiguration Check...")
    results['file_upload'] = FileUploadChecker(url).run()

    return results