import time
from .directory_listing import DirectoryListingChecker
from .open_redirect     import OpenRedirectChecker
from .sqli              import SQLInjectionChecker   
from .xss               import XSSChecker
from .command_injection import CommandInjectionChecker
from .file_upload       import FileUploadChecker
from helpers.http_client import HostDeadException
from helpers.crawler_helper import CrawlerHelper

__all__ = [
    'DirectoryListingChecker',
    'OpenRedirectChecker',
    'SQLInjectionChecker',
    'XSSChecker',
    'CommandInjectionChecker',
    'FileUploadChecker',
    'run_web_vulnerability_checks',
]


def _safe_run(label: str, checker) -> dict:
    """Jalankan modul dengan proteksi HostDeadException agar scan lanjut ke modul berikutnya."""
    try:
        return checker.run()
    except HostDeadException as e:
        print(f"  [!] {label}: Target mati/tarpit terdeteksi, modul di-skip. ({e})")
        return {
            'vulnerable': False,
            'vulnerable_paths': [],
            'total_tested': 0,
            'findings': [f"Modul di-skip: {e}"],
            'error': f"target_dead: {e}",
        }


def run_web_vulnerability_checks(url: str, scope_mode: str = 'wildcard', discovered: dict = None) -> dict:
    results = {}

    if not discovered:
        print("  [>] Menjalankan Centralized Crawler...")
        crawler = CrawlerHelper(url, scope_mode=scope_mode)
        discovered = crawler.crawl()

    print("  [>] Directory Listing Check...")
    results['directory_listing'] = _safe_run(
        'Directory Listing', DirectoryListingChecker(url, discovered=discovered, scope_mode=scope_mode))
    time.sleep(0.5)

    print("  [>] Open Redirect Check...")
    results['open_redirect'] = _safe_run(
        'Open Redirect', OpenRedirectChecker(url, discovered=discovered, scope_mode=scope_mode))
    time.sleep(0.5)

    print("  [>] SQL Injection Check...")
    results['sql_injection'] = _safe_run(
        'SQL Injection', SQLInjectionChecker(url, discovered=discovered, scope_mode=scope_mode))
    time.sleep(0.5)

    print("  [>] XSS Check...")
    results['xss'] = _safe_run(
        'XSS', XSSChecker(url, discovered=discovered, scope_mode=scope_mode))
    time.sleep(0.5)

    print("  [>] Command Injection Check...")
    results['command_injection'] = _safe_run(
        'Command Injection', CommandInjectionChecker(url, discovered=discovered, scope_mode=scope_mode))
    time.sleep(0.5)

    print("  [>] File Upload Misconfiguration Check...")
    results['file_upload'] = _safe_run(
        'File Upload', FileUploadChecker(url, discovered=discovered, scope_mode=scope_mode))

    return results