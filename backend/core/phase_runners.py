import socket
from modules.reconnaissance  import DNSLookup, SubdomainFinder, PortScanner, TechFingerprint
from modules.http_security   import analyze_security_headers, check_cors_misconfig
from modules.auth_protection import run_auth_protection_checks
from modules.web_vulnerabilities import run_web_vulnerability_checks

def run_dns_lookup(domain: str):
    try:
        dns_obj = DNSLookup(domain)
        results = dns_obj.run()
        ip      = results['A'][0] if results.get('A') else None
        return results, ip
    except Exception as e:
        print(f"[!] DNS Lookup error: {e}")
        return {}, None


def run_subdomain_finder(domain: str):
    try:
        return SubdomainFinder(domain).run(max_workers=10)
    except Exception as e:
        print(f"[!] Subdomain error: {e}")
        return []


def run_port_scanner(domain: str, ip_address: str):
    try:
        if not ip_address:
            ip_address = socket.gethostbyname(domain)
    except Exception:
        return []

    try:
        return PortScanner(ip_address).run()
    except Exception as e:
        print(f"[!] Port scanner error: {e}")
        return []


def run_tech_fingerprint(target_url: str):
    try:
        return TechFingerprint(target_url).run()
    except Exception as e:
        print(f"[!] Tech fingerprint error: {e}")
        return {}


def run_http_security_check(target_url: str):
    try:
        return {
            'headers': analyze_security_headers(target_url),
            'cors':    check_cors_misconfig(target_url),
        }
    except Exception as e:
        print(f"[!] HTTP Security check error: {e}")
        return {}


def run_auth_protection(target_url: str):
    try:
        return run_auth_protection_checks(target_url)
    except Exception as e:
        print(f"[!] Auth protection error: {e}")
        return {}


def run_web_vulnerabilities(target_url: str, cookies: dict = None) -> dict:
    try:
        print("  [*] Starting web vulnerability checks...")
        raw = run_web_vulnerability_checks(target_url)
        return _normalize_web_vuln_results(raw)
    except Exception as e:
        print(f"[!] Web vulnerability check error: {e}")
        return {
            key: {
                'vulnerable':       False,
                'vulnerable_paths': [],
                'findings':         [],
                'summary':          {},
                'error':            str(e),
            }
            for key in [
                'directory_listing', 'open_redirect', 'sql_injection',
                'xss', 'command_injection', 'file_upload',
            ]
        }


def _normalize_web_vuln_results(raw: dict) -> dict:
    """
    Pastikan setiap hasil checker punya key yang dibutuhkan
    oleh process_web_vuln_results():
        - vulnerable        : bool
        - vulnerable_paths  : list[dict]
        - findings          : list[str]
        - summary           : dict
        - error             : str | None

    Jika checker mengembalikan format berbeda, fungsi ini
    melakukan normalisasi minimal agar tidak KeyError.
    """
    normalized = {}

    for key, result in raw.items():
        if not isinstance(result, dict):
            normalized[key] = {
                'vulnerable':       False,
                'vulnerable_paths': [],
                'findings':         [str(result)],
                'summary':          {},
                'error':            None,
            }
            continue

        normalized[key] = {
            'vulnerable':       result.get('vulnerable',       False),
            'vulnerable_paths': result.get('vulnerable_paths', []),
            'findings':         result.get('findings',         []),
            'summary':          result.get('summary',          {}),
            'error':            result.get('error',            None),
        }

    return normalized