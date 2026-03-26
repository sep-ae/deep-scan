import socket
from modules.reconnaissance import DNSLookup, SubdomainFinder, PortScanner, TechFingerprint
from modules.http_security import analyze_security_headers, check_cors_misconfig
from modules.auth_protection import run_auth_protection_checks


def run_dns_lookup(domain):
    try:
        dns_obj = DNSLookup(domain)
        results = dns_obj.run()
        ip      = results['A'][0] if results.get('A') else None
        return results, ip        
    except Exception as e:
        print(f"[!] DNS Lookup error: {e}")
        return {}, None


def run_subdomain_finder(domain):
    try:
        return SubdomainFinder(domain).run(max_workers=10)
    except Exception as e:
        print(f"[!] Subdomain error: {e}")
        return []


def run_port_scanner(domain, ip_address):
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


def run_tech_fingerprint(target_url):
    try:
        return TechFingerprint(target_url).run()
    except Exception as e:
        print(f"[!] Tech fingerprint error: {e}")
        return {}


def run_http_security_check(target_url):
    try:
        return {
            'headers': analyze_security_headers(target_url),
            'cors':    check_cors_misconfig(target_url)
        }
    except Exception as e:
        print(f"[!] HTTP Security check error: {e}")
        return {}


def run_auth_protection(target_url):
    try:
        return run_auth_protection_checks(target_url)
    except Exception as e:
        print(f"[!] Auth protection error: {e}")
        return {}
