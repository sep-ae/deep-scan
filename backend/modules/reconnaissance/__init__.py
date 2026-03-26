import time
from .dns_lookup  import DNSLookup
from .subdomain   import SubdomainFinder
from .port_scanner import PortScanner
from .footprint   import TechFingerprint

__all__ = [
    'DNSLookup',
    'SubdomainFinder',
    'PortScanner',
    'TechFingerprint',
    'run_reconnaissance_checks',
]


def run_reconnaissance_checks(url: str) -> dict:
    results = {}

    print("  [>] DNS Lookup...")
    results['dns'] = DNSLookup(url).run()
    time.sleep(0.5)

    print("  [>] Subdomain Finder...")
    results['subdomain'] = SubdomainFinder(url).run()
    time.sleep(0.5)

    print("  [>] Port Scanner...")
    results['ports'] = PortScanner(url).run()
    time.sleep(0.5)

    print("  [>] Tech Fingerprinting...")
    results['fingerprint'] = TechFingerprint(url).run()

    return results