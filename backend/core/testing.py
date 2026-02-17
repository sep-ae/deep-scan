import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.reconnaissance.dns_lookup import DNSLookup
from modules.reconnaissance.subdomain import SubdomainFinder
from modules.reconnaissance.port_scanner import PortScanner
from modules.reconnaissance.footprint import TechFingerprint

def test_reconnaissance():
    target = "juice-shop.herokuapp.com"
    
    print("=== DNS Lookup ===")
    dns = DNSLookup(target)
    print(dns.run())
    
    print("\n=== Subdomain Finder ===")
    subdomain = SubdomainFinder(target)
    subs = subdomain.run(max_workers=5)
    print(f"Found {len(subs)} subdomains")
    for s in subs[:3]:
        print(s)
    
    print("\n=== Port Scanner ===")
    scanner = PortScanner("8.8.8.8")
    ports = scanner.run(timeout=0.5)
    print(f"Found {len(ports)} open ports")
    for p in ports[:3]:
        print(p)
    
    print("\n=== Tech Fingerprint ===")
    tech = TechFingerprint(f"https://{target}")
    print(tech.run())
    

if __name__ == '__main__':
    test_reconnaissance()
