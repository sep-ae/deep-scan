# backend/core/scanner_engine.py
from modules.reconnaissance import FootprintModule, HeaderScanModule, SubdomainModule

class ScannerEngine:
    def __init__(self, target):
        self.target = target if target.startswith(('http', 'https')) else 'http://' + target
        self.results = {}

    def start(self):
        print(f"[*] Starting Recon on {self.target}...")

        # 1. Jalanin Footprint
        fp = FootprintModule(self.target)
        self.results['info'] = fp.run()

        # 2. Jalanin Header Scan
        hd = HeaderScanModule(self.target)
        self.results['headers'] = hd.run()

        # 3. Jalanin Subdomain Scan
        sub = SubdomainModule(self.target)
        self.results['subdomains'] = sub.run()

        return self.results

# TESTING BLOCK (Jalankan ini buat Demo ke Dosen di Terminal)
if __name__ == "__main__":
    import json
    # Target aman buat demo
    target = "testphp.vulnweb.com" 
    
    engine = ScannerEngine(target)
    laporan = engine.start()
    
    print(json.dumps(laporan, indent=2))