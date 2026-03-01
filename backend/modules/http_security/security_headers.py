import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "CSP membantu mencegah XSS dan serangan injection.",
    "X-Frame-Options": "Mencegah clickjacking dengan melarang iframe tidak trusted.",
    "X-Content-Type-Options": "Mencegah MIME sniffing (nosniff).",
    "Referrer-Policy": "Mengontrol informasi referer yang dikirim.",
    "Strict-Transport-Security": "Memaksa penggunaan HTTPS (HSTS).",
    "Permissions-Policy": "Batasi akses fitur browser (camera, mic, geolocation)."
}

def analyze_security_headers(target_url: str):
    try:
        resp = requests.get(target_url, timeout=10, verify=False)
    except Exception as e:
        return {
            "error": str(e),
            "headers": {},
            "missing": list(SECURITY_HEADERS.keys())
        }

    headers = resp.headers
    missing = []
    findings = []

    for header, explanation in SECURITY_HEADERS.items():
        if header not in headers:
            missing.append(header)
            findings.append({
                "header": header,
                "present": False,
                "description": explanation
            })
        else:
            findings.append({
                "header": header,
                "present": True,
                "value": headers.get(header),
                "description": explanation
            })

    return {
        "raw_headers": dict(headers),
        "findings": findings,
        "missing": missing
    }
