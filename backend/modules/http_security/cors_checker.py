import requests

def check_cors_misconfig(target_url: str):
    try:
        resp = requests.get(
            target_url,
            headers={"Origin": "https://evil.example.com"},
            timeout=10,
            verify=False
        )
    except Exception as e:
        return {
            "error": str(e),
            "cors_headers": {},
            "issues": []
        }

    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials")
    issues = []

    if acao == "*":
        issues.append("Access-Control-Allow-Origin: * (berpotensi CORS misconfiguration).")

    if acac == "true" and acao not in (None, "null") and acao != "https://evil.example.com":
        issues.append("Access-Control-Allow-Credentials: true dengan origin tidak spesifik.")

    if not acao:
        issues.append("Access-Control-Allow-Origin tidak di-set (default aman, tapi CORS tidak diaktifkan).")

    return {
        "cors_headers": {
            "Access-Control-Allow-Origin": acao,
            "Access-Control-Allow-Credentials": acac
        },
        "issues": issues
    }
