import requests
from urllib.parse import urlparse

# ── Severity constants ───────────────────────────────────────────────────────
SEV_CRITICAL = "critical"
SEV_HIGH     = "high"
SEV_MEDIUM   = "medium"
SEV_LOW      = "low"
SEV_INFO     = "info"


def _safe_request(method: str, url: str, **kwargs):
    """Kirim HTTP request dengan error handling."""
    try:
        fn = requests.get if method == "GET" else requests.options
        return fn(url, timeout=10, verify=False, allow_redirects=True, **kwargs)
    except Exception:
        return None


def check_cors_misconfig(target_url: str):
    """
    Mengecek miskonfigurasi CORS melalui beberapa pengujian:
    1. Origin Reflection (server memantulkan origin attacker)
    2. Wildcard Origin (Access-Control-Allow-Origin: *)
    3. Null Origin (Origin: null diterima)
    4. Subdomain Bypass (regex validasi origin lemah)
    5. Preflight (OPTIONS) — methods/headers terlalu permisif
    6. Kombinasi Credentials + Origin permisif

    Returns:
        dict dengan key: cors_headers, issues
        (format backward-compatible dengan result_processor)
    """
    parsed = urlparse(target_url)
    target_domain = parsed.netloc.replace("www.", "")
    evil_origin = "https://evil.example.com"

    issues = []
    all_cors_headers = {}

    resp = _safe_request("GET", target_url, headers={"Origin": evil_origin})
    if resp is not None:
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")
        acam = resp.headers.get("Access-Control-Allow-Methods")
        acah = resp.headers.get("Access-Control-Allow-Headers")

        all_cors_headers = {
            "Access-Control-Allow-Origin": acao,
            "Access-Control-Allow-Credentials": acac,
            "Access-Control-Allow-Methods": acam,
            "Access-Control-Allow-Headers": acah,
        }

        if acao == evil_origin:
            sev = SEV_CRITICAL if acac == "true" else SEV_HIGH
            issues.append({
                "test": "origin_reflection",
                "severity": sev,
                "vuln_key": "CORS_ORIGIN_REFLECTION",
                "message": (
                    f"Server memantulkan origin attacker ({evil_origin}) di "
                    f"Access-Control-Allow-Origin. "
                    + ("Dengan Credentials: true — akses data terautentikasi korban "
                       "dapat dicuri oleh situs pihak ketiga!"
                       if acac == "true" else
                       "Situs pihak ketiga dapat membaca response API dari domain ini.")
                ),
            })

        # Wildcard
        if acao == "*":
            sev = SEV_HIGH if acac == "true" else SEV_MEDIUM
            vuln_key = "CORS_WILDCARD_WITH_CREDENTIALS" if acac == "true" else "cors_misconfiguration"
            issues.append({
                "test": "wildcard_origin",
                "severity": sev,
                "vuln_key": vuln_key,
                "message": (
                    "Access-Control-Allow-Origin: * (semua domain diizinkan). "
                    + ("Dikombinasi dengan Credentials: true — sangat berbahaya!"
                       if acac == "true" else
                       "Berpotensi CORS misconfiguration.")
                ),
            })

        # Credentials tanpa origin yang spesifik
        if acac == "true" and acao and acao not in (evil_origin, "*"):
            issues.append({
                "test": "credentials_enabled",
                "severity": SEV_INFO,
                "vuln_key": None,
                "message": (
                    f"Access-Control-Allow-Credentials: true aktif. "
                    f"Origin yang diizinkan: {acao}."
                ),
            })

    else:
        # Request gagal — kembalikan error
        return {
            "error": "Tidak dapat terhubung ke target untuk pengecekan CORS.",
            "cors_headers": {},
            "issues": [],
        }

    # ── Test 2: Null Origin ──────────────────────────────────────────────────
    resp_null = _safe_request("GET", target_url, headers={"Origin": "null"})
    if resp_null is not None:
        acao_null = resp_null.headers.get("Access-Control-Allow-Origin")
        acac_null = resp_null.headers.get("Access-Control-Allow-Credentials")

        if acao_null == "null":
            sev = SEV_HIGH if acac_null == "true" else SEV_MEDIUM
            issues.append({
                "test": "null_origin",
                "severity": sev,
                "vuln_key": "CORS_NULL_ORIGIN_ALLOWED",
                "message": (
                    "Server mengizinkan Origin: null. "
                    "Iframe sandboxed atau file lokal dapat melakukan cross-origin request "
                    "dan membaca response."
                    + (" Dikombinasi dengan Credentials: true — data terautentikasi berisiko!"
                       if acac_null == "true" else "")
                ),
            })

    # ── Test 3: Subdomain Bypass ─────────────────────────────────────────────
    spoofed_origin = f"https://evil.{target_domain}"
    resp_sub = _safe_request("GET", target_url, headers={"Origin": spoofed_origin})
    if resp_sub is not None:
        acao_sub = resp_sub.headers.get("Access-Control-Allow-Origin")
        acac_sub = resp_sub.headers.get("Access-Control-Allow-Credentials")

        if acao_sub == spoofed_origin:
            sev = SEV_HIGH if acac_sub == "true" else SEV_MEDIUM
            issues.append({
                "test": "subdomain_bypass",
                "severity": sev,
                "vuln_key": "CORS_ORIGIN_REFLECTION",
                "message": (
                    f"Server mengizinkan subdomain spoofed ({spoofed_origin}). "
                    f"Validasi origin menggunakan regex/suffix matching yang lemah — "
                    f"penyerang dapat mendaftarkan domain 'evil.{target_domain}' "
                    f"untuk mem-bypass validasi CORS."
                    + (f" Dengan Credentials: true!" if acac_sub == "true" else "")
                ),
            })

    # ── Test 4: Preflight (OPTIONS) ──────────────────────────────────────────
    resp_pre = _safe_request("OPTIONS", target_url, headers={
        "Origin": evil_origin,
        "Access-Control-Request-Method": "PUT",
        "Access-Control-Request-Headers": "X-Custom-Header",
    })
    if resp_pre is not None:
        pre_acao = resp_pre.headers.get("Access-Control-Allow-Origin")
        pre_methods = resp_pre.headers.get("Access-Control-Allow-Methods", "")
        pre_headers = resp_pre.headers.get("Access-Control-Allow-Headers", "")

        # Cek apakah preflight juga vulnerable
        if pre_acao in (evil_origin, "*"):
            dangerous_methods = {"PUT", "DELETE", "PATCH"}
            allowed_set = {m.strip().upper() for m in pre_methods.split(",") if m.strip()}
            risky = dangerous_methods & allowed_set

            if risky:
                issues.append({
                    "test": "preflight_methods",
                    "severity": SEV_MEDIUM,
                    "vuln_key": None,
                    "message": (
                        f"Preflight response mengizinkan method berbahaya: "
                        f"{', '.join(sorted(risky))} untuk origin pihak ketiga."
                    ),
                })

            if pre_headers == "*":
                issues.append({
                    "test": "preflight_headers",
                    "severity": SEV_LOW,
                    "vuln_key": None,
                    "message": (
                        "Preflight response mengizinkan semua custom header "
                        "(Access-Control-Allow-Headers: *) — terlalu permisif."
                    ),
                })

    # ── Jika tidak ada issue ─────────────────────────────────────────────────
    if not issues:
        acao_val = all_cors_headers.get("Access-Control-Allow-Origin")
        if not acao_val:
            issues.append({
                "test": "cors_not_configured",
                "severity": SEV_INFO,
                "vuln_key": None,
                "message": (
                    "Access-Control-Allow-Origin tidak di-set "
                    "(default aman, CORS tidak diaktifkan)."
                ),
            })

    return {
        "cors_headers": all_cors_headers,
        "issues": issues,
    }
