import requests
import re

# ── Header yang dicek beserta penjelasannya ──────────────────────────────────

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "CSP membantu mencegah XSS dan serangan injection.",
        "vuln_key_missing": "HEADER_CSP_MISSING",
        "severity_missing": "medium",
    },
    "X-Frame-Options": {
        "description": "Mencegah clickjacking dengan melarang iframe tidak trusted.",
        "vuln_key_missing": "HEADER_XFRAME_MISSING",
        "severity_missing": "medium",
    },
    "X-Content-Type-Options": {
        "description": "Mencegah MIME sniffing (nosniff).",
        "vuln_key_missing": "HEADER_XCTO_MISSING",
        "severity_missing": "low",
    },
    "Referrer-Policy": {
        "description": "Mengontrol informasi referer yang dikirim.",
        "vuln_key_missing": "HEADER_REFERRER_MISSING",
        "severity_missing": "low",
    },
    "Strict-Transport-Security": {
        "description": "Memaksa penggunaan HTTPS (HSTS).",
        "vuln_key_missing": "HEADER_HSTS_MISSING",
        "severity_missing": "medium",
    },
    "Permissions-Policy": {
        "description": "Batasi akses fitur browser (camera, mic, geolocation).",
        "vuln_key_missing": None,
        "severity_missing": "info",
    },
    "X-XSS-Protection": {
        "description": "Header legacy untuk proteksi XSS bawaan browser.",
        "vuln_key_missing": None,
        "severity_missing": "info",
    },
    "Cache-Control": {
        "description": "Mengatur caching response untuk mencegah penyimpanan data sensitif.",
        "vuln_key_missing": "HEADER_PERMISSIVE_CACHE",
        "severity_missing": "low",
    },
}

# ── Minimal HSTS max-age yang dianggap aman (6 bulan) ────────────────────────
MIN_HSTS_MAX_AGE = 15768000


# ── Value Analysis Functions ─────────────────────────────────────────────────

def _analyze_csp(value: str) -> list:
    """Analisis isi Content-Security-Policy untuk konfigurasi berbahaya."""
    issues = []
    val_lower = value.lower()

    if "'unsafe-inline'" in val_lower:
        issues.append({
            "issue": "CSP mengandung 'unsafe-inline' — memperlemah proteksi XSS.",
            "severity": "high",
            "vuln_key": "HEADER_CSP_UNSAFE",
        })

    if "'unsafe-eval'" in val_lower:
        issues.append({
            "issue": "CSP mengandung 'unsafe-eval' — memungkinkan eksekusi kode dinamis (eval).",
            "severity": "high",
            "vuln_key": "HEADER_CSP_UNSAFE",
        })

    # Cek wildcard di directive krusial
    for directive in ("default-src", "script-src", "object-src"):
        pattern = rf"{directive}\s+[^;]*\*"
        if re.search(pattern, val_lower):
            issues.append({
                "issue": f"CSP directive '{directive}' menggunakan wildcard (*) — terlalu permisif.",
                "severity": "medium",
                "vuln_key": "HEADER_CSP_UNSAFE",
            })

    # Jika tidak ada default-src sama sekali
    if "default-src" not in val_lower:
        issues.append({
            "issue": "CSP tidak memiliki directive 'default-src' sebagai fallback.",
            "severity": "low",
            "vuln_key": None,
        })

    return issues


def _analyze_hsts(value: str) -> list:
    """Analisis isi Strict-Transport-Security."""
    issues = []
    val_lower = value.lower()

    # Ekstrak max-age
    match = re.search(r"max-age\s*=\s*(\d+)", val_lower)
    if match:
        max_age = int(match.group(1))
        if max_age < MIN_HSTS_MAX_AGE:
            issues.append({
                "issue": f"HSTS max-age terlalu pendek ({max_age}s / ~{max_age // 86400} hari). "
                         f"Minimum yang disarankan: {MIN_HSTS_MAX_AGE}s (6 bulan).",
                "severity": "medium",
                "vuln_key": "HEADER_HSTS_WEAK",
            })
    else:
        issues.append({
            "issue": "HSTS tidak memiliki directive max-age yang valid.",
            "severity": "medium",
            "vuln_key": "HEADER_HSTS_WEAK",
        })

    if "includesubdomains" not in val_lower:
        issues.append({
            "issue": "HSTS tidak menyertakan 'includeSubDomains' — subdomain tidak dilindungi.",
            "severity": "low",
            "vuln_key": None,
        })

    return issues


def _analyze_xframe(value: str) -> list:
    """Analisis isi X-Frame-Options."""
    issues = []
    val_upper = value.strip().upper()

    valid_values = ("DENY", "SAMEORIGIN")
    if val_upper not in valid_values:
        issues.append({
            "issue": f"X-Frame-Options memiliki nilai tidak standar: '{value}'. "
                     f"Gunakan DENY atau SAMEORIGIN.",
            "severity": "medium",
            "vuln_key": None,
        })

    # ALLOW-FROM sudah deprecated dan tidak didukung browser modern
    if "ALLOW-FROM" in val_upper:
        issues.append({
            "issue": "X-Frame-Options menggunakan 'ALLOW-FROM' yang sudah deprecated. "
                     "Gunakan CSP frame-ancestors sebagai pengganti.",
            "severity": "medium",
            "vuln_key": None,
        })

    return issues


def _analyze_xcto(value: str) -> list:
    """Analisis isi X-Content-Type-Options."""
    issues = []
    if value.strip().lower() != "nosniff":
        issues.append({
            "issue": f"X-Content-Type-Options memiliki nilai tidak standar: '{value}'. "
                     f"Harus bernilai 'nosniff'.",
            "severity": "low",
            "vuln_key": None,
        })
    return issues


def _analyze_referrer(value: str) -> list:
    """Analisis isi Referrer-Policy."""
    issues = []
    val_lower = value.strip().lower()

    unsafe_policies = ("unsafe-url", "no-referrer-when-downgrade")
    if val_lower in unsafe_policies:
        issues.append({
            "issue": f"Referrer-Policy '{val_lower}' terlalu permisif — "
                     f"URL lengkap (termasuk query string) dikirim ke situs lain.",
            "severity": "medium",
            "vuln_key": None,
        })

    return issues


def _analyze_permissions(value: str) -> list:
    """Analisis isi Permissions-Policy."""
    issues = []
    val_lower = value.lower()

    sensitive_features = ["camera", "microphone", "geolocation"]
    for feat in sensitive_features:
        # Cek apakah fitur diizinkan tanpa pembatasan (misal: camera=*)
        pattern = rf"{feat}\s*=\s*\*"
        if re.search(pattern, val_lower):
            issues.append({
                "issue": f"Permissions-Policy mengizinkan fitur '{feat}' tanpa pembatasan (wildcard).",
                "severity": "low",
                "vuln_key": None,
            })

    return issues


def _analyze_xss_protection(value: str) -> list:
    """Analisis isi X-XSS-Protection."""
    issues = []
    val = value.strip()

    if val == "0":
        issues.append({
            "issue": "X-XSS-Protection dinonaktifkan (bernilai '0').",
            "severity": "info",
            "vuln_key": None,
        })
    elif val == "1" and "mode=block" not in val.lower():
        issues.append({
            "issue": "X-XSS-Protection aktif tapi tanpa 'mode=block' — "
                     "browser mungkin hanya menyaring sebagian serangan.",
            "severity": "info",
            "vuln_key": None,
        })

    return issues


def _analyze_cache_control(value: str) -> list:
    """Analisis isi Cache-Control."""
    issues = []
    val_lower = value.lower()

    if "no-store" not in val_lower and "no-cache" not in val_lower:
        issues.append({
            "issue": "Cache-Control tidak mengandung 'no-store' atau 'no-cache' — "
                     "response mungkin di-cache oleh proxy/browser dan mengekspos data sensitif.",
            "severity": "low",
            "vuln_key": "HEADER_PERMISSIVE_CACHE",
        })

    return issues


# ── Mapping header → fungsi analisis ─────────────────────────────────────────

VALUE_ANALYZERS = {
    "Content-Security-Policy":    _analyze_csp,
    "Strict-Transport-Security":  _analyze_hsts,
    "X-Frame-Options":            _analyze_xframe,
    "X-Content-Type-Options":     _analyze_xcto,
    "Referrer-Policy":            _analyze_referrer,
    "Permissions-Policy":         _analyze_permissions,
    "X-XSS-Protection":           _analyze_xss_protection,
    "Cache-Control":              _analyze_cache_control,
}


# Fungsi utama 
def analyze_security_headers(target_url: str):
    try:
        resp = requests.get(target_url, timeout=10, verify=False)
    except Exception as e:
        return {
            "error": str(e),
            "headers": {},
            "missing": list(SECURITY_HEADERS.keys()),
            "findings": [],
        }

    headers = resp.headers
    missing = []
    findings = []

    for header, config in SECURITY_HEADERS.items():
        value = headers.get(header)

        if not value:
            # Header tidak ditemukan
            missing.append(header)
            findings.append({
                "header": header,
                "present": False,
                "description": config["description"],
                "severity": config["severity_missing"],
                "vuln_key": config["vuln_key_missing"],
            })
        else:
            # Header ditemukan — lakukan value analysis
            finding = {
                "header": header,
                "present": True,
                "value": value,
                "description": config["description"],
                "severity": "info",        # default: info (aman)
                "vuln_key": None,
                "value_issues": [],
            }

            analyzer = VALUE_ANALYZERS.get(header)
            if analyzer:
                value_issues = analyzer(value)
                if value_issues:
                    finding["value_issues"] = value_issues
                    # Ambil severity tertinggi dari semua issue
                    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
                    worst = max(value_issues, key=lambda x: severity_order.get(x["severity"], 0))
                    finding["severity"] = worst["severity"]
                    finding["vuln_key"] = worst.get("vuln_key")

            findings.append(finding)

    return {
        "raw_headers": dict(headers),
        "findings": findings,
        "missing": missing,
    }
