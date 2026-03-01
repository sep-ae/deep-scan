HTTP_PROFILES = {
    "missing_security_headers": {
        "name": "Missing HTTP Security Headers",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "N","s": "U","c": "L","i": "N","a": "N"},
        "description": "Beberapa HTTP security header penting tidak ditemukan.",
        "recommendation": "Tambahkan: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy."
    },

    "HEADER_CSP_MISSING": {
        "name": "Content-Security-Policy Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "R","s": "U","c": "L","i": "L","a": "N"},
        "description": "Header CSP tidak ada. Meningkatkan risiko XSS.",
        "recommendation": "Tambahkan: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'."
    },

    "HEADER_XFRAME_MISSING": {
        "name": "X-Frame-Options Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "R","s": "U","c": "L","i": "L","a": "N"},
        "description": "Halaman dapat di-embed dalam iframe, membuka celah clickjacking.",
        "recommendation": "Tambahkan: X-Frame-Options: DENY atau SAMEORIGIN."
    },

    "HEADER_XCTO_MISSING": {
        "name": "X-Content-Type-Options Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "R","s": "U","c": "L","i": "N","a": "N"},
        "description": "Browser dapat melakukan MIME sniffing.",
        "recommendation": "Tambahkan: X-Content-Type-Options: nosniff."
    },

    "HEADER_HSTS_MISSING": {
        "name": "Strict-Transport-Security Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N","ac": "H","pr": "N","ui": "R","s": "U","c": "L","i": "L","a": "N"},
        "description": "Browser tidak dipaksa HTTPS, rentan SSL stripping.",
        "recommendation": "Tambahkan: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload."
    },

    "HEADER_REFERRER_MISSING": {
        "name": "Referrer-Policy Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "R","s": "U","c": "L","i": "N","a": "N"},
        "description": "URL sensitif dapat bocor ke situs pihak ketiga melalui referrer.",
        "recommendation": "Tambahkan: Referrer-Policy: strict-origin-when-cross-origin."
    },

    "cors_misconfiguration": {
        "name": "CORS Misconfiguration",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "R","s": "U","c": "L","i": "L","a": "N"},
        "description": "Konfigurasi CORS tidak aman, mengizinkan akses dari origin tidak trusted.",
        "recommendation": "Batasi Access-Control-Allow-Origin hanya ke origin terpercaya. Hindari wildcard (*)."
    },

    "CORS_WILDCARD_WITH_CREDENTIALS": {
        "name": "CORS Wildcard with Credentials Enabled",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "R","s": "U","c": "H","i": "H","a": "N"},
        "description": "Wildcard CORS dengan credentials aktif. Attacker dapat membaca response terautentikasi.",
        "recommendation": "Jangan gunakan wildcard jika credentials diaktifkan. Tentukan origin spesifik."
    },
}